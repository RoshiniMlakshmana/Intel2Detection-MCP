"""Prepare local Sysmon XML exports for analyst-labeled reference replay."""
import csv
import hashlib
import json
import xml.etree.ElementTree as ET
from pathlib import Path


def prepare(xml_file, output_directory, labels_file=None):
    with Path(xml_file).open('rb') as handle:
        raw = handle.read(8_000_001)
    if len(raw)>8_000_000 or b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
        raise ValueError('Sysmon export must be bounded XML without DTD/entities')
    root = ET.fromstring(raw)
    def tag(node):
        return node.tag.rsplit('}',1)[-1]
    rows=[]
    for event in root.iter():
        if tag(event)!='Event':
            continue
        system=next((n for n in event if tag(n)=='System'),None)
        if system is None:
            continue
        children={tag(n):n for n in system}
        if children.get('Provider') is None or children['Provider'].get('Name')!='Microsoft-Windows-Sysmon':
            continue
        if children.get('EventID') is None or children['EventID'].text!='1':
            continue
        data={n.get('Name'):n.text or '' for n in event.iter() if tag(n)=='Data' and n.get('Name')}
        if not all(data.get(key) for key in ('Image','CommandLine')):
            raise ValueError('Sysmon process event lacks Image or CommandLine')
        if not all(key in children for key in ('EventRecordID','TimeCreated','Computer')):
            raise ValueError('Sysmon process event lacks record identity or time')
        ident='sysmon:'+str(children['Computer'].text)+':'+str(children['EventRecordID'].text)
        timestamp=children['TimeCreated'].get('SystemTime')
        if not timestamp:
            raise ValueError('Sysmon process event lacks SystemTime')
        rows.append({'event_id':ident, 'timestamp':timestamp, 'event_type':'process_creation',
                     **{key:data[key] for key in ('Image','ParentImage','CommandLine','User') if key in data},
                     'expected_malicious':None, 'source_format':'sysmon_xml', 'origin_unverified':True})
        if len(rows)>10000:
            raise ValueError('too many process events; export a narrower window')
    if not rows or len({row['event_id'] for row in rows})!=len(rows):
        raise ValueError('export needs distinct Sysmon Event 1 records')
    if labels_file:
        labels={}
        with Path(labels_file).open(newline='',encoding='utf-8-sig') as handle:
            for label in csv.DictReader(handle):
                ident=label.get('event_id')
                truth=label.get('expected_malicious','').strip().lower()
                if not ident or ident in labels or truth not in ('true','false'):
                    raise ValueError('labels need distinct event_id and explicit true/false truth')
                labels[ident]=truth=='true'
        if set(labels)-{row['event_id'] for row in rows}:
            raise ValueError('label references an event outside this export')
        for row in rows:
            row['expected_malicious']=labels.get(row['event_id'])
    out=Path(output_directory)
    out.mkdir(parents=True,exist_ok=False)
    (out/'events.jsonl').write_text(''.join(json.dumps(row)+'\n' for row in rows),encoding='utf-8')
    with (out/'labels.csv').open('w',newline='',encoding='utf-8') as handle:
        writer=csv.DictWriter(handle,fieldnames=['event_id','expected_malicious'])
        writer.writeheader()
        writer.writerows({'event_id':row['event_id'],'expected_malicious':
                         '' if row['expected_malicious'] is None else str(row['expected_malicious']).lower()} for row in rows)
    report={'events':len(rows),'labeled_events':sum(row['expected_malicious'] is not None for row in rows),
            'input_sha256':hashlib.sha256(raw).hexdigest(),'output':str(out.resolve()),
            'scope':'Local XML import only. Origin and truth require analyst review; no SIEM executed a rule.',
            'next_step':'Label every event true/false, then prepare again with --labels-file and a new output directory before test-rule.'}
    (out/'import-report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    return report
