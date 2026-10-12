"""Translate a bounded literal KQL subset; retain unsupported hunts verbatim."""
import json
import re
from . import custom_rules

TABLES = {
    'DeviceFileEvents': ('file_event', {'SHA256':'SHA256', 'FileName':'FileName', 'FolderPath':'TargetFilename', 'InitiatingProcessFileName':'InitiatingProcessFileName'}),
    'DeviceProcessEvents': ('process_creation', {'FileName':'Image', 'ProcessCommandLine':'CommandLine', 'InitiatingProcessFileName':'ParentImage', 'InitiatingProcessCommandLine':'ParentCommandLine', 'InitiatingProcessParentFileName':'GrandparentImage', 'InitiatingProcessVersionInfoCompanyName':'ParentCompany'}),
    'DeviceNetworkEvents': ('network_connection', {'InitiatingProcessFileName':'Image', 'RemoteUrl':'DestinationHostname', 'RemoteIP':'DestinationIp'}),
}
TOKEN = re.compile(r'''\s*(?:(?P<comment>//[^\n]*(?:\n|$))|(?P<literal>'(?:\\.|[^'\\\n]){1,200}'|"(?:\\.|[^"\\\n]){1,200}")|(?P<op>==|=~|>=|=)|(?P<duration>\d+[dhms])|(?P<word>[A-Za-z][A-Za-z0-9_]*)|(?P<punct>[|(),;]))''')


def _literal(token):
    if token.startswith('"'):
        return json.loads(token)
    if not token.startswith("'") or not token.endswith("'"):
        raise ValueError('literal required')
    return re.sub(r'''\\([\\'"])''', lambda m:m.group(1), token[1:-1])


def bounded_spec(text, platform_hint=None):
    """Literal AND filters, grouped parentheses, constants and scoped ago().

    Every token must be consumed. Unsupported OR, joins, aggregates and query
    variables remain full publisher hunts, never widened partial translations.
    """
    if not isinstance(text, str) or len(text)>5000:
        return None
    try:
        tokens, pos = [], 0
        while pos<len(text.rstrip()):
            match=TOKEN.match(text,pos)
            if not match:
                return None
            if match.lastgroup!='comment':
                tokens.append(match.group(match.lastgroup))
            pos=match.end()
        constants={}
        while tokens and tokens[0].lower()=='let':
            if len(constants)>=8 or len(tokens)<5 or tokens[2]!='=' or tokens[4]!=';':
                return None
            if not re.fullmatch('[A-Za-z][A-Za-z0-9_]*',tokens[1]) or tokens[1] in constants:
                return None
            _literal(tokens[3])
            constants[tokens[1]]=tokens[3]
            tokens=tokens[5:]
        if tokens and tokens[-1]==';':
            tokens=tokens[:-1]
        if not tokens or tokens[0] not in TABLES:
            return None
        family,mapping=TABLES[tokens[0]]
        literals=' '.join(_literal(constants.get(t,t)) for t in tokens if t.startswith(('"',"'")) or t in constants)
        platform=('windows' if re.search(r'(?i)\.exe\b|\.dll\b|[A-Za-z]:\\',literals) else
                  'linux' if re.search(r'(?i)\b(?:linux|zimbra)\b|/(?:opt|bin|tmp|var|usr)/',literals) else None)
        if not platform and platform_hint in ('windows','linux'):
            platform=platform_hint
        if not platform:
            return None
        predicates,alternatives=[],[]
        i,window=1,None
        def leaf():
            nonlocal i,window
            field,op=tokens[i],tokens[i+1].lower()
            i+=2
            if field=='Timestamp' and op=='>=':
                if tokens[i:i+2]!=['ago','('] or tokens[i+3]!=')':
                    raise ValueError('unsupported time clause')
                duration=re.fullmatch(r'(\d+)([dhms])',tokens[i+2])
                if not duration:
                    raise ValueError('unsupported duration')
                seconds=int(duration[1])*{'d':86400,'h':3600,'m':60,'s':1}[duration[2]]
                if not 1<=seconds<=7776000:
                    raise ValueError('unbounded lookback')
                window=min(window,seconds) if window is not None else seconds
                i+=4
                return
            if field not in mapping or op not in ('==','=~','has','contains','endswith','startswith','has_any','has_all'):
                raise ValueError('unsupported filter')
            values=[]
            if op in ('has_any','has_all'):
                if tokens[i]!='(':
                    raise ValueError('literal list required')
                i+=1
                while True:
                    values.append(_literal(constants.get(tokens[i],tokens[i]))); i+=1
                    if tokens[i]==')':
                        i+=1; break
                    if tokens[i]!=',':
                        raise ValueError('malformed literal list')
                    i+=1
            else:
                values=[_literal(constants.get(tokens[i],tokens[i]))]; i+=1
            if op=='has_any' and alternatives:
                raise ValueError('independent OR lists unsupported')
            target=alternatives if op=='has_any' else predicates
            for value in dict.fromkeys(values):
                item={'field':mapping[field],'operator':'equals' if op in ('==','=~') else 'has' if op in ('has_any','has_all') else op,'value':value}
                if op in ('==','=~') and field in ('FileName','InitiatingProcessFileName') and mapping[field] in ('Image','ParentImage'):
                    item['operator']='basename_equals'
                if op=='==':
                    item['case_sensitive']=True
                if item not in target:
                    target.append(item)
        def conjunction(depth=0):
            nonlocal i
            if depth>8:
                raise ValueError('nested expression too deep')
            while True:
                if tokens[i]=='(':
                    i+=1; conjunction(depth+1)
                    if tokens[i]!=')':
                        raise ValueError('unclosed group')
                    i+=1
                else:
                    leaf()
                if i<len(tokens) and tokens[i].lower()=='and':
                    i+=1; continue
                break
        while i<len(tokens):
            if tokens[i]!='|':
                return None
            i+=1
            if tokens[i].lower()=='project':
                rest=tokens[i+1:]
                if not rest or len(rest)%2==0 or any(not re.fullmatch('[A-Za-z][A-Za-z0-9_]*' if j%2==0 else ',',v) for j,v in enumerate(rest)):
                    return None
                i=len(tokens); break
            if tokens[i].lower()!='where':
                return None
            i+=1; conjunction()
        spec={'event_family':family,'platform':platform,'predicates':predicates}
        if alternatives:
            spec['any_of']=alternatives
        if window is not None:
            spec['query_scope']={'lookback_seconds':window}
        return custom_rules.validate_spec(spec)
    except (IndexError,ValueError,TypeError):
        return None
