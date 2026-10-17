#!/usr/bin/env python3
"""Use the existing collected threat database: exact known IOC match or research next step."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from threat_research import intelligence_router

def main(argv=None):
    p=argparse.ArgumentParser(description="Match known threat IOCs, otherwise route research")
    p.add_argument("--database",type=Path,required=True,help="Existing Intel2Detection SQLite database")
    p.add_argument("--event",type=Path,help="A JSON object of observed event fields")
    p.add_argument("--threat-id",help="Existing collected lead ID for research routing")
    p.add_argument("--output",type=Path)
    args=p.parse_args(argv)
    if (args.event is None)==(args.threat_id is None):
        p.error("provide exactly one of --event or --threat-id")
    if args.event:
        raw=args.event.read_bytes()
        if len(raw)>64_000:
            p.error("event file larger than 64 KB")
        data=json.loads(raw)
        result=intelligence_router.classify_event(data,args.database)
    else:
        result=intelligence_router.route(args.threat_id,args.database)
    output=json.dumps(result,indent=2)+"\n"
    if args.output:
        args.output.parent.mkdir(parents=True,exist_ok=True)
        args.output.write_text(output,encoding="utf-8")
    print(output,end="")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
