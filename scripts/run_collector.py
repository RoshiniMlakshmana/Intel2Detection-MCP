"""One independent collection run, with a JSONL status log and no email delivery."""
import argparse
import json
import os
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--interval-minutes", type=int, choices=(30, 60), default=30)
    args = parser.parse_args()
    os.environ["THREAT_RESEARCH_DB"] = args.database
    os.environ["POLL_INTERVAL_MINUTES"] = str(args.interval_minutes)
    from threat_research import poller
    from threat_research.core import now
    try:
        result = poller.run_poll(notify=False)
    except Exception as exc:
        result = {"status": "failed", "completed": now(), "error": str(exc)[:300]}
    log = Path(args.log)
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(result) + "\n")
    print(json.dumps(result))
    return 0 if result["status"] in ("collected", "already_running") else 2


if __name__ == "__main__":
    raise SystemExit(main())
