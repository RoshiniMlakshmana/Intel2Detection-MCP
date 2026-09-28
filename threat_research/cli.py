"""CLI used by a host scheduler, cron, or an always-on local process."""

import argparse
import json
import os
import time

from . import dashboard, doctor, enterprise, environment, frameworks, lead_queue, live_validation, poller, report_inspection, rule_repository, rules, soc_lab, soc_replay, store
from .core import collect_daily, get_threat, list_threats
from .digest import due_now, run_daily
from .rules import import_inventory


def main():
    parser = argparse.ArgumentParser(prog="threat-research")
    parser.add_argument("command", choices=["init", "collect", "list", "show", "digest", "serve-scheduler", "import-inventory",
                                            "onboard", "environment-status", "assess-assets", "check-rule", "probe-splunk", "inspect-report",
                                            "test-siem", "compare-splunk-rules", "poll-once", "poll-status", "serve-live",
                                            "create-pack", "inspect-pack", "onboard-pack", "export-sigma",
                                            "demo-soc", "watch-events", "review-leads", "review-queue", "doctor",
                                            "refresh-frameworks", "framework-status", "review-detection", "dashboard",
                                            "inventory-status", "declare-inventory", "reject-rule", "reopen-rule",
                                            "rule-repository-status", "test-rule"])
    parser.add_argument("--host", help="dashboard bind host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, help="dashboard bind port (default 8765)")
    parser.add_argument("--no-auto-refresh", action="store_true", help="dashboard: do not poll on startup/daily; use when serve-live already polls")
    parser.add_argument("--id", help="threat ID for show/assess-assets/inventory-status, or local rule ID for check-rule/reject-rule/reopen-rule/test-rule")
    parser.add_argument("--file", help="curated JSON inventory file, or with import-inventory")
    parser.add_argument("--database", help="database path for the local JSONL watcher")
    parser.add_argument("--output-directory", help="new or empty directory for the isolated SOC lab")
    parser.add_argument("--include-drafts", action="store_true", help="explicitly enable review-only drafts in the local watcher")
    parser.add_argument("--from-end", action="store_true", help="start watching after existing file contents")
    parser.add_argument("--profile", help="environment profile JSON file")
    parser.add_argument("--assets", help="asset inventory CSV file")
    parser.add_argument("--family", choices=["process_creation", "network_connection", "mcp_audit"], help="Splunk event family")
    parser.add_argument("--source-url", help="already cited publisher URL for inspect-report")
    parser.add_argument("--directory", help="new or existing enterprise environment pack directory")
    parser.add_argument("--name", help="environment name for create-pack")
    parser.add_argument("--siem", choices=["splunk", "defender", "generic"], help="target SIEM for create-pack")
    parser.add_argument("--scope", help="declare-inventory: specific description of what inventory was checked")
    parser.add_argument("--complete", action="store_true", help="declare-inventory: mark the declared scope as the complete current inventory")
    parser.add_argument("--reason", help="reject-rule: short rejection reason")
    parser.add_argument("--events-file", help="test-rule: local JSONL file of analyst-labeled positive/benign events")
    args = parser.parse_args()
    if args.directory and args.command not in ("create-pack", "inspect-pack", "onboard-pack"):
        os.environ["THREAT_RESEARCH_DB"] = str(enterprise.pack_database(args.directory))
    if args.command == "init":
        store.initialize()
        result = {"database": str(store.db_path())}
    elif args.command == "collect":
        result = collect_daily()
    elif args.command == "list":
        result = list_threats()
    elif args.command == "show":
        result = get_threat(args.id or "")
    elif args.command == "digest":
        result = run_daily()
    elif args.command == "import-inventory":
        if not args.file:
            parser.error("import-inventory requires --file")
        with open(args.file, encoding="utf-8") as handle:
            result = import_inventory(json.load(handle))
    elif args.command == "onboard":
        if not args.profile or not args.assets:
            parser.error("onboard requires --profile and --assets")
        with open(args.profile, encoding="utf-8") as handle:
            profile = json.load(handle)
        with open(args.assets, encoding="utf-8-sig", newline="") as handle:
            assets = environment.parse_assets(handle.read())
        result = environment.onboard(profile, assets)
    elif args.command == "environment-status":
        result = environment.status()
    elif args.command == "assess-assets":
        if not args.id:
            parser.error("assess-assets requires --id CVE-...")
        result = environment.risk_from_assets(args.id)
    elif args.command == "check-rule":
        if not args.id:
            parser.error("check-rule requires --id RULE-ID")
        result = environment.check_rule_fit(args.id)
    elif args.command == "refresh-frameworks":
        result = frameworks.refresh()
    elif args.command == "framework-status":
        result = frameworks.status()
    elif args.command == "review-detection":
        if not args.id:
            parser.error("review-detection requires --id RULE-ID")
        result = rules.review_for_client(args.id)
    elif args.command == "probe-splunk":
        if not args.family:
            parser.error("probe-splunk requires --family")
        result = environment.probe_splunk(args.family)
    elif args.command == "inspect-report":
        if not args.id or not args.source_url:
            parser.error("inspect-report requires --id and --source-url")
        result = report_inspection.inspect_report(args.id, args.source_url)
    elif args.command == "test-siem":
        if not args.id:
            parser.error("test-siem requires --id RULE-ID")
        result = live_validation.check_live_query(args.id)
    elif args.command == "compare-splunk-rules":
        if not args.id:
            parser.error("compare-splunk-rules requires --id RULE-ID")
        result = live_validation.compare_splunk_inventory(args.id)
    elif args.command == "poll-once":
        result = poller.run_poll()
    elif args.command == "poll-status":
        result = poller.poll_status()
    elif args.command == "review-leads":
        result = lead_queue.list_leads()
    elif args.command == "review-queue":
        result = lead_queue.queue_status()
    elif args.command == "doctor":
        result = doctor.check(args.directory)
    elif args.command == "serve-live":
        poller.serve()
        return
    elif args.command == "dashboard":
        dashboard.serve(host=args.host, port=args.port, auto_refresh=(False if args.no_auto_refresh else None))
        return
    elif args.command == "inventory-status":
        if not args.id:
            parser.error("inventory-status requires --id THREAT-ID")
        result = rules.inventory_status(args.id)
    elif args.command == "declare-inventory":
        if not args.scope:
            parser.error("declare-inventory requires --scope \"description of what was checked\" (add --complete if it is the full current inventory)")
        result = rules.declare_inventory_scope(args.scope, args.complete)
    elif args.command == "reject-rule":
        if not args.id or not args.reason:
            parser.error("reject-rule requires --id RULE-ID and --reason")
        result = rules.reject_rule(args.id, args.reason)
    elif args.command == "reopen-rule":
        if not args.id:
            parser.error("reopen-rule requires --id RULE-ID")
        result = rules.reopen_rule(args.id)
    elif args.command == "rule-repository-status":
        result = rule_repository.list_repository()
    elif args.command == "test-rule":
        if not args.id or not args.events_file:
            parser.error("test-rule requires --id RULE-ID and --events-file events.jsonl")
        result = soc_replay.test_rule_against_samples(args.id, args.events_file)
    elif args.command == "create-pack":
        if not args.directory or not args.name or not args.siem:
            parser.error("create-pack requires --directory, --name, and --siem")
        result = enterprise.create_pack(args.directory, args.name, args.siem)
    elif args.command == "inspect-pack":
        if not args.directory:
            parser.error("inspect-pack requires --directory")
        result = enterprise.inspect_pack(args.directory)
    elif args.command == "onboard-pack":
        if not args.directory:
            parser.error("onboard-pack requires --directory")
        result = enterprise.onboard_pack(args.directory)
    elif args.command == "export-sigma":
        if not args.directory or not args.id:
            parser.error("export-sigma requires --directory and --id RULE-ID")
        result = enterprise.export_sigma_bundle(args.directory, args.id)
    elif args.command == "demo-soc":
        result = soc_lab.run(args.output_directory or "soc-lab-output")
    elif args.command == "watch-events":
        if not args.file:
            parser.error("watch-events requires --file JSONL and an approved local rule, or --include-drafts for a lab")
        try:
            soc_replay.watch_jsonl(args.file, args.database, include_drafts=args.include_drafts, from_end=args.from_end)
        except KeyboardInterrupt:
            pass
        return
    else:
        while True:
            if due_now():
                try:
                    print(json.dumps(run_daily()), flush=True)
                except Exception as exc:
                    print(json.dumps({"error": str(exc)[:300]}), flush=True)
            time.sleep(60)
    print(json.dumps(result, indent=2))
    if args.command == "doctor" and result["status"] != "ready_for_research":
        raise SystemExit(2)


if __name__ == "__main__":
    main()
