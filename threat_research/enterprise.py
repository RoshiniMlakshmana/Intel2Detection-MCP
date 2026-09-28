"""Create an isolated, local environment pack for one organization."""

import json
import re
import sys
from pathlib import Path

from . import environment, rule_repository, rules, store

ASSET_HEADER = "asset_id,hostname,product,version,confirmed_cves,internet_exposed,criticality,asset_role\n"
FAMILIES = ("process_creation", "network_connection", "mcp_audit")


def _profile(name, siem):
    if siem == "splunk":
        telemetry = {family: {"index": "replace_index", "sourcetype": "replace:sourcetype", "fields": []}
                     for family in FAMILIES}
    elif siem == "defender":
        tables = {"process_creation": "DeviceProcessEvents", "network_connection": "DeviceNetworkEvents",
                  "mcp_audit": "MCPAudit_CL"}
        telemetry = {family: {"table": table, "fields": []} for family, table in tables.items()}
    elif siem == "generic":
        telemetry = {family: {"source": "replace_source", "field_map": {}} for family in FAMILIES}
    else:
        raise ValueError("siem must be splunk, defender, or generic")
    profile = {"name": name, "siem": siem, "organization_aliases": [], "supplier_aliases": [],
               "telemetry": telemetry}
    environment.validate_profile(profile)
    return profile


def create_pack(directory, name, siem, python_executable=None):
    """Write no secrets, no synthetic assets, and no global configuration."""
    target = Path(directory).expanduser().resolve()
    if target.exists() and any(target.iterdir()):
        raise ValueError("target directory must be new or empty")
    profile = _profile(name, siem)
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    db = target / "intel.sqlite3"
    executable = str(Path(python_executable or sys.executable).resolve())
    claude = {"mcpServers": {"threat-research": {
        "command": executable, "args": ["-m", "threat_research.server"],
        "env": {"THREAT_RESEARCH_DB": str(db)}
    }}}
    (target / "profile.json").write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    (target / "assets.csv").write_text(ASSET_HEADER, encoding="utf-8")
    (target / "inventory.json").write_text("[]\n", encoding="utf-8")
    (target / "claude-mcp.json").write_text(json.dumps(claude, indent=2) + "\n", encoding="utf-8")
    store.initialize(db)
    # Each organization's rule repository lives beside its own database, so
    # it is isolated by construction -- never shared across packs, and no
    # credentials are ever written into it (it only holds detection text,
    # evidence, and review metadata computed from that pack's own database).
    repo = rule_repository.repo_dir(db)
    (repo / "draft").mkdir(parents=True, exist_ok=True)
    (repo / "approved").mkdir(parents=True, exist_ok=True)
    (repo / "README.md").write_text(rule_repository.README, encoding="utf-8")
    return {"directory": str(target), "siem": siem, "database": str(db), "rule_repository": str(repo),
            "files": ["profile.json", "assets.csv", "inventory.json", "claude-mcp.json", "rule-repository/"],
            "status": "templates_created_not_onboarded",
            "next_step": "Map real telemetry and verified assets, then onboard into this pack's database."}


def inspect_pack(directory):
    """Offline readiness check; no credentials or private asset rows are returned."""
    target = Path(directory).expanduser().resolve()
    profile = json.loads((target / "profile.json").read_text(encoding="utf-8"))
    environment.validate_profile(profile)
    asset_text = (target / "assets.csv").read_text(encoding="utf-8-sig")
    try:
        assets = environment.parse_assets(asset_text)
    except ValueError as exc:
        assets = []
        asset_issue = str(exc)
    else:
        asset_issue = None
    issues = [asset_issue] if asset_issue else []
    for family, config in profile["telemetry"].items():
        if profile["siem"] == "generic":
            if config["source"] == "replace_source" or not config["field_map"]:
                issues.append(f"{family}: map source and canonical fields")
        elif profile["siem"] == "splunk":
            if config["index"] == "replace_index" or not config["fields"]:
                issues.append(f"{family}: map index and fields")
        elif not config["fields"]:
            issues.append(f"{family}: map collected fields")
    return {"directory": str(target), "siem": profile["siem"], "assets_valid": len(assets),
            "ready_to_onboard": not issues, "issues": issues,
            "native_validation": profile["siem"] in ("splunk", "defender"),
            "rule_repository": str(rule_repository.repo_dir(pack_database(target))),
            "note": "Readiness checks supplied files only; they do not verify actual SIEM events or asset exposure."}


def pack_database(directory):
    target = Path(directory).expanduser().resolve()
    if not (target / "profile.json").is_file():
        raise ValueError("directory does not contain an enterprise environment pack")
    return target / "intel.sqlite3"


def onboard_pack(directory):
    """Validate every input before applying the local environment and rule mapping."""
    target = Path(directory).expanduser().resolve()
    db = pack_database(target)
    profile = json.loads((target / "profile.json").read_text(encoding="utf-8"))
    environment.validate_profile(profile)
    assets = environment.parse_assets((target / "assets.csv").read_text(encoding="utf-8-sig"))
    inventory = json.loads((target / "inventory.json").read_text(encoding="utf-8"))
    rules.validate_inventory(inventory)
    readiness = inspect_pack(target)
    if not readiness["ready_to_onboard"]:
        raise ValueError("finish profile mapping before onboarding: " + "; ".join(readiness["issues"]))
    installed = environment.onboard(profile, assets, db)
    imported = rules.import_inventory(inventory, db)
    return {"status": "onboarded", "database": str(db), "siem": profile["siem"],
            "assets": installed["assets"], "mapped_inventory_rules": imported["imported"],
            "note": "Only supplied mappings were imported. Native event and rule checks still require authorized SIEM access."}


def export_sigma_bundle(directory, rule_id):
    """Export a generic field mapping pipeline and a rule for local backend review."""
    if not re.fullmatch(r"[a-f0-9-]{36}", rule_id):
        raise ValueError("a generated rule UUID is required")
    db = pack_database(directory)
    fit = environment.check_rule_fit(rule_id, db)
    if fit.get("siem") != "generic" or not fit["ready"]:
        raise ValueError("generic profile with the rule's required canonical fields is needed")
    rule = rules.get_rule(rule_id, db)
    if not rule:
        raise ValueError("unknown local rule")
    if rule["behavior"] == "custom":
        family = rule["custom_spec"]["event_family"]
        category, product = ("application", "mcp_audit") if family == "mcp_audit" else (family, "windows")
    else:
        category, product = (("application", "mcp_audit") if rule["behavior"] == "mcp_unauthorized_execution"
                         else ("network_connection", "windows") if rule["behavior"] == "ioc_network"
                         else ("process_creation", "windows"))
    lines = [f"name: {json.dumps('ThreatResearch ' + rule['behavior'] + ' field mapping')}",
             "priority: 100", "transformations:", "  - id: field_map", "    type: field_name_mapping", "    mapping:"]
    lines.extend(f"      {json.dumps(key)}: {json.dumps(value)}" for key, value in fit["field_map"].items())
    lines += ["    rule_conditions:", "      - type: logsource", f"        category: {category}",
              f"        product: {product}"]
    target = Path(directory).expanduser().resolve() / "rules"
    target.mkdir(exist_ok=True)
    rule_file = target / f"{rule_id}.yml"
    pipeline_file = target / f"{rule_id}.pipeline.yml"
    rule_file.write_text(rule["sigma"], encoding="utf-8")
    pipeline_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return {"rule": str(rule_file), "field_pipeline": str(pipeline_file), "source": fit["source"],
            "status": "exported_for_local_conversion",
            "next_step": "Choose and install the correct Sigma backend, add its source/index condition, convert, and validate on representative events. No native query is verified or deployed."}
