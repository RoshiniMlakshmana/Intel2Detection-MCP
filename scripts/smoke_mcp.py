"""Start the actual stdio MCP server and call the synthetic lab tool."""

import asyncio
import json
import os
import sys
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main():
    with tempfile.TemporaryDirectory(prefix="threat-research-mcp-smoke-") as folder:
        params = StdioServerParameters(
            command=sys.executable, args=["-m", "threat_research.server"],
            env={**os.environ, "THREAT_RESEARCH_DB": str(Path(folder) / "intel.sqlite3")},
        )
        async with stdio_client(params) as (reader, writer):
            async with ClientSession(reader, writer) as session:
                await session.initialize()
                tools = await session.list_tools()
                names = {item.name for item in tools.tools}
                assert {"latest_threats", "behavior_review_leads", "evaluate_synthetic_soc_lab",
                        "risk_from_asset_inventory", "draft_detection", "implement_rule",
                        "research_detection_plan", "draft_custom_detection", "search_framework_techniques",
                        "list_sources", "list_leads", "lead_progression", "workflow_counts", "list_rules",
                        "source_errors"} <= names
                result = await session.call_tool("evaluate_synthetic_soc_lab", {})
                assert not result.is_error
                report = json.loads(result.content[0].text)
                assert report["measurement"]["counts"] == {"tp": 3, "fp": 2, "fn": 2, "tn": 5}
                assert report["approval"] == "drafts remain unapproved in the isolated lab inventory"
                source = "https://example.test/fictional-mcp-smoke-report"

                async def call(name, arguments):
                    response = await session.call_tool(name, arguments)
                    assert not response.is_error, (name, response.content)
                    return json.loads(response.content[0].text)

                registered = await call("register_campaign_report", {
                    "title": "Fictional campaign for MCP smoke validation",
                    "summary": "Synthetic report documents an encoded PowerShell execution and a local analyst review scenario.",
                    "source_url": source,
                })
                first = await call("record_observed_behavior", {
                    "threat_id": registered["id"], "source_url": source,
                    "claim": "Synthetic analyst verified encoded PowerShell execution in a fictional report.",
                    "behavior": "encoded_powershell",
                })
                refused = await call("draft_detection", {"threat_id": registered["id"], "evidence_id": 1})
                assert refused["status"] == "research_needed" and refused["rule_id"] is None, refused
                assert refused["draftable_evidence_ids"] == [first["evidence_id"]], refused
                proposed = await call("draft_detection", {"threat_id": registered["id"],
                                                            "evidence_id": first["evidence_id"]})
                assert proposed["status"] == "draft"
                approved = await call("implement_rule", {"rule_id": proposed["rule_id"],
                                                           "approval_phrase": "implement this rule"})
                assert approved["status"] == "approved_in_local_inventory"
                second = await call("record_observed_behavior", {
                    "threat_id": registered["id"], "source_url": source,
                    "claim": "Another independent synthetic observation verifies the same encoded PowerShell behavior.",
                    "behavior": "encoded_powershell",
                })
                existing = await call("draft_detection", {"threat_id": registered["id"],
                                                            "evidence_id": second["evidence_id"]})
                assert existing["status"] == "existing_coverage"
                corroborated = await call("implement_rule", {"rule_id": existing["rule_id"],
                                                               "approval_phrase": "implement this rule",
                                                               "new_evidence_id": second["evidence_id"]})
                repeated = await call("implement_rule", {"rule_id": existing["rule_id"],
                                                            "approval_phrase": "implement this rule",
                                                            "new_evidence_id": second["evidence_id"]})
                assert corroborated["pattern_score"] == repeated["pattern_score"] == 1
                leads = await call("list_leads", {"status": "evidence_recorded", "per_page": 500})
                assert leads["per_page"] == 50 and leads["total"] == 1, leads
                assert leads["items"][0]["source_url"] == source
                progression = await call("lead_progression", {"threat_id": registered["id"]})
                assert [s["key"] for s in progression["steps"]][-1] == "repository"
                assert next(s for s in progression["steps"] if s["key"] == "inventory")["answer"] == "Yes"
                counts = await call("workflow_counts", {})
                assert counts["approved_rules"] == 1 and "source_errors" in counts
                assert (await call("list_rules", {"state": "approved"}))["total"] == 1
                assert "sources" in await call("source_errors", {})
                assert any(c["name"] == "NVD" for c in (await call("list_sources", {}))["sources"])
                print(f"MCP stdio: {len(names)} tools; replay {report['measurement']['counts']}; approval and dedup passed")


if __name__ == "__main__":
    asyncio.run(main())
