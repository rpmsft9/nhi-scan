from pathlib import Path

from nhiscan import report
from nhiscan.diff import diff
from nhiscan.ingest import load_fleet

EX = Path(__file__).resolve().parents[1] / "examples"
BEFORE = EX / "sample-inventory.json"
AFTER = EX / "sample-inventory-after.json"


def _report():
    return diff(load_fleet(BEFORE), load_fleet(AFTER))


def _by_id(deltas):
    return {d.id: d for d in deltas}


def test_added_and_removed_detected():
    rep = _report()
    assert "svc-new-integration" in _by_id(rep.added)
    assert "hook-sandbox-test" in _by_id(rep.removed)


def test_agent_reach_grew_without_tier_change():
    """The CISO's scenario: agent gains tools + a scope; privilege/cred/owner unchanged;
    tier stays the same but reach clearly grew."""
    rep = _report()
    agent = _by_id(rep.changed)["agent-collections"]
    assert "payment_refund_api" in agent.tools_added
    assert "customer_db_query" in agent.tools_added
    assert "payments:refund" in agent.scopes_added
    assert agent.tier_direction == "same"        # still Tier 1
    assert agent.reach_grew is True
    assert agent.risk_increased is True
    assert agent in rep.reach_growth_only        # surfaced despite unchanged tier


def test_tier_escalation_detected():
    rep = _report()
    sp = _by_id(rep.changed)["sp-analytics-vendor"]
    assert sp.tier_direction == "escalated"       # scoped -> wildcard => tier 3 -> 2
    assert any("NHI5" in f for f in sp.findings_new)
    assert "reports:*" in sp.scopes_added


def test_escalations_include_agent_and_vendor():
    rep = _report()
    ids = {d.id for d in rep.escalations}
    assert {"agent-collections", "sp-analytics-vendor"} <= ids


def test_markdown_and_json_render():
    rep = _report()
    md = report.drift_to_markdown(rep)
    assert "Drift Report" in md
    assert "Reach grew without a tier change" in md
    data = report.drift_to_json(rep)
    assert data["summary"]["reach_growth_without_tier_change"] >= 1
    assert any(c["id"] == "agent-collections" for c in data["changed"])


def test_no_change_when_identical():
    rep = diff(load_fleet(BEFORE), load_fleet(BEFORE))
    assert rep.changed == [] and rep.added == [] and rep.removed == []
    assert rep.unchanged == 8
