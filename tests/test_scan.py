from pathlib import Path

from nhiscan import report
from nhiscan.ingest import load_fleet
from nhiscan.models import RiskTier
from nhiscan.scan import scan

EXAMPLE = Path(__file__).resolve().parents[1] / "examples" / "sample-inventory.json"


def _result():
    return scan(load_fleet(EXAMPLE))


def test_example_loads_all_identities():
    assert _result().total == 8


def test_example_has_critical_and_baseline():
    counts = _result().tier_counts
    assert counts[RiskTier.TIER_1] >= 1
    assert sum(counts.values()) == 8


def test_orphaned_detected():
    # key-legacy-etl has owner=null
    assert _result().orphaned == 1


def test_by_risk_is_descending():
    scores = [a.risk_score for a in _result().by_risk]
    assert scores == sorted(scores, reverse=True)


def test_highest_risk_is_a_crown_jewel():
    top = _result().by_risk[0]
    assert top.tier.tier is RiskTier.TIER_1


def test_owasp_counts_present():
    counts = _result().owasp_counts
    assert counts  # at least one OWASP finding
    assert all(code.startswith("NHI") for code in counts)


def test_markdown_renders():
    md = report.to_markdown(_result())
    assert "# Non-Human Identity Risk Report" in md
    assert "OWASP NHI Top 10" in md


def test_json_shape():
    data = report.to_json(_result())
    assert data["summary"]["total_identities"] == 8
    assert len(data["identities"]) == 8
    assert "tier" in data["identities"][0]
