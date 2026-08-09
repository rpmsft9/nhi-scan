import json
from datetime import datetime, timezone
from pathlib import Path

from nhiscan.ingest import load_fleet
from nhiscan.scan import scan
from tools.collectors import aws, csv_import, entra, gcp
from tools.collectors.common import KNOWN_FIELDS, days_since

SAMPLES = Path(__file__).resolve().parents[1] / "tools" / "samples"
NOW = datetime(2026, 8, 9, tzinfo=timezone.utc)


def _load(name):
    return json.loads((SAMPLES / name).read_text(encoding="utf-8"))


def _only_known(records):
    return all(set(r).issubset(KNOWN_FIELDS) for r in records)


# --- common ---------------------------------------------------------------------------
def test_days_since_handles_formats():
    assert days_since("2026-07-10T00:00:00Z", now=NOW) == 30
    assert days_since("2026-07-10T00:00:00+00:00", now=NOW) == 30
    assert days_since("2026-07-10", now=NOW) == 30
    assert days_since(None, now=NOW) is None
    assert days_since("not-a-date", now=NOW) is None


# --- Entra ----------------------------------------------------------------------------
def test_entra_transform():
    recs = entra.transform(_load("entra-sp.json"), tenant_id="TENANT-AAA", now=NOW)
    assert len(recs) == 3
    assert _only_known(recs)
    by_name = {r["name"]: r for r in recs}
    assert by_name["payments-connector"]["credential"] == "static_secret"
    assert by_name["payments-connector"]["last_rotated_days"] > 900
    assert by_name["reporting-federated"]["credential"] == "federated"
    assert "last_rotated_days" not in by_name["reporting-federated"]  # no creds -> omitted
    assert by_name["vendor-analytics-app"]["credential"] == "certificate"
    assert by_name["vendor-analytics-app"]["third_party"] is True
    assert "third_party" not in by_name["payments-connector"]  # same tenant -> omitted


# --- AWS ------------------------------------------------------------------------------
def test_aws_transform():
    recs = aws.transform(_load("aws-users.json"), now=NOW)
    assert len(recs) == 2
    assert _only_known(recs)
    admin = next(r for r in recs if r["privilege"] == "admin")
    assert admin["owner"] == "data-eng@bank.example"
    assert admin["last_used_days"] <= 2
    assert admin["type"] == "api_key"
    scoped = next(r for r in recs if r["privilege"] == "scoped")
    assert scoped["last_used_days"] > 90  # stale


# --- GCP ------------------------------------------------------------------------------
def test_gcp_transform():
    recs = gcp.transform(_load("gcp-accounts.json"), now=NOW)
    assert len(recs) == 2
    assert _only_known(recs)
    by_name = {r["name"]: r for r in recs}
    assert by_name["batch-runner"]["credential"] == "static_secret"
    assert by_name["batch-runner"]["last_rotated_days"] > 800
    assert by_name["workload-federated"]["credential"] == "managed"
    assert "last_rotated_days" not in by_name["workload-federated"]


# --- CSV ------------------------------------------------------------------------------
def test_csv_transform():
    recs = csv_import.transform_csv_text((SAMPLES / "identities.csv").read_text(encoding="utf-8"))
    assert len(recs) == 3
    assert _only_known(recs)
    by_id = {r["id"]: r for r in recs}
    agent = by_id["agent-support"]
    assert agent["autonomous"] is True
    assert "accounts:*" in agent["scopes"]
    legacy = by_id["key-legacy"]
    assert "owner" not in legacy           # blank owner -> omitted (orphaned)
    assert legacy["third_party"] is True
    assert legacy["secret_storage"] == "plaintext"
    assert "last_rotated_days" not in legacy  # blank int -> omitted


# --- round-trip: collector output feeds nhi-scan --------------------------------------
def test_collector_output_scans(tmp_path):
    merged = (
        entra.transform(_load("entra-sp.json"), tenant_id="TENANT-AAA", now=NOW)
        + aws.transform(_load("aws-users.json"), now=NOW)
        + gcp.transform(_load("gcp-accounts.json"), now=NOW)
        + csv_import.transform_csv_text((SAMPLES / "identities.csv").read_text(encoding="utf-8"))
    )
    p = tmp_path / "merged.json"
    p.write_text(json.dumps(merged), encoding="utf-8")
    result = scan(load_fleet(p))
    assert result.total == len(merged) == 10
    # the plaintext admin internet-facing legacy key must land Tier 1
    assert any(a.tier.tier.value == 1 for a in result.assessments)
