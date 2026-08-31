import json
from datetime import datetime, timezone
from pathlib import Path

import sys

from nhiscan.ingest import load_fleet
from nhiscan.scan import scan
from tools.collectors import aws, csv_import, entra, entra_agents, gcp, mcp
from tools.collectors.common import KNOWN_FIELDS, days_since, read_input, run_cli

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


def test_read_input_tolerates_utf8_bom(tmp_path):
    # Windows PowerShell (`>`, Out-File) prepends a UTF-8 BOM; plain json.load rejects it.
    p = tmp_path / "bundle.json"
    p.write_bytes(b'\xef\xbb\xbf[{"id": "x", "name": "y"}]')
    assert read_input(["prog", str(p)]) == [{"id": "x", "name": "y"}]


def test_load_fleet_tolerates_utf8_bom(tmp_path):
    p = tmp_path / "inventory.json"
    p.write_bytes(b'\xef\xbb\xbf[{"id": "a", "name": "a"}]')
    assert len(load_fleet(p)) == 1


def test_run_cli_executes_cross_platform():
    # Exercises the platform-specific launch path (cmd.exe on Windows, direct on POSIX).
    assert "nhi-ok" in run_cli([sys.executable, "-c", "print('nhi-ok')"])


# --- Entra ----------------------------------------------------------------------------
def test_entra_transform():
    recs = entra.transform(_load("entra-sp.json"), tenant_id="TENANT-AAA", now=NOW)
    assert len(recs) == 4
    assert _only_known(recs)
    by_name = {r["name"]: r for r in recs}
    assert by_name["payments-connector"]["credential"] == "static_secret"
    assert by_name["payments-connector"]["last_rotated_days"] > 900
    assert by_name["reporting-federated"]["credential"] == "federated"
    assert "last_rotated_days" not in by_name["reporting-federated"]  # no creds -> omitted

    assert by_name["vendor-analytics-app"]["credential"] == "certificate"
    assert by_name["vendor-analytics-app"]["third_party"] is True
    assert "third_party" not in by_name["payments-connector"]  # same tenant -> omitted

    # grant data present -> real scopes and inferred privilege
    assert by_name["payments-connector"]["scopes"] == ["Payments.ReadWrite.All", "User.Read"]
    assert by_name["payments-connector"]["privilege"] == "privileged"
    # no grant data gathered -> omit rather than guess (conservative defaults apply)
    assert "privilege" not in by_name["reporting-federated"]
    assert "scopes" not in by_name["reporting-federated"]

    # a managed identity's platform-issued cert is not a stored secret: credential is
    # "managed" (no NHI4/NHI7 despite the old startDateTime), and its owner is emitted
    mi = by_name["aks-cluster-identity"]
    assert mi["credential"] == "managed"
    assert mi["secret_storage"] == "none"
    assert mi["owner"] == "platform@bank.example"
    # SPs gathered without owner data stay ownerless (orphaned) rather than guessing
    assert "owner" not in by_name["payments-connector"]


def test_entra_runs_as_module(tmp_path):
    # Exercises the real `python -m tools.collectors.entra` entrypoint (the __main__ block and
    # its sys.argv use), which importing transform() directly would not catch.
    import subprocess
    out = subprocess.check_output(
        [sys.executable, "-m", "tools.collectors.entra", str(SAMPLES / "entra-sp.json"),
         "--tenant", "TENANT-AAA"],
        cwd=str(Path(__file__).resolve().parents[1]), text=True)
    recs = json.loads(out)
    assert isinstance(recs, list) and len(recs) == 4


def test_entra_skips_agent_identities():
    sps = _load("entra-sp.json") + [{
        "id": "agent-1", "displayName": "some-agent",
        "servicePrincipalType": "ServiceIdentity",
    }]
    recs = entra.transform(sps, tenant_id="TENANT-AAA", now=NOW)
    assert len(recs) == 4  # the agent identity belongs to the entra_agents collector


# --- AWS ------------------------------------------------------------------------------
def test_aws_transform():
    recs = aws.transform(_load("aws-users.json"), now=NOW)
    assert len(recs) == 3
    assert _only_known(recs)
    by_name = {r["name"].split(" ")[0]: r for r in recs}
    admin = by_name["svc-etl"]
    assert admin["privilege"] == "admin"
    assert admin["owner"] == "data-eng@bank.example"
    assert admin["last_used_days"] <= 2
    assert admin["type"] == "api_key"
    scoped = by_name["svc-reports"]
    assert scoped["privilege"] == "scoped"
    assert scoped["last_used_days"] > 90  # stale

    # nothing attached directly — admin arrives through group membership,
    # and the wildcard inline policy surfaces as a wildcard scope (NHI5)
    deploy = by_name["svc-deploy"]
    assert deploy["privilege"] == "admin"
    assert deploy["scopes"] == ["*"]


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

    # roles/editor is project-wide write -> admin; scoped role stays scoped
    assert by_name["batch-runner"]["privilege"] == "admin"
    assert by_name["batch-runner"]["scopes"] == ["roles/editor", "roles/storage.objectAdmin"]
    assert by_name["workload-federated"]["privilege"] == "scoped"


def test_gcp_without_bindings_omits_privilege():
    accounts = _load("gcp-accounts.json")
    for a in accounts:
        del a["roles"]
    recs = gcp.transform(accounts, now=NOW)
    assert all("privilege" not in r and "scopes" not in r for r in recs)


# --- CSV ------------------------------------------------------------------------------
def test_mcp_collector_builds_agent_tools():
    recs = mcp.transform(_load("mcp-agents.json"))
    assert _only_known(recs)
    by_id = {r["id"]: r for r in recs}
    agent = by_id["agent-collections"]
    assert agent["type"] == "ai_agent"
    assert agent["autonomous"] is True
    assert agent["tools"] == ["crm.lookup", "crm.update", "email.send"]  # server-namespaced
    analyst = by_id["agent-analyst"]
    # flat tools + server tools merge, de-duped, order preserved
    assert analyst["tools"] == ["sql.read_only", "warehouse.query"]


def test_mcp_output_scans(tmp_path):
    recs = mcp.transform(_load("mcp-agents.json"))
    p = tmp_path / "agents.json"
    p.write_text(json.dumps(recs), encoding="utf-8")
    result = scan(load_fleet(p))
    assert result.total == 2  # both agents assessed


def test_csv_parses_tools_column():
    text = "id,name,type,tools\nag1,agent-one,ai_agent,crm.lookup;payments.refund\n"
    rec = csv_import.transform_csv_text(text)[0]
    assert rec["tools"] == ["crm.lookup", "payments.refund"]


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



# --- Entra Agent ID -------------------------------------------------------------------
def test_entra_agents_transform():
    bundle = _load("entra-agents.json")
    recs = entra_agents.transform(bundle, now=NOW)
    assert len(recs) == 4
    assert _only_known(recs)
    by_name = {r["name"]: r for r in recs}

    # every agent identity is an ai_agent, not a generic service principal
    assert all(r["type"] == "ai_agent" for r in recs)

    # application permissions => acts with no user present
    assert by_name["claims-review-agent"]["autonomous"] is True
    # delegated-only grants => not autonomous, and the scopes still come through
    assert "autonomous" not in by_name["drafting-assistant"]
    assert by_name["drafting-assistant"]["scopes"] == ["User.Read", "Mail.Send"]

    # sponsor becomes the accountable owner
    assert by_name["claims-review-agent"]["owner"] == "dana@bank.example"
    # no sponsor and no owner => orphaned, so nhi-scan can flag it (NHI1)
    assert "owner" not in by_name["orphaned-batch-agent"]

    # privilege is inferred from the granted roles
    assert by_name["claims-review-agent"]["privilege"] == "admin"      # Directory.ReadWrite.All
    assert by_name["orphaned-batch-agent"]["privilege"] == "admin"     # wildcard ledger:*
    assert by_name["vendor-triage-agent"]["privilege"] == "scoped"

    # credential shape and rotation age
    assert by_name["claims-review-agent"]["credential"] == "static_secret"
    assert by_name["drafting-assistant"]["credential"] == "federated"
    assert by_name["vendor-triage-agent"]["credential"] == "certificate"
    assert by_name["orphaned-batch-agent"]["last_rotated_days"] > 900

    # third party derived from the owning tenant
    assert by_name["vendor-triage-agent"]["third_party"] is True
    assert "third_party" not in by_name["claims-review-agent"]


def test_entra_agents_accepts_bare_list_and_groups_blueprints():
    bundle = _load("entra-agents.json")
    assert entra_agents.transform(bundle["agents"], now=NOW)  # bare list works too
    groups = entra_agents.blueprint_summary(bundle)
    assert len(groups) == 3
    assert len(groups["bp-claims-0000-0000-0000-000000000001"]) == 2


def test_entra_agents_output_scans(tmp_path):
    recs = entra_agents.transform(_load("entra-agents.json"), now=NOW)
    path = tmp_path / "agents.json"
    path.write_text(json.dumps(recs), encoding="utf-8")
    result = scan(load_fleet(path))
    assert result.total == len(recs) == 4

    by_name = {a.nhi.name: a for a in result.assessments}
    # autonomous + wildcard privilege + orphaned + stale secret = crown jewel
    assert int(by_name["orphaned-batch-agent"].tier.tier) == 1
    assert by_name["orphaned-batch-agent"].findings
    # the delegated, federated, sponsored agent should not rank alongside it
    assert int(by_name["drafting-assistant"].tier.tier) > 1

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
    assert result.total == len(merged) == 12
    # the plaintext admin internet-facing legacy key must land Tier 1
    assert any(a.tier.tier.value == 1 for a in result.assessments)
