import json

from nhiscan.ingest import load_fleet
from nhiscan.models import CredentialType, Environment, NHIType, Privilege


def test_partial_record_gets_safe_defaults(tmp_path):
    p = tmp_path / "inv.json"
    p.write_text(json.dumps([{"id": "a", "name": "a"}]), encoding="utf-8")
    n = load_fleet(p).identities[0]
    assert n.type is NHIType.SERVICE_ACCOUNT
    assert n.environment is Environment.PROD
    assert n.privilege is Privilege.SCOPED
    assert n.is_orphaned  # no owner supplied


def test_unknown_enum_value_falls_back(tmp_path):
    p = tmp_path / "inv.json"
    p.write_text(json.dumps([{"id": "a", "name": "a", "privilege": "wizard"}]), encoding="utf-8")
    assert load_fleet(p).identities[0].privilege is Privilege.SCOPED


def test_scopes_string_coerced_to_list(tmp_path):
    p = tmp_path / "inv.json"
    p.write_text(json.dumps([{"id": "a", "name": "a", "scopes": "repo:*"}]), encoding="utf-8")
    n = load_fleet(p).identities[0]
    assert n.scopes == ["repo:*"]
    assert n.has_wildcard_scope


def test_identities_key_wrapper(tmp_path):
    p = tmp_path / "inv.json"
    p.write_text(json.dumps({"identities": [{"id": "a", "name": "a"}]}), encoding="utf-8")
    assert len(load_fleet(p)) == 1


def test_federated_credential_is_not_static(tmp_path):
    p = tmp_path / "inv.json"
    p.write_text(json.dumps([{"id": "a", "name": "a", "credential": "federated"}]), encoding="utf-8")
    n = load_fleet(p).identities[0]
    assert n.credential is CredentialType.FEDERATED
    assert not n.has_static_secret


def test_owner_active_tristate_parsed(tmp_path):
    p = tmp_path / "inv.json"
    p.write_text(json.dumps([
        {"id": "a", "name": "a", "owner": "j@x", "owner_active": False},
        {"id": "b", "name": "b", "owner": "k@x", "owner_active": True},
        {"id": "c", "name": "c", "owner": "l@x"},  # absent -> None (backward compatible)
    ]), encoding="utf-8")
    a, b, c = load_fleet(p).identities
    assert a.owner_active is False and a.is_orphaned and a.orphan_reason == "owner deprovisioned"
    assert b.owner_active is True and not b.is_orphaned
    assert c.owner_active is None and not c.is_orphaned
