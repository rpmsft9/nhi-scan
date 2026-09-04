from nhiscan import tiering
from nhiscan.models import (
    NHI,
    CredentialType,
    Environment,
    Exposure,
    NHIType,
    Privilege,
    RiskTier,
)


def _nhi(**kw) -> NHI:
    base = dict(id="x", name="x", owner="o@example")
    base.update(kw)
    return NHI(**base)


def test_baseline_is_tier4():
    n = _nhi(
        type=NHIType.WORKLOAD_IDENTITY,
        environment=Environment.SANDBOX,
        privilege=Privilege.READ_ONLY,
        credential=CredentialType.FEDERATED,
    )
    assert tiering.assess(n).tier is RiskTier.TIER_4


def test_admin_static_secret_is_critical():
    n = _nhi(privilege=Privilege.ADMIN, credential=CredentialType.STATIC_SECRET)
    res = tiering.assess(n)
    assert res.tier is RiskTier.TIER_1
    assert any(r.rule_id == "ADMIN_STATIC_SECRET" for r in res.reasons)


def test_privileged_orphan_is_critical():
    n = _nhi(owner=None, privilege=Privilege.PRIVILEGED, credential=CredentialType.FEDERATED)
    assert tiering.assess(n).tier is RiskTier.TIER_1


def test_autonomous_privileged_agent_is_critical():
    n = _nhi(type=NHIType.AI_AGENT, autonomous=True, privilege=Privilege.PRIVILEGED,
             credential=CredentialType.FEDERATED)
    assert tiering.assess(n).tier is RiskTier.TIER_1


def test_internet_exposed_privileged_is_critical():
    n = _nhi(exposure=Exposure.INTERNET, privilege=Privilege.PRIVILEGED,
             credential=CredentialType.FEDERATED)
    assert tiering.assess(n).tier is RiskTier.TIER_1


def test_autonomous_agent_scoped_is_high():
    n = _nhi(type=NHIType.AI_AGENT, autonomous=True, privilege=Privilege.SCOPED,
             credential=CredentialType.FEDERATED, environment=Environment.NONPROD)
    assert tiering.assess(n).tier is RiskTier.TIER_2


def test_tier_is_most_severe_floor():
    # prod (tier 3) + overprivileged (tier 2) -> tier 2
    n = _nhi(environment=Environment.PROD, privilege=Privilege.ADMIN,
             credential=CredentialType.FEDERATED)
    # admin also triggers OVERPRIVILEGED (tier2), not admin-static (needs static secret)
    assert tiering.assess(n).tier is RiskTier.TIER_2


def test_assessment_is_reproducible():
    n = _nhi(privilege=Privilege.ADMIN, credential=CredentialType.STATIC_SECRET)
    assert tiering.assess(n) == tiering.assess(n)


def test_reasons_sorted_most_severe_first():
    n = _nhi(privilege=Privilege.ADMIN, credential=CredentialType.STATIC_SECRET,
             environment=Environment.PROD)
    reasons = tiering.assess(n).reasons
    floors = [int(r.floor) for r in reasons]
    assert floors == sorted(floors)


def test_privileged_deprovisioned_owner_is_tier1():
    n = _nhi(privilege=Privilege.ADMIN, credential=CredentialType.FEDERATED,
             owner="jane@example", owner_active=False)
    assert tiering.assess(n).tier is RiskTier.TIER_1


def test_privileged_live_owner_is_not_tier1_orphan():
    n = _nhi(privilege=Privilege.ADMIN, credential=CredentialType.FEDERATED,
             owner="jane@example", owner_active=True)
    assert tiering.assess(n).tier is not RiskTier.TIER_1
