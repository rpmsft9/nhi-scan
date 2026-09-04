from nhiscan.checks import Severity, run_checks
from nhiscan.models import (
    NHI,
    CredentialType,
    Environment,
    Exposure,
    NHIType,
    Privilege,
    SecretStorage,
)


def _nhi(**kw) -> NHI:
    base = dict(id="x", name="x", owner="o@example", credential=CredentialType.FEDERATED,
                secret_storage=SecretStorage.NONE)
    base.update(kw)
    return NHI(**base)


def _codes(n: NHI) -> set[str]:
    return {f.owasp_id for f in run_checks(n)}


def test_plaintext_secret_is_critical_leakage():
    n = _nhi(credential=CredentialType.STATIC_SECRET, secret_storage=SecretStorage.PLAINTEXT)
    findings = run_checks(n)
    leak = next(f for f in findings if f.owasp_id == "NHI2:2025")
    assert leak.severity is Severity.CRITICAL


def test_long_lived_secret_flagged():
    n = _nhi(credential=CredentialType.API_KEY, secret_storage=SecretStorage.VAULT,
             last_rotated_days=None)
    assert "NHI7:2025" in _codes(n)


def test_recently_rotated_secret_not_long_lived():
    n = _nhi(credential=CredentialType.API_KEY, secret_storage=SecretStorage.VAULT,
             last_rotated_days=10)
    assert "NHI7:2025" not in _codes(n)


def test_overprivileged_admin():
    assert "NHI5:2025" in _codes(_nhi(privilege=Privilege.ADMIN))


def test_wildcard_scope_is_overprivileged():
    assert "NHI5:2025" in _codes(_nhi(scopes=["ledger:*"]))


def test_cicd_static_credential_is_deployment_finding():
    n = _nhi(type=NHIType.CI_CD_TOKEN, credential=CredentialType.STATIC_SECRET,
             secret_storage=SecretStorage.VAULT)
    assert "NHI6:2025" in _codes(n)


def test_cicd_federated_is_not_deployment_finding():
    assert "NHI6:2025" not in _codes(_nhi(type=NHIType.CI_CD_TOKEN))


def test_internet_exposure_is_not_nhi6():
    # Internet exposure drives the risk tier (see test_tiering); OWASP scopes NHI6 to
    # CI/CD deployment configuration, so exposure alone must not claim it.
    assert "NHI6:2025" not in _codes(_nhi(exposure=Exposure.INTERNET))


def test_stale_is_offboarding():
    assert "NHI1:2025" in _codes(_nhi(last_used_days=365))


def test_shared_across_env():
    assert "NHI8:2025" in _codes(_nhi(shared_across_env=True))


def test_reuse():
    assert "NHI9:2025" in _codes(_nhi(used_by=["a", "b"]))


def test_human_use():
    assert "NHI10:2025" in _codes(_nhi(human_used=True))


def test_third_party():
    assert "NHI3:2025" in _codes(_nhi(third_party=True))


def test_clean_identity_has_no_findings():
    n = _nhi(
        type=NHIType.WORKLOAD_IDENTITY,
        environment=Environment.PROD,
        privilege=Privilege.SCOPED,
        credential=CredentialType.FEDERATED,
        secret_storage=SecretStorage.NONE,
        last_used_days=1,
        scopes=["features:read"],
    )
    assert run_checks(n) == []


def test_findings_sorted_by_severity():
    n = _nhi(credential=CredentialType.STATIC_SECRET, secret_storage=SecretStorage.PLAINTEXT,
             privilege=Privilege.ADMIN, exposure=Exposure.INTERNET, last_rotated_days=None)
    weights = [f.severity.weight for f in run_checks(n)]
    assert weights == sorted(weights, reverse=True)


# --- owner validity (presence vs. liveness) -----------------------------------------
def test_deprovisioned_owner_is_high_nhi1():
    n = _nhi(owner="jane@example", owner_active=False)
    f = next(x for x in run_checks(n) if x.owasp_id == "NHI1:2025")
    assert f.severity is Severity.HIGH
    assert "no longer an active account" in f.evidence.lower()


def test_missing_owner_is_medium_nhi1():
    n = _nhi(owner=None)
    f = next(x for x in run_checks(n) if x.owasp_id == "NHI1:2025")
    assert f.severity is Severity.MEDIUM


def test_live_owner_has_no_orphan_finding():
    n = _nhi(owner="jane@example", owner_active=True)
    assert "NHI1:2025" not in _codes(n)


def test_unknown_owner_liveness_is_backward_compatible():
    # owner present, liveness unknown (None default) -> not orphaned, as before
    n = _nhi(owner="jane@example")
    assert "NHI1:2025" not in _codes(n)
