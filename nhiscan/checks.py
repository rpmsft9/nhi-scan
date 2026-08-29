"""Control checks that map an NHI's posture to the OWASP NHI Top 10.

Each check is a pure function of a single NHI. If the posture matches, it emits a Finding
tied to a specific OWASP NHI id, with the concrete evidence and a least-privilege
remediation. Checks are deliberately conservative — they only fire on posture the inventory
actually asserts, so findings are actionable rather than speculative.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

from . import owasp
from .models import NHI, ROTATION_MAX_DAYS, STALE_DAYS, CredentialType, NHIType


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {"info": 1, "low": 2, "medium": 4, "high": 8, "critical": 12}[self.value]


@dataclass
class Finding:
    nhi_id: str
    nhi_name: str
    owasp_id: str
    severity: Severity
    evidence: str
    remediation: str

    @property
    def owasp_title(self) -> str:
        return owasp.get(self.owasp_id).title

    def to_dict(self) -> dict:
        return {
            "nhi_id": self.nhi_id,
            "nhi_name": self.nhi_name,
            "owasp_id": self.owasp_id,
            "owasp_title": self.owasp_title,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


Check = Callable[[NHI], Optional[Finding]]


def _f(n: NHI, code: str, sev: Severity, evidence: str, remediation: str) -> Finding:
    return Finding(n.id, n.name, code, sev, evidence, remediation)


# --- NHI1: Improper Offboarding -------------------------------------------------------
def check_offboarding(n: NHI) -> Optional[Finding]:
    if n.is_stale:
        sev = Severity.HIGH if n.privilege.is_elevated else Severity.MEDIUM
        return _f(
            n, "NHI1:2025", sev,
            f"Unused for {n.last_used_days} days (staleness window is {STALE_DAYS}).",
            "Deprovision or disable; if still required, re-justify ownership and set an expiry.",
        )
    if n.is_orphaned:
        return _f(
            n, "NHI1:2025", Severity.MEDIUM,
            "No accountable owner recorded.",
            "Assign a named owner and confirm the identity is still needed; otherwise offboard.",
        )
    return None


# --- NHI2: Secret Leakage -------------------------------------------------------------
def check_secret_leakage(n: NHI) -> Optional[Finding]:
    if not n.has_static_secret:
        return None
    if n.secret_storage.value == "plaintext":
        return _f(
            n, "NHI2:2025", Severity.CRITICAL,
            "Static secret stored in plaintext (hardcoded/committed/config).",
            "Move the secret to a managed vault, rotate it immediately, and scan history for exposure.",
        )
    if n.secret_storage.value == "env":
        return _f(
            n, "NHI2:2025", Severity.MEDIUM,
            "Static secret injected via environment variable (readable by the process and crash dumps).",
            "Source the secret from a vault at runtime; avoid long-lived env injection.",
        )
    return None


# --- NHI3: Vulnerable Third-Party NHI -------------------------------------------------
def check_third_party(n: NHI) -> Optional[Finding]:
    if n.third_party:
        sev = Severity.HIGH if n.privilege.is_elevated else Severity.MEDIUM
        return _f(
            n, "NHI3:2025", sev,
            "Identity is issued to / operated by an external third party.",
            "Constrain to least-privilege scopes, require short-lived credentials, and monitor its access.",
        )
    return None


# --- NHI4: Insecure Authentication ----------------------------------------------------
def check_insecure_auth(n: NHI) -> Optional[Finding]:
    if n.credential in (CredentialType.STATIC_SECRET, CredentialType.API_KEY):
        return _f(
            n, "NHI4:2025", Severity.MEDIUM,
            f"Authenticates with {n.credential.value} rather than federated/managed identity.",
            "Migrate to workload identity federation (OIDC) or a cloud-managed identity — no stored secret.",
        )
    return None


# --- NHI5: Overprivileged NHI ---------------------------------------------------------
def check_overprivileged(n: NHI) -> Optional[Finding]:
    if n.privilege.value == "admin":
        return _f(
            n, "NHI5:2025", Severity.HIGH,
            "Holds admin privilege.",
            "Right-size to the specific permissions the workload uses; remove standing admin.",
        )
    if n.has_wildcard_scope:
        return _f(
            n, "NHI5:2025", Severity.HIGH,
            f"Carries wildcard/full-access scope: {', '.join(n.scopes)}.",
            "Replace wildcard scopes with the explicit, minimal set the workload calls.",
        )
    return None


# --- NHI6: Insecure Cloud Deployment Configurations -----------------------------------
def check_deployment_config(n: NHI) -> Optional[Finding]:
    """OWASP scopes NHI6 to deployment configuration: CI/CD pipelines authenticating with
    static credentials, or OIDC federation lacking audience/subject claim restrictions.
    The inventory can assert the first directly; claim-restriction state is not modeled,
    so the check stays conservative. Internet exposure is a tiering driver (tiering.py),
    not an NHI6 finding."""
    if n.type == NHIType.CI_CD_TOKEN and n.credential in (
        CredentialType.STATIC_SECRET, CredentialType.API_KEY
    ):
        sev = Severity.CRITICAL if n.privilege.is_elevated else Severity.HIGH
        return _f(
            n, "NHI6:2025", sev,
            f"CI/CD pipeline authenticates with a {n.credential.value} instead of OIDC workload identity federation.",
            "Move the pipeline to OIDC federation with audience and subject claim restrictions; retire the static credential.",
        )
    return None


# --- NHI7: Long-Lived Secrets ---------------------------------------------------------
def check_long_lived(n: NHI) -> Optional[Finding]:
    if not n.is_long_lived:
        return None
    if n.last_rotated_days is None:
        evidence = "Static secret with no recorded rotation (never rotated)."
    else:
        evidence = f"Static secret last rotated {n.last_rotated_days} days ago (max is {ROTATION_MAX_DAYS})."
    sev = Severity.HIGH if n.environment.value == "prod" else Severity.MEDIUM
    return _f(
        n, "NHI7:2025", sev, evidence,
        "Rotate now and automate rotation; prefer short-lived, auto-issued credentials.",
    )


# --- NHI8: Environment Isolation ------------------------------------------------------
def check_environment_isolation(n: NHI) -> Optional[Finding]:
    if n.shared_across_env:
        return _f(
            n, "NHI8:2025", Severity.HIGH,
            "Same identity/credential is used across production and non-production.",
            "Split into per-environment identities so a non-prod compromise cannot reach prod.",
        )
    return None


# --- NHI9: NHI Reuse ------------------------------------------------------------------
def check_reuse(n: NHI) -> Optional[Finding]:
    if n.is_reused:
        return _f(
            n, "NHI9:2025", Severity.MEDIUM,
            f"Shared across {len(n.used_by)} workloads: {', '.join(n.used_by)}.",
            "Issue a dedicated identity per workload to restore least privilege and attribution.",
        )
    return None


# --- NHI10: Human Use of NHI ----------------------------------------------------------
def check_human_use(n: NHI) -> Optional[Finding]:
    if n.human_used:
        return _f(
            n, "NHI10:2025", Severity.HIGH,
            "A human authenticates interactively with this non-human identity.",
            "Give humans their own identities; reserve this NHI for automation and block interactive login.",
        )
    return None


CHECKS: list[Check] = [
    check_offboarding,
    check_secret_leakage,
    check_third_party,
    check_insecure_auth,
    check_overprivileged,
    check_deployment_config,
    check_long_lived,
    check_environment_isolation,
    check_reuse,
    check_human_use,
]


def run_checks(n: NHI) -> list[Finding]:
    """Every finding this NHI's posture warrants, sorted most-severe first."""
    findings = [f for f in (chk(n) for chk in CHECKS) if f is not None]
    findings.sort(key=lambda f: (-f.severity.weight, f.owasp_id))
    return findings
