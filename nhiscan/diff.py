"""Drift detection: compare two scans and surface how each identity *changed*.

A point-in-time posture scan re-tiers on the latest snapshot, but it does not tell you what
moved between runs. That matters most for **AI agents**: an agent's reach (its tools /
connectors / MCP servers, and its scopes) can grow without any change to privilege, credential
age, or owner — so the tier can look identical while the blast radius quietly expands. This
module diffs two inventories and flags that growth explicitly.

Everything is deterministic: a delta is a pure function of the two snapshots.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import NHI, Fleet
from .scan import Assessment, scan


def _added_removed(old: list[str], new: list[str]) -> tuple[list[str], list[str]]:
    olds, news = set(old), set(new)
    added = [x for x in new if x not in olds]
    removed = [x for x in old if x not in news]
    return added, removed


@dataclass
class IdentityDelta:
    id: str
    name: str
    status: str  # added | removed | changed | unchanged
    tier_before: int | None = None
    tier_after: int | None = None
    tools_added: list[str] = field(default_factory=list)
    tools_removed: list[str] = field(default_factory=list)
    scopes_added: list[str] = field(default_factory=list)
    scopes_removed: list[str] = field(default_factory=list)
    posture_changes: list[str] = field(default_factory=list)   # e.g. "became autonomous"
    findings_new: list[str] = field(default_factory=list)      # "NHI5:2025 Overprivileged NHI"
    findings_resolved: list[str] = field(default_factory=list)

    @property
    def tier_direction(self) -> str:
        if self.tier_before is None or self.tier_after is None:
            return "n/a"
        if self.tier_after < self.tier_before:
            return "escalated"   # lower number = more severe
        if self.tier_after > self.tier_before:
            return "reduced"
        return "same"

    @property
    def reach_grew(self) -> bool:
        return bool(self.tools_added or self.scopes_added)

    @property
    def risk_increased(self) -> bool:
        """The identity got riskier — even if the tier number didn't move."""
        return bool(
            self.tier_direction == "escalated"
            or self.reach_grew
            or self.posture_changes
            or self.findings_new
        )


@dataclass
class DriftReport:
    added: list[IdentityDelta] = field(default_factory=list)
    removed: list[IdentityDelta] = field(default_factory=list)
    changed: list[IdentityDelta] = field(default_factory=list)
    unchanged: int = 0

    @property
    def escalations(self) -> list[IdentityDelta]:
        return [d for d in self.changed if d.risk_increased]

    @property
    def reach_growth_only(self) -> list[IdentityDelta]:
        """Reach grew but the tier did NOT move — the exact blind spot drift closes."""
        return [d for d in self.changed if d.reach_grew and d.tier_direction != "escalated"]


def _owasp_labels(a: Assessment) -> dict[str, str]:
    return {f.owasp_id: f"{f.owasp_id} {f.owasp_title}" for f in a.findings}


def _posture_changes(old: NHI, new: NHI) -> list[str]:
    out: list[str] = []
    if not old.autonomous and new.autonomous:
        out.append("became autonomous")
    if not old.is_orphaned and new.is_orphaned:
        out.append("lost owner (now orphaned)")
    if old.privilege is not new.privilege:
        out.append(f"privilege {old.privilege.value} → {new.privilege.value}")
    if old.exposure is not new.exposure:
        out.append(f"exposure {old.exposure.value} → {new.exposure.value}")
    if old.credential is not new.credential:
        out.append(f"credential {old.credential.value} → {new.credential.value}")
    if old.secret_storage is not new.secret_storage:
        out.append(f"secret storage {old.secret_storage.value} → {new.secret_storage.value}")
    if not old.human_used and new.human_used:
        out.append("now human-used")
    if not old.shared_across_env and new.shared_across_env:
        out.append("now shared across environments")
    return out


def diff(old_fleet: Fleet, new_fleet: Fleet) -> DriftReport:
    old_scan = {a.nhi.id: a for a in scan(old_fleet).assessments}
    new_scan = {a.nhi.id: a for a in scan(new_fleet).assessments}
    report = DriftReport()

    for nid, a in new_scan.items():
        if nid not in old_scan:
            report.added.append(IdentityDelta(nid, a.nhi.name, "added", tier_after=int(a.tier.tier)))

    for nid, a in old_scan.items():
        if nid not in new_scan:
            report.removed.append(IdentityDelta(nid, a.nhi.name, "removed", tier_before=int(a.tier.tier)))

    for nid, new_a in new_scan.items():
        old_a = old_scan.get(nid)
        if old_a is None:
            continue
        o, n = old_a.nhi, new_a.nhi
        tools_added, tools_removed = _added_removed(o.tools, n.tools)
        scopes_added, scopes_removed = _added_removed(o.scopes, n.scopes)
        posture = _posture_changes(o, n)
        old_f, new_f = _owasp_labels(old_a), _owasp_labels(new_a)
        findings_new = [lbl for k, lbl in new_f.items() if k not in old_f]
        findings_resolved = [lbl for k, lbl in old_f.items() if k not in new_f]

        delta = IdentityDelta(
            id=nid, name=n.name,
            status="changed", tier_before=int(old_a.tier.tier), tier_after=int(new_a.tier.tier),
            tools_added=tools_added, tools_removed=tools_removed,
            scopes_added=scopes_added, scopes_removed=scopes_removed,
            posture_changes=posture, findings_new=findings_new, findings_resolved=findings_resolved,
        )
        any_change = (tools_added or tools_removed or scopes_added or scopes_removed
                      or posture or findings_new or findings_resolved
                      or delta.tier_direction != "same")
        if any_change:
            report.changed.append(delta)
        else:
            report.unchanged += 1

    # Most-concerning first.
    report.changed.sort(key=lambda d: (not d.risk_increased, d.tier_after or 9, d.id))
    return report
