"""Render a ScanResult (or a DriftReport) as Markdown or a JSON object."""

from __future__ import annotations

import re

from . import owasp
from .diff import DriftReport, IdentityDelta
from .models import RiskTier
from .scan import ScanResult

_TIER_BADGE = {1: "🔴 Critical", 2: "🟠 High", 3: "🟡 Moderate", 4: "🟢 Baseline"}
_ARROW = {"escalated": "🔺", "reduced": "🔻", "same": "＝", "n/a": ""}

# Markdown control characters to neutralize in identity-controlled fields — the identity name,
# owner, and id, which are emitted in high-impact positions (a `###` heading, bold text). These
# values come from the inventory, ultimately from a directory where an attacker may control, e.g.,
# an app's display name, so emitting them raw would let a crafted name inject markup or a link when
# the report is later rendered as HTML. (Finding evidence is tool-composed prose and scope names
# are platform-constrained, so those are left as-is to avoid mangling. The JSON output is unaffected.)
_MD_SPECIAL = re.compile(r"([\\`*_\[\]()#!|~])")


def _md(text) -> str:
    """Escape a value for safe inclusion in the Markdown report."""
    s = str(text).replace("\r", " ").replace("\n", " ")
    s = s.replace("<", "&lt;").replace(">", "&gt;")   # neutralize raw HTML
    return _MD_SPECIAL.sub(r"\\\1", s)


def to_json(result: ScanResult) -> dict:
    return {
        "summary": {
            "total_identities": result.total,
            "findings": result.finding_count,
            "orphaned": result.orphaned,
            "long_lived_secrets": result.long_lived,
            "tier_counts": {t.name: c for t, c in result.tier_counts.items()},
            "type_counts": result.type_counts,
            "owasp_counts": result.owasp_counts,
        },
        "identities": [
            {
                "id": a.nhi.id,
                "name": a.nhi.name,
                "type": a.nhi.type.value,
                "tier": int(a.tier.tier),
                "tier_label": a.tier.tier.label,
                "risk_score": a.risk_score,
                "reasons": [
                    {"rule": r.rule_id, "floor": int(r.floor), "rationale": r.rationale}
                    for r in a.tier.reasons
                ],
                "findings": [f.to_dict() for f in a.findings],
            }
            for a in result.by_risk
        ],
    }


def to_markdown(result: ScanResult) -> str:
    out: list[str] = []
    out.append("# Non-Human Identity Risk Report\n")

    tc = result.tier_counts
    out.append(
        f"**{result.total}** identities · **{result.finding_count}** findings · "
        f"**{result.orphaned}** orphaned · **{result.long_lived}** long-lived secrets\n"
    )

    out.append("## Risk tiers\n")
    out.append("| Tier | Identities |")
    out.append("| --- | ---: |")
    for t in RiskTier:
        out.append(f"| {_TIER_BADGE[int(t)]} | {tc[t]} |")
    out.append("")

    if result.owasp_counts:
        out.append("## OWASP NHI Top 10 findings\n")
        out.append("| OWASP | Title | Count |")
        out.append("| --- | --- | ---: |")
        for code, count in result.owasp_counts.items():
            out.append(f"| {code} | {owasp.get(code).title} | {count} |")
        out.append(f"\n_Mapped to the [OWASP NHI Top 10]({owasp.SOURCE_URL})._\n")

    out.append("## Identities by risk\n")
    for a in result.by_risk:
        n = a.nhi
        owner = _md(n.owner) if n.owner else "_orphaned_"
        out.append(f"### {_TIER_BADGE[int(a.tier.tier)]} — {_md(n.name)} `({n.type.value})`")
        out.append(
            f"- **Owner:** {owner} · **Env:** {n.environment.value} · "
            f"**Privilege:** {n.privilege.value} · **Score:** {a.risk_score}"
        )
        out.append(f"- **Why this tier:** {a.tier.top_rationale}")
        if a.findings:
            out.append("- **Findings:**")
            for f in a.findings:
                out.append(
                    f"  - `{f.severity.value.upper()}` **{f.owasp_id} {f.owasp_title}** — "
                    f"{f.evidence} _→ {f.remediation}_"
                )
        out.append("")

    return "\n".join(out)


# ---- drift (scan-to-scan) rendering --------------------------------------------------

def _delta_lines(d: IdentityDelta) -> list[str]:
    out: list[str] = []
    if d.tier_before is not None and d.tier_after is not None:
        arrow = _ARROW[d.tier_direction]
        out.append(
            f"  - Tier: {_TIER_BADGE[d.tier_before]} → {_TIER_BADGE[d.tier_after]} {arrow} "
            f"({d.tier_direction})"
        )
    if d.tools_added:
        out.append(f"  - **Tools added (reach ↑):** {', '.join(d.tools_added)}")
    if d.tools_removed:
        out.append(f"  - Tools removed: {', '.join(d.tools_removed)}")
    if d.scopes_added:
        out.append(f"  - **Scopes added (reach ↑):** {', '.join(d.scopes_added)}")
    if d.scopes_removed:
        out.append(f"  - Scopes removed: {', '.join(d.scopes_removed)}")
    for change in d.posture_changes:
        out.append(f"  - Posture: {change}")
    for f in d.findings_new:
        out.append(f"  - `NEW` finding: {f}")
    for f in d.findings_resolved:
        out.append(f"  - `resolved`: {f}")
    return out


def drift_to_markdown(report: DriftReport) -> str:
    out: list[str] = ["# Non-Human Identity Drift Report\n"]
    out.append(
        f"**{len(report.changed)}** changed · **{len(report.added)}** added · "
        f"**{len(report.removed)}** removed · **{report.unchanged}** unchanged · "
        f"**{len(report.escalations)}** risk escalations\n"
    )

    reach_only = report.reach_growth_only
    if reach_only:
        out.append("## ⚠️ Reach grew without a tier change\n")
        out.append("_These identities gained tools or scopes while privilege, credential age, "
                   "and owner stayed the same — the blind spot a point-in-time tier misses._\n")
        for d in reach_only:
            out.append(f"### {_md(d.name)} `({_md(d.id)})`")
            out.extend(_delta_lines(d))
            out.append("")

    if report.escalations:
        out.append("## 🔺 Risk escalations\n")
        for d in report.escalations:
            if d in reach_only:
                continue
            out.append(f"### {_md(d.name)} `({_md(d.id)})`")
            out.extend(_delta_lines(d))
            out.append("")

    if report.added:
        out.append("## Added identities\n")
        for d in report.added:
            out.append(f"- **{_md(d.name)}** `({_md(d.id)})` — {_TIER_BADGE[d.tier_after]}")
        out.append("")
    if report.removed:
        out.append("## Removed identities\n")
        for d in report.removed:
            out.append(f"- {_md(d.name)} `({_md(d.id)})` — was {_TIER_BADGE[d.tier_before]}")
        out.append("")

    return "\n".join(out)


def drift_to_json(report: DriftReport) -> dict:
    def d(delta: IdentityDelta) -> dict:
        return {
            "id": delta.id, "name": delta.name, "status": delta.status,
            "tier_before": delta.tier_before, "tier_after": delta.tier_after,
            "tier_direction": delta.tier_direction,
            "reach_grew": delta.reach_grew, "risk_increased": delta.risk_increased,
            "tools_added": delta.tools_added, "tools_removed": delta.tools_removed,
            "scopes_added": delta.scopes_added, "scopes_removed": delta.scopes_removed,
            "posture_changes": delta.posture_changes,
            "findings_new": delta.findings_new, "findings_resolved": delta.findings_resolved,
        }
    return {
        "summary": {
            "changed": len(report.changed), "added": len(report.added),
            "removed": len(report.removed), "unchanged": report.unchanged,
            "escalations": len(report.escalations),
            "reach_growth_without_tier_change": len(report.reach_growth_only),
        },
        "changed": [d(x) for x in report.changed],
        "added": [d(x) for x in report.added],
        "removed": [d(x) for x in report.removed],
    }
