"""Render a ScanResult as Markdown or a JSON object."""

from __future__ import annotations

from . import owasp
from .models import RiskTier
from .scan import ScanResult

_TIER_BADGE = {1: "🔴 Critical", 2: "🟠 High", 3: "🟡 Moderate", 4: "🟢 Baseline"}


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
        owner = n.owner or "_orphaned_"
        out.append(f"### {_TIER_BADGE[int(a.tier.tier)]} — {n.name} `({n.type.value})`")
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
