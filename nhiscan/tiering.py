"""Deterministic risk-tiering rules engine for non-human identities.

Design (mirrors the pattern that works well for AI-system governance): a fixed, ordered
list of rules. Each rule inspects an NHI and, if it matches, imposes a *floor* tier — a
minimum level of scrutiny — with a written rationale. The NHI's final tier is the most
severe floor any rule imposed (numerically the smallest). Every matching rule is recorded,
so the assessment is fully explainable and — because rules are pure functions of the
inventory — reproducible. No LLM is involved.

To change the risk policy, edit RULES. Do not scatter tiering logic elsewhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from .models import NHI, NHIType, RiskTier


@dataclass(frozen=True)
class Rule:
    id: str
    floor: RiskTier
    rationale: str
    predicate: Callable[[NHI], bool]


@dataclass(frozen=True)
class TierReason:
    rule_id: str
    floor: RiskTier
    rationale: str


@dataclass
class TierResult:
    nhi_id: str
    tier: RiskTier
    reasons: list[TierReason]

    @property
    def top_rationale(self) -> str:
        return self.reasons[0].rationale if self.reasons else ""


# Ordered most-severe first for readability; evaluation order does not affect the result.
RULES: list[Rule] = [
    Rule(
        "ADMIN_STATIC_SECRET",
        RiskTier.TIER_1,
        "Admin-level identity authenticating with a long-lived static secret — a stealable crown-jewel credential.",
        lambda n: n.privilege.is_elevated and n.privilege.value == "admin" and n.has_static_secret,
    ),
    Rule(
        "PRIVILEGED_ORPHAN",
        RiskTier.TIER_1,
        "Privileged identity has no accountable owner — nobody governs, rotates, or offboards it.",
        lambda n: n.privilege.is_elevated and n.is_orphaned,
    ),
    Rule(
        "AUTONOMOUS_PRIVILEGED_AGENT",
        RiskTier.TIER_1,
        "Autonomous AI agent holds elevated privilege and acts without per-action human approval.",
        lambda n: n.type is NHIType.AI_AGENT and n.autonomous and n.privilege.is_elevated,
    ),
    Rule(
        "INTERNET_EXPOSED_PRIVILEGED",
        RiskTier.TIER_1,
        "Privileged identity is reachable from the public internet.",
        lambda n: n.exposure.value == "internet" and n.privilege.is_elevated,
    ),
    Rule(
        "PROD_LONG_LIVED_SECRET",
        RiskTier.TIER_2,
        "Production identity relies on a long-lived / never-rotated static secret.",
        lambda n: n.environment.value == "prod" and n.is_long_lived,
    ),
    Rule(
        "OVERPRIVILEGED",
        RiskTier.TIER_2,
        "Identity is admin or carries wildcard/full-access scopes (violates least privilege).",
        lambda n: n.is_overprivileged,
    ),
    Rule(
        "ORPHANED",
        RiskTier.TIER_2,
        "Identity has no accountable owner.",
        lambda n: n.is_orphaned,
    ),
    Rule(
        "STALE_PRIVILEGED",
        RiskTier.TIER_2,
        "Privileged identity is stale (unused) — a standing offboarding gap.",
        lambda n: n.is_stale and n.privilege.is_elevated,
    ),
    Rule(
        "AUTONOMOUS_AGENT",
        RiskTier.TIER_2,
        "Autonomous AI agent acts without per-action human approval.",
        lambda n: n.type is NHIType.AI_AGENT and n.autonomous,
    ),
    Rule(
        "HUMAN_USE_OF_NHI",
        RiskTier.TIER_2,
        "A human authenticates interactively with this shared non-human identity (no individual attribution).",
        lambda n: n.human_used,
    ),
    Rule(
        "PROD_NHI",
        RiskTier.TIER_3,
        "Identity operates in production.",
        lambda n: n.environment.value == "prod",
    ),
    Rule(
        "LONG_LIVED_SECRET",
        RiskTier.TIER_3,
        "Identity relies on a long-lived / never-rotated static secret.",
        lambda n: n.is_long_lived,
    ),
    Rule(
        "STALE",
        RiskTier.TIER_3,
        "Identity is stale (unused beyond the staleness window).",
        lambda n: n.is_stale,
    ),
    Rule(
        "THIRD_PARTY",
        RiskTier.TIER_3,
        "Identity is issued to or operated by an external third party.",
        lambda n: n.third_party,
    ),
]

# Every inventoried NHI gets at least Tier 4 so it lands in the inventory with baseline governance.
BASELINE = TierReason(
    rule_id="BASELINE",
    floor=RiskTier.TIER_4,
    rationale="Baseline: all inventoried non-human identities receive minimum governance.",
)


def assess(nhi: NHI) -> TierResult:
    reasons: list[TierReason] = [BASELINE]
    for rule in RULES:
        if rule.predicate(nhi):
            reasons.append(TierReason(rule.id, rule.floor, rule.rationale))
    tier = RiskTier(min(int(r.floor) for r in reasons))
    # Sort most-severe first for stable, readable output.
    reasons.sort(key=lambda r: (int(r.floor), r.rule_id))
    return TierResult(nhi_id=nhi.id, tier=tier, reasons=reasons)
