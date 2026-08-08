"""Orchestration: turn a Fleet into per-identity assessments and a fleet summary.

This is the single entry point the CLI, report, and tests call, so the shape of a scan is
defined in one place.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from . import tiering
from .checks import Finding, run_checks
from .models import NHI, Fleet, RiskTier
from .tiering import TierResult


@dataclass
class Assessment:
    nhi: NHI
    tier: TierResult
    findings: list[Finding] = field(default_factory=list)

    @property
    def risk_score(self) -> int:
        """Blended score: tier weight (crown jewels dominate) plus finding severity."""
        tier_weight = {1: 40, 2: 20, 3: 8, 4: 2}[int(self.tier.tier)]
        return tier_weight + sum(f.severity.weight for f in self.findings)


@dataclass
class ScanResult:
    assessments: list[Assessment]

    @property
    def total(self) -> int:
        return len(self.assessments)

    @property
    def tier_counts(self) -> dict[RiskTier, int]:
        c: Counter[RiskTier] = Counter(a.tier.tier for a in self.assessments)
        return {t: c.get(t, 0) for t in RiskTier}

    @property
    def type_counts(self) -> dict[str, int]:
        return dict(Counter(a.nhi.type.value for a in self.assessments))

    @property
    def owasp_counts(self) -> dict[str, int]:
        c: Counter[str] = Counter()
        for a in self.assessments:
            for f in a.findings:
                c[f.owasp_id] += 1
        return dict(sorted(c.items()))

    @property
    def finding_count(self) -> int:
        return sum(len(a.findings) for a in self.assessments)

    @property
    def orphaned(self) -> int:
        return sum(1 for a in self.assessments if a.nhi.is_orphaned)

    @property
    def long_lived(self) -> int:
        return sum(1 for a in self.assessments if a.nhi.is_long_lived)

    @property
    def by_risk(self) -> list[Assessment]:
        return sorted(self.assessments, key=lambda a: (-a.risk_score, a.nhi.id))


def scan(fleet: Fleet) -> ScanResult:
    assessments = [
        Assessment(nhi=n, tier=tiering.assess(n), findings=run_checks(n))
        for n in fleet.identities
    ]
    return ScanResult(assessments=assessments)
