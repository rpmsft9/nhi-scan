"""OWASP Non-Human Identities (NHI) Top 10 — 2025 catalog.

Content is a versioned data layer, not model memory: each entry carries its canonical id,
title, and the project source URL. Update this file when the list is revised; the checks
engine references entries by id.

Source: OWASP Non-Human Identities Top 10 (2025) — https://owasp.org/www-project-non-human-identities-top-10/
"""

from __future__ import annotations

from dataclasses import dataclass

SOURCE_URL = "https://owasp.org/www-project-non-human-identities-top-10/"


@dataclass(frozen=True)
class OwaspNHI:
    id: str
    title: str
    summary: str


CATALOG: dict[str, OwaspNHI] = {
    "NHI1:2025": OwaspNHI(
        "NHI1:2025", "Improper Offboarding",
        "NHIs left active after the workload, integration, or owner they served is gone.",
    ),
    "NHI2:2025": OwaspNHI(
        "NHI2:2025", "Secret Leakage",
        "Secrets stored or transmitted where they can be exposed (code, config, logs, env).",
    ),
    "NHI3:2025": OwaspNHI(
        "NHI3:2025", "Vulnerable Third-Party NHI",
        "Identities granted to external apps/vendors that widen the trust boundary.",
    ),
    "NHI4:2025": OwaspNHI(
        "NHI4:2025", "Insecure Authentication",
        "Weak or deprecated auth methods (static keys/basic) instead of federated/managed identity.",
    ),
    "NHI5:2025": OwaspNHI(
        "NHI5:2025", "Overprivileged NHI",
        "Identities with more privilege or broader scope than the task requires.",
    ),
    "NHI6:2025": OwaspNHI(
        "NHI6:2025", "Insecure Cloud Deployment Configurations",
        "Deployment/config weaknesses that expose or over-trust an NHI.",
    ),
    "NHI7:2025": OwaspNHI(
        "NHI7:2025", "Long-Lived Secrets",
        "Credentials that live far beyond a safe rotation window (or are never rotated).",
    ),
    "NHI8:2025": OwaspNHI(
        "NHI8:2025", "Environment Isolation",
        "The same identity/credential reused across prod and non-prod, collapsing isolation.",
    ),
    "NHI9:2025": OwaspNHI(
        "NHI9:2025", "NHI Reuse",
        "One identity shared across multiple workloads, destroying least privilege and attribution.",
    ),
    "NHI10:2025": OwaspNHI(
        "NHI10:2025", "Human Use of NHI",
        "A person authenticating interactively with a non-human identity.",
    ),
}


def get(code: str) -> OwaspNHI:
    return CATALOG[code]
