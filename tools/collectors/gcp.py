"""GCP service accounts (+ keys) -> nhi-scan records.

Gather (read-only; roles/iam.securityReviewer or viewer is sufficient):

    # list service accounts, then attach each account's keys, into accounts.json
    # see tools/collectors/README.md for a ready-to-paste gather script
    python -m tools.collectors.gcp accounts.json > gcp-nhi.json

Expected input (list of service accounts, each with its keys and — when gathered with
``gather_gcp`` — its project IAM role bindings):
    [{"email": "svc@proj.iam.gserviceaccount.com", "displayName": "svc",
      "disabled": false, "labels": {"owner": "team@x", "env": "prod"},
      "roles": ["roles/editor", "roles/storage.objectViewer"],
      "keys": [{"keyType": "USER_MANAGED", "validAfterTime": "2025-01-01T00:00:00Z"}]}]

A user-managed key is a long-lived static credential; accounts without one authenticate via the
managed platform identity.

**Permissions.** When ``roles`` is present, the bindings populate ``scopes`` and drive
``privilege``: ``roles/owner`` and ``roles/editor`` are project-wide write and map to
``admin``; ``*Admin``/``*admin`` roles and ``roles/iam.*`` map to ``privileged``. Accounts
gathered without bindings (the older path) omit ``privilege``/``scopes`` rather than guess —
nhi-scan's conservative defaults apply and overprivilege findings will not fire for them. Use
``python -m tools.collectors.gather_gcp`` to include bindings.
"""

from __future__ import annotations

import sys
from datetime import datetime

from .common import days_since, emit, newest, read_input, record

# Project-wide write access: the GCP basic roles that make an SA effectively an admin.
_ADMIN_ROLES = {"roles/owner", "roles/editor"}


def _privilege(roles: list[str]) -> str:
    low = [r.lower() for r in roles]
    if any(r in _ADMIN_ROLES for r in low):
        return "admin"
    if any("admin" in r or r.startswith("roles/iam.") for r in low):
        return "privileged"
    return "scoped" if roles else "read_only"


def transform(accounts: list[dict], now: datetime | None = None) -> list[dict]:
    out: list[dict] = []
    for sa in accounts:
        keys = sa.get("keys") or []
        user_keys = [k for k in keys if (k.get("keyType") or "").upper() == "USER_MANAGED"]
        if user_keys:
            credential, secret_storage = "static_secret", "vault"
            last_rotated = days_since(newest(k.get("validAfterTime") for k in user_keys), now=now)
        else:
            credential, secret_storage, last_rotated = "managed", "none", None

        labels = sa.get("labels") or {}
        has_bindings = "roles" in sa
        roles = list(sa.get("roles") or [])
        out.append(record(
            id=sa.get("email") or sa.get("name"),
            name=sa.get("displayName") or sa.get("email") or sa.get("name"),
            type="service_account",
            owner=labels.get("owner") or labels.get("team"),
            environment=(labels.get("env") or labels.get("environment") or "prod"),
            credential=credential,
            secret_storage=secret_storage,
            last_rotated_days=last_rotated,
            privilege=(_privilege(roles) if has_bindings else None),
            scopes=(roles or None),
        ))
    return out


def main(argv: list[str]) -> int:
    emit(transform(read_input(argv)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
