"""GCP service accounts (+ keys) -> nhi-scan records.

Gather (read-only; roles/iam.securityReviewer or viewer is sufficient):

    # list service accounts, then attach each account's keys, into accounts.json
    # see tools/collectors/README.md for a ready-to-paste gather script
    python -m tools.collectors.gcp accounts.json > gcp-nhi.json

Expected input (list of service accounts, each with its keys):
    [{"email": "svc@proj.iam.gserviceaccount.com", "displayName": "svc",
      "disabled": false, "labels": {"owner": "team@x", "env": "prod"},
      "keys": [{"keyType": "USER_MANAGED", "validAfterTime": "2025-01-01T00:00:00Z"}]}]

A user-managed key is a long-lived static credential; accounts without one authenticate via the
managed platform identity.
"""

from __future__ import annotations

import sys
from datetime import datetime

from .common import days_since, emit, newest, read_input, record


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
        out.append(record(
            id=sa.get("email") or sa.get("name"),
            name=sa.get("displayName") or sa.get("email") or sa.get("name"),
            type="service_account",
            owner=labels.get("owner") or labels.get("team"),
            environment=(labels.get("env") or labels.get("environment") or "prod"),
            credential=credential,
            secret_storage=secret_storage,
            last_rotated_days=last_rotated,
        ))
    return out


def main(argv: list[str]) -> int:
    emit(transform(read_input(argv)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
