"""AWS IAM users & access keys -> nhi-scan records (one record per access key).

Because the signals span several IAM calls, assemble a small bundle first, then transform it.
A read-only gather (requires iam:List*/iam:Get* — e.g. the AWS-managed IAMReadOnlyAccess policy):

    # for each user: access keys (+ last-used) and attached policy names, collected into bundle.json
    # see tools/collectors/README.md for a ready-to-paste gather script
    python -m tools.collectors.aws bundle.json > aws-nhi.json

Expected bundle shape (list of users):
    [{"UserName": "...",
      "Tags": [{"Key": "owner", "Value": "team@x"}, {"Key": "env", "Value": "prod"}],
      "AttachedPolicies": ["AdministratorAccess"],
      "InlinePolicyNames": ["etl-extra"],
      "GroupPolicies": ["PowerUserAccess"],
      "HasWildcardAction": true,
      "AccessKeys": [{"AccessKeyId": "AKIA...", "Status": "Active",
                      "CreateDate": "2024-01-01T00:00:00+00:00",
                      "LastUsedDate": "2026-08-01T00:00:00+00:00"}]}]

**Effective permissions, not just direct ones.** Privilege is inferred from the union of
attached user policies, inline user policies, and policies inherited through group membership
(``GroupPolicies``) — the quiet path by which most over-permissioned IAM users got that way.
``HasWildcardAction`` (any reachable policy document granting ``"Action": "*"``) surfaces as a
wildcard scope so NHI5 detection fires. Bundles built by the older gather script (attached
policies only) still transform, with correspondingly narrower inference — use
``python -m tools.collectors.gather_aws`` to build the full bundle.
"""

from __future__ import annotations

import sys
from datetime import datetime

from .common import days_since, emit, read_input, record

_ADMIN = {"administratoraccess"}
_PRIVILEGED_HINTS = ("fullaccess", "poweruser", "iamfull")


def _privilege(policies: list[str]) -> str:
    names = [p.lower() for p in policies]
    if any(n in _ADMIN for n in names):
        return "admin"
    if any(h in n for n in names for h in _PRIVILEGED_HINTS):
        return "privileged"
    return "scoped"


def _tag(tags: list[dict], *keys: str) -> str | None:
    lookup = {t.get("Key", "").lower(): t.get("Value") for t in (tags or [])}
    for k in keys:
        if lookup.get(k):
            return lookup[k]
    return None


def transform(users: list[dict], now: datetime | None = None) -> list[dict]:
    out: list[dict] = []
    for u in users:
        tags = u.get("Tags") or []
        owner = _tag(tags, "owner", "team", "contact")
        env = (_tag(tags, "env", "environment") or "prod").lower()
        policy_names = (
            (u.get("AttachedPolicies") or [])
            + (u.get("InlinePolicyNames") or [])
            + (u.get("GroupPolicies") or [])
        )
        priv = _privilege(policy_names)
        wildcard = bool(u.get("HasWildcardAction"))
        for key in (u.get("AccessKeys") or []):
            akid = key.get("AccessKeyId", "")
            out.append(record(
                id=akid or f"{u.get('UserName')}-key",
                name=f"{u.get('UserName')} ({akid[-4:] or 'key'})",
                type="api_key",
                owner=owner,
                environment=env,
                privilege=priv,
                credential="api_key",
                last_rotated_days=days_since(key.get("CreateDate"), now=now),
                last_used_days=days_since(key.get("LastUsedDate"), now=now),
                scopes=(["*"] if wildcard else None),
            ))
    return out


def main(argv: list[str]) -> int:
    emit(transform(read_input(argv)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
