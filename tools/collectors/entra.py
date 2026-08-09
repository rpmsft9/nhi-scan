"""Entra ID (Azure AD) service principals -> nhi-scan records.

Gather (read-only; Directory.Read.All is sufficient):

    az ad sp list --all -o json | python -m tools.collectors.entra --tenant <YOUR_TENANT_ID> > entra-nhi.json

Maps each service principal to an NHI, inferring credential type from its password/key
credentials, rotation age from the newest credential, and third-party status from the app's
owning tenant. Role assignments (privilege) require extra Graph calls and are left at the default.
"""

from __future__ import annotations

import sys
from datetime import datetime

from .common import days_since, emit, newest, record


def transform(service_principals: list[dict], tenant_id: str | None = None,
              now: datetime | None = None) -> list[dict]:
    out: list[dict] = []
    for sp in service_principals:
        passwords = sp.get("passwordCredentials") or []
        certs = sp.get("keyCredentials") or []
        if certs:
            credential = "certificate"
        elif passwords:
            credential = "static_secret"
        else:
            credential = "federated"  # no stored secret (e.g. workload identity federation)

        starts = [c.get("startDateTime") for c in (passwords + certs)]
        last_rotated = days_since(newest(starts), now=now)

        owner_org = sp.get("appOwnerOrganizationId")
        third_party = bool(tenant_id and owner_org and owner_org != tenant_id)

        out.append(record(
            id=sp.get("id") or sp.get("appId"),
            name=sp.get("displayName") or sp.get("appId"),
            type="service_principal",
            environment="prod",
            credential=credential,
            secret_storage=("none" if credential == "federated" else "vault"),
            last_rotated_days=last_rotated,
            third_party=(True if third_party else None),
        ))
    return out


def main(argv: list[str]) -> int:
    tenant = None
    args = [a for a in argv[1:]]
    if "--tenant" in args:
        i = args.index("--tenant")
        tenant = args[i + 1] if i + 1 < len(args) else None
        del args[i:i + 2]
    import json
    data = json.load(open(args[0], encoding="utf-8")) if args else json.load(sys.stdin)
    emit(transform(data, tenant_id=tenant))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
