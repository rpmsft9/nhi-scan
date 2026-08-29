"""Entra ID (Azure AD) service principals -> nhi-scan records.

Two ways to gather (both read-only):

    # names, credentials, ownership only — one call, no permission data
    az ad sp list --all -o json | python -m tools.collectors.entra --tenant <YOUR_TENANT_ID> > entra-nhi.json

    # names, credentials, ownership AND granted permissions (app roles + delegated scopes)
    python -m tools.collectors.gather_entra > entra-sp-bundle.json
    python -m tools.collectors.entra entra-sp-bundle.json > entra-nhi.json

Maps each service principal to an NHI, inferring credential type from its password/key
credentials, rotation age from the newest credential, and third-party status from the app's
owning tenant.

**Permissions.** When a service principal carries ``appRoleAssignments`` /
``oauth2PermissionGrants`` (the ``gather_entra`` path), its granted application roles and
delegated scopes populate ``scopes`` and drive ``privilege`` — so overprivilege (NHI5) and
wildcard detection can actually fire. Plain ``az ad sp list`` output carries no grant data, and
in that case ``privilege``/``scopes`` are omitted rather than guessed: nhi-scan's conservative
defaults apply, and overprivilege findings will not fire for those records.

**Agent identities are skipped.** Entra Agent ID identities inherit from servicePrincipal
(``servicePrincipalType == "ServiceIdentity"``) and would flatten into generic
``service_principal`` records here, losing sponsor, autonomy, and blueprint. Collect them with
:mod:`tools.collectors.entra_agents` instead; skipping them here keeps a merged inventory free
of double-counted agents.
"""

from __future__ import annotations

import sys
from datetime import datetime

from .common import days_since, emit, newest, record
from .entra_agents import collect_scopes, display_handle, infer_privilege


def transform(data, tenant_id: str | None = None,
              now: datetime | None = None) -> list[dict]:
    """Accepts a bare ``az ad sp list`` array or a ``gather_entra`` bundle
    (``{"tenantId": ..., "servicePrincipals": [...]}``)."""
    if isinstance(data, dict):
        service_principals = data.get("servicePrincipals") or data.get("value") or []
        tenant_id = tenant_id or data.get("tenantId")
    else:
        service_principals = data or []

    out: list[dict] = []
    for sp in service_principals:
        if sp.get("servicePrincipalType") == "ServiceIdentity":
            continue  # agent identity — belongs to the entra_agents collector

        passwords = sp.get("passwordCredentials") or []
        certs = sp.get("keyCredentials") or []
        if sp.get("servicePrincipalType") == "ManagedIdentity":
            # A managed identity's keyCredentials are Azure platform-issued certs the platform
            # rotates itself — not a stored secret anyone manages. Classifying them as
            # "certificate" produces false NHI7 (long-lived secret) and NHI4 findings.
            credential = "managed"
        elif certs:
            credential = "certificate"
        elif passwords:
            credential = "static_secret"
        else:
            credential = "federated"  # no stored secret (e.g. workload identity federation)

        starts = [c.get("startDateTime") for c in (passwords + certs)]
        last_rotated = days_since(newest(starts), now=now)

        owner_org = sp.get("appOwnerOrganizationId")
        third_party = bool(tenant_id and owner_org and owner_org != tenant_id)

        # Only emit privilege/scopes when grant data was actually collected. An empty grants
        # list is real information (the SP holds nothing); an absent key means "not gathered",
        # and guessing there would let overprivilege findings fire on assumption.
        has_grant_data = ("appRoleAssignments" in sp) or ("oauth2PermissionGrants" in sp)
        scopes = collect_scopes(sp) if has_grant_data else []

        owners = sp.get("owners") or []
        owner = display_handle(owners[0]) if owners else None

        out.append(record(
            id=sp.get("id") or sp.get("appId"),
            name=sp.get("displayName") or sp.get("appId"),
            type="service_principal",
            environment="prod",
            owner=owner,
            credential=credential,
            secret_storage=("none" if credential in ("federated", "managed") else "vault"),
            last_rotated_days=last_rotated,
            third_party=(True if third_party else None),
            privilege=(infer_privilege(scopes) if has_grant_data else None),
            scopes=(scopes or None),
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
