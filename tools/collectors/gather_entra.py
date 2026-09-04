"""Fetch Entra service principals WITH their granted permissions for :mod:`entra`.

Auth stays with the Azure CLI — this script never sees a credential, it only shells out to
``az rest`` using the session you already established:

    az login --tenant <YOUR_TENANT_ID>
    python -m tools.collectors.gather_entra > entra-sp-bundle.json
    python -m tools.collectors.entra entra-sp-bundle.json > entra-nhi.json

Read-only throughout: every call is a GET. ``Application.Read.All`` covers the service
principal and grant reads (``Directory.Read.All`` also works); Global Reader is a sufficient
directory role.

Per principal, expansion adds ``owners`` (so the transform can tell owned from orphaned
instead of flagging everything ownerless), ``appRoleAssignments`` (with each role id resolved
to its readable value, e.g. ``Files.Read.All``), and ``oauth2PermissionGrants`` — the
permission surfaces that drive ``privilege``/``scopes`` in the transform.

Cost: expansion issues three extra GETs per service principal (plus one per newly-seen resource
to resolve role names). A large tenant with thousands of SPs takes a while — pass
``--no-expand`` for a fast names-and-credentials pass, or ``--filter <substring>`` to expand
only display names containing the substring.

Agent identities (``servicePrincipalType == "ServiceIdentity"``) are excluded here; gather
those with :mod:`tools.collectors.gather_entra_agents`.
"""

from __future__ import annotations

import json
import sys

from .gather_entra_agents import GRAPH, az_rest, paged, tenant_id


def main(argv: list[str]) -> int:
    expand = "--no-expand" not in argv
    name_filter = None
    if "--filter" in argv:
        i = argv.index("--filter")
        name_filter = argv[i + 1].lower() if i + 1 < len(argv) else None
    base = f"{GRAPH}/v1.0"

    sps = paged(
        f"{base}/servicePrincipals?$top=999&$select=id,appId,displayName,"
        "servicePrincipalType,appOwnerOrganizationId,passwordCredentials,keyCredentials,"
        "accountEnabled,tags"
    )
    sps = [sp for sp in sps if sp.get("servicePrincipalType") != "ServiceIdentity"]
    sys.stderr.write(f"# {len(sps)} service principals (agent identities excluded)\n")

    if expand:
        role_names: dict[str, str] = {}
        todo = [sp for sp in sps
                if not name_filter or name_filter in (sp.get("displayName") or "").lower()]
        sys.stderr.write(f"# expanding grants for {len(todo)} of {len(sps)}\n")
        for i, sp in enumerate(todo, 1):
            sid = sp.get("id")
            if not sid:
                continue
            sys.stderr.write(f"\r# expanding {i}/{len(todo)}")
            url = f"{base}/servicePrincipals/{sid}"
            sp["owners"] = paged(f"{url}/owners?$select=id,displayName,userPrincipalName,mail,accountEnabled")
            sp["oauth2PermissionGrants"] = paged(f"{url}/oauth2PermissionGrants")

            assignments = paged(f"{url}/appRoleAssignments")
            for asg in assignments:
                rid, res = asg.get("appRoleId"), asg.get("resourceId")
                if not rid or not res:
                    continue
                if res not in role_names:
                    resource = az_rest(f"{base}/servicePrincipals/{res}?$select=appRoles")
                    for role in resource.get("appRoles") or []:
                        role_names[f"{res}:{role.get('id')}"] = role.get("value") or ""
                    role_names[res] = "_loaded"
                asg["appRoleValue"] = role_names.get(f"{res}:{rid}") or None
            sp["appRoleAssignments"] = assignments
        sys.stderr.write("\n")

    json.dump({"tenantId": tenant_id(), "servicePrincipals": sps}, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
