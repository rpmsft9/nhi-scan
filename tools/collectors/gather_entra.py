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

Cost: expansion reads three relationships per service principal (owners, delegated grants, app
role assignments) plus one lookup per referenced resource, but every read goes through Graph
``$batch`` (20 sub-requests per POST) — so a tenant with N SPs costs about ``ceil(3N/20)``
requests, not ``3N`` sequential ``az rest`` calls (hundreds of SPs finish in a couple of minutes
rather than tens). Pass ``--no-expand`` for a fast names-and-credentials pass, or
``--filter <substring>`` to expand only display names containing the substring.

Agent identities (``servicePrincipalType == "ServiceIdentity"``) are excluded here; gather
those with :mod:`tools.collectors.gather_entra_agents`.
"""

from __future__ import annotations

import json
import sys

from .gather_entra_agents import GRAPH, az_batch, chunked, paged, tenant_id

_RELATIONSHIPS = ("owners", "oauth2PermissionGrants", "appRoleAssignments")


def _expand_grants(todo: list[dict]) -> None:
    """Populate owners / oauth2PermissionGrants / appRoleAssignments on each SP in ``todo``.

    Every per-principal read goes through Graph ``$batch`` (20 sub-requests per POST), so a
    tenant with N service principals costs about ``ceil(3N / 20)`` requests instead of ``3N``
    sequential ``az rest`` spawns. Resolved app-role *values* are attached to each assignment.
    """
    by_id = {sp["id"]: sp for sp in todo if sp.get("id")}

    reqs, meta = [], {}
    for sid in by_id:
        for rel in _RELATIONSHIPS:
            rid = str(len(reqs) + 1)
            reqs.append({"id": rid, "method": "GET",
                         "url": f"/servicePrincipals/{sid}/{rel}"})
            meta[rid] = (sid, rel)

    done = 0
    for chunk in chunked(reqs):
        for req_id, r in az_batch(chunk).items():
            sid, rel = meta[req_id]
            body = r.get("body") or {}
            values = body.get("value") or []
            nxt = body.get("@odata.nextLink")  # sub-requests aren't paged inside a batch
            if nxt:
                values = values + paged(nxt)
            by_id[sid][rel] = values
        done += len(chunk)
        sys.stderr.write(f"\r# batched {done}/{len(reqs)} grant requests")
    sys.stderr.write("\n")

    # Resolve appRoleId -> readable value for every referenced resource, also batched.
    resource_ids = sorted({a.get("resourceId")
                           for sp in todo for a in (sp.get("appRoleAssignments") or [])
                           if a.get("resourceId")})
    role_reqs, role_meta = [], {}
    for res in resource_ids:
        rid = str(len(role_reqs) + 1)
        role_reqs.append({"id": rid, "method": "GET",
                          "url": f"/servicePrincipals/{res}?$select=appRoles"})
        role_meta[rid] = res

    role_names: dict[str, str] = {}
    for chunk in chunked(role_reqs):
        for req_id, r in az_batch(chunk).items():
            res = role_meta[req_id]
            for role in (r.get("body") or {}).get("appRoles") or []:
                role_names[f"{res}:{role.get('id')}"] = role.get("value") or ""

    for sp in todo:
        for asg in sp.get("appRoleAssignments") or []:
            rid, res = asg.get("appRoleId"), asg.get("resourceId")
            asg["appRoleValue"] = role_names.get(f"{res}:{rid}") or None


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
        todo = [sp for sp in sps
                if not name_filter or name_filter in (sp.get("displayName") or "").lower()]
        sys.stderr.write(f"# expanding grants for {len(todo)} of {len(sps)} via Graph $batch\n")
        _expand_grants(todo)

    json.dump({"tenantId": tenant_id(), "servicePrincipals": sps}, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
