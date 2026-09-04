"""Fetch Entra Agent ID agent identities into a bundle for :mod:`entra_agents`.

Auth stays with the Azure CLI — this script never sees a credential, it only shells out to
``az rest`` using the session you already established:

    az login --tenant <YOUR_TENANT_ID>
    python -m tools.collectors.gather_entra_agents > entra-agents-bundle.json

Read-only throughout: every call is a GET. Least-privileged permission is
``AgentIdentity.Read.All`` plus ``Application.Read.All`` to resolve app-role values
(``Directory.Read.All`` covers both); Global Reader is a sufficient directory role.

Options:
    --beta        query the beta endpoint instead of v1.0
    --no-expand   skip the per-agent sponsor/owner/role calls (one request total, less detail)
"""

from __future__ import annotations

import json
import subprocess
import sys

GRAPH = "https://graph.microsoft.com"


def az_rest(url: str) -> dict:
    """GET a Graph URL through the Azure CLI session. Returns {} on a handled failure."""
    try:
        raw = subprocess.check_output(
            ["az", "rest", "--method", "GET", "--url", url, "-o", "json"],
            stderr=subprocess.PIPE, text=True,
        )
    except FileNotFoundError:
        sys.exit("az CLI not found. Install the Azure CLI, then run: az login --tenant <TENANT>")
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or "").strip().splitlines()
        sys.stderr.write(f"# warn: GET {url} failed: {detail[-1] if detail else e}\n")
        return {}
    return json.loads(raw) if raw.strip() else {}


def paged(url: str) -> list[dict]:
    """Follow @odata.nextLink until exhausted."""
    items: list[dict] = []
    while url:
        page = az_rest(url)
        items.extend(page.get("value") or [])
        url = page.get("@odata.nextLink") or ""
    return items


def tenant_id() -> str | None:
    try:
        acct = json.loads(subprocess.check_output(
            ["az", "account", "show", "-o", "json"], text=True, stderr=subprocess.DEVNULL))
        return acct.get("tenantId")
    except Exception:
        return None


def main(argv: list[str]) -> int:
    version = "beta" if "--beta" in argv else "v1.0"
    expand = "--no-expand" not in argv
    base = f"{GRAPH}/{version}"

    agents = paged(f"{base}/servicePrincipals/microsoft.graph.agentIdentity")
    sys.stderr.write(f"# {len(agents)} agent identities found ({version})\n")

    if expand:
        # Resolve app-role *values* once: assignments carry only appRoleId + resourceId.
        role_names: dict[str, str] = {}
        for i, a in enumerate(agents, 1):
            aid = a.get("id")
            if not aid:
                continue
            sys.stderr.write(f"\r# expanding {i}/{len(agents)}")
            sp = f"{base}/servicePrincipals/{aid}"
            a["sponsors"] = paged(f"{sp}/sponsors?$select=id,displayName,userPrincipalName,mail,accountEnabled")
            a["owners"] = paged(f"{sp}/owners?$select=id,displayName,userPrincipalName,mail,accountEnabled")
            a["oauth2PermissionGrants"] = paged(f"{sp}/oauth2PermissionGrants")

            assignments = paged(f"{sp}/appRoleAssignments")
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
            a["appRoleAssignments"] = assignments
        sys.stderr.write("\n")

    json.dump({"tenantId": tenant_id(), "version": version, "agents": agents},
              sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
