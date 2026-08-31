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
import os
import subprocess
import sys
import tempfile
import time

from .common import run_cli

GRAPH = "https://graph.microsoft.com"

# Microsoft Graph caps a JSON batch at 20 sub-requests.
BATCH_MAX = 20


def az_rest(url: str) -> dict:
    """GET a Graph URL through the Azure CLI session. Returns {} on a handled failure."""
    try:
        raw = run_cli(["az", "rest", "--method", "GET", "--url", url, "-o", "json"])
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


def chunked(items: list, size: int = BATCH_MAX):
    """Yield successive ``size``-length chunks of ``items``."""
    for i in range(0, len(items), size):
        yield items[i:i + size]


def az_batch(requests: list[dict], version: str = "v1.0") -> dict[str, dict]:
    """POST one Graph ``$batch`` (<= ``BATCH_MAX`` sub-requests) and return ``{id: response}``.

    Each request is ``{"id", "method", "url"}`` with a tenant-relative ``url``. Sub-requests
    throttled with 429/503 are retried; a whole-batch transient failure is retried too. Any id
    still unanswered after the retry budget is simply absent from the result (caller degrades to
    empty rather than crashing). Batching turns the per-principal expansion from thousands of
    sequential ``az rest`` process spawns into a handful of POSTs.
    """
    url = f"{GRAPH}/{version}/$batch"
    pending = list(requests)
    out: dict[str, dict] = {}
    for _ in range(6):
        if not pending:
            break
        fd, path = tempfile.mkstemp(suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"requests": pending}, f)
            try:
                raw = run_cli(["az", "rest", "--method", "POST", "--url", url,
                               "--headers", "Content-Type=application/json",
                               "--body", f"@{path}", "-o", "json"])
            except subprocess.CalledProcessError:
                time.sleep(2)  # transient: retry the whole batch
                continue
        finally:
            os.unlink(path)

        resp = json.loads(raw) if raw.strip() else {}
        retry: list[dict] = []
        by_id = {q["id"]: q for q in pending}
        for r in resp.get("responses") or []:
            if r.get("status") in (429, 503) and r.get("id") in by_id:
                retry.append(by_id[r["id"]])
            else:
                out[r["id"]] = r
        pending = retry
        if pending:
            time.sleep(2)
    return out


def tenant_id() -> str | None:
    try:
        acct = json.loads(run_cli(["az", "account", "show", "-o", "json"]))
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
            a["sponsors"] = paged(f"{sp}/sponsors")
            a["owners"] = paged(f"{sp}/owners")
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
