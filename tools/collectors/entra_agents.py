"""Microsoft Entra Agent ID agent identities -> nhi-scan records.

The general-purpose :mod:`entra` collector reads ``/servicePrincipals`` and maps everything to
``type: service_principal``. Agent identities inherit from servicePrincipal, so they *appear*
there — but flattened into the same shape as a payments connector, which loses exactly the
attributes that make an agent worth governing: its sponsor, its blueprint, whether it holds
application permissions (and so acts with no human present), and what it can reach.

This collector reads the ``microsoft.graph.agentIdentity`` cast instead and emits
``type: ai_agent`` records with sponsors, autonomy, privilege, and scopes populated.

Gather (read-only). Sign in first with ``az login --tenant <TENANT>``, then:

    python -m tools.collectors.gather_entra_agents > entra-agents-bundle.json
    python -m tools.collectors.entra_agents entra-agents-bundle.json > entra-agents-nhi.json

Least-privileged read: ``AgentIdentity.Read.All`` plus ``Application.Read.All`` to resolve app
role assignments (``Directory.Read.All`` covers both). Directory role: Global Reader is enough.

**Autonomy is inferred, not guessed.** An agent holding *application* permissions
(``appRoleAssignments`` — the ``roles`` claim) acts with no user present, so it is marked
``autonomous``. An agent with only *delegated* grants (``oauth2PermissionGrants`` — the ``scp``
claim) acts within a signed-in user's context and is not. That distinction is the one that
decides which controls apply, so it is worth getting from data rather than assumption.

**Sponsor becomes owner.** Entra Agent ID makes ``sponsors`` a first-class relationship, and the
sponsor is the accountable human. An agent with neither sponsor nor owner emits no ``owner`` —
which is correct: nhi-scan will flag it orphaned under NHI1, and it should.

**Reach (``tools``) is not in Entra.** An agent's tool/connector manifest lives in Agent 365,
Copilot Studio, or its MCP config. Collect that with :mod:`tools.collectors.mcp` and merge on
``id`` — see the collectors README.
"""

from __future__ import annotations

import sys
from datetime import datetime

from .common import days_since, emit, newest, read_input, record

# Graph permissions that make an agent effectively privileged if granted. Microsoft blocks the
# most dangerous ones for agent identities outright, so anything in this list that *is* present
# was deliberately granted and deserves the higher tier.
_PRIVILEGED_HINTS = (
    "readwrite.all", "directory.", "rolemanagement.", "privilegedaccess.",
    "application.", "approleassignment.", "delegatedpermissiongrant.", "fullcontrol",
)
_ADMIN_HINTS = ("directory.readwrite.all", "rolemanagement.readwrite", "fullcontrol.all")


def display_handle(principal: dict) -> str | None:
    """Best human-readable handle for a sponsor/owner directory object."""
    if not isinstance(principal, dict):
        return None
    return (
        principal.get("userPrincipalName")
        or principal.get("mail")
        or principal.get("displayName")
        or principal.get("id")
    )


def owner_liveness(principal: dict | None) -> bool | None:
    """Tri-state liveness of an owner/sponsor directory object, for owner *validity*
    (not just presence). True = account enabled; False = disabled/deprovisioned — the
    real 'improper offboarding' case; None = unknown (field not gathered, or a group
    owner that carries no accountEnabled). Requires the enriched gather to $select it."""
    if not isinstance(principal, dict):
        return None
    val = principal.get("accountEnabled")
    return val if isinstance(val, bool) else None


def collect_scopes(agent: dict) -> list[str]:
    """Application roles + delegated scopes, as a flat, de-duplicated list."""
    out: list[str] = []
    for a in agent.get("appRoleAssignments") or []:
        # Prefer the resolved role value; fall back to the resource + role id.
        value = a.get("appRoleValue") or a.get("value")
        if not value:
            rid = a.get("appRoleId") or "role"
            value = f"{a.get('resourceDisplayName') or 'resource'}:{rid}"
        out.append(value)
    for g in agent.get("oauth2PermissionGrants") or []:
        for s in (g.get("scope") or "").split():
            out.append(s)
    seen: set[str] = set()
    deduped: list[str] = []
    for s in out:
        if s not in seen:
            seen.add(s)
            deduped.append(s)
    return deduped


def infer_privilege(scopes: list[str]) -> str:
    low = [s.lower() for s in scopes]
    if any(any(h in s for h in _ADMIN_HINTS) for s in low):
        return "admin"
    if any(s.endswith("*") or ":*" in s for s in low):
        return "admin"
    if any(any(h in s for h in _PRIVILEGED_HINTS) for s in low):
        return "privileged"
    return "scoped" if scopes else "read_only"


def transform(bundle, tenant_id: str | None = None,
              now: datetime | None = None) -> list[dict]:
    """Map a gathered agent-identity bundle to nhi-scan records.

    Accepts the bundle produced by ``gather_entra_agents`` (``{"tenantId": ..., "agents": [...]}``)
    or a bare list of agentIdentity objects.
    """
    if isinstance(bundle, dict):
        agents = bundle.get("agents") or bundle.get("value") or []
        tenant_id = tenant_id or bundle.get("tenantId")
    else:
        agents = bundle or []

    out: list[dict] = []
    for a in agents:
        passwords = a.get("passwordCredentials") or []
        certs = a.get("keyCredentials") or []
        if certs:
            credential = "certificate"
        elif passwords:
            credential = "static_secret"
        else:
            # No stored credential on the object: federated / managed. This is the good case.
            credential = "federated"

        last_rotated = days_since(
            newest([c.get("startDateTime") for c in (passwords + certs)]), now=now
        )

        sponsors = a.get("sponsors") or []
        owners = a.get("owners") or []
        owner_obj = sponsors[0] if sponsors else (owners[0] if owners else None)
        owner = display_handle(owner_obj)

        scopes = collect_scopes(a)
        app_roles = a.get("appRoleAssignments") or []

        owner_org = a.get("appOwnerOrganizationId")
        third_party = bool(tenant_id and owner_org and owner_org != tenant_id)

        out.append(record(
            id=a.get("id") or a.get("appId"),
            name=a.get("displayName") or a.get("id"),
            type="ai_agent",
            owner=owner,
            owner_active=owner_liveness(owner_obj),
            # Entra carries no environment signal; assume production rather than under-report.
            environment="prod",
            privilege=infer_privilege(scopes),
            credential=credential,
            secret_storage=("none" if credential == "federated" else "vault"),
            last_rotated_days=last_rotated,
            exposure="internal",
            scopes=scopes or None,
            # Application permissions => acts with no user present.
            autonomous=(True if app_roles else None),
            third_party=(True if third_party else None),
            # Disabled agents still hold their grants; surface them rather than hiding them.
            last_used_days=days_since(a.get("lastSignInDateTime"), now=now),
        ))
    return out


def blueprint_summary(bundle) -> dict[str, list[str]]:
    """Group agent display names by blueprint id — context nhi-scan's schema doesn't carry.

    Agents created from one blueprint inherit one access model, so a finding against a blueprint
    is a finding against every agent under it. Printed to stderr so stdout stays clean JSON.
    """
    agents = bundle.get("agents", []) if isinstance(bundle, dict) else (bundle or [])
    groups: dict[str, list[str]] = {}
    for a in agents:
        bp = a.get("agentIdentityBlueprintId") or "(no blueprint)"
        groups.setdefault(bp, []).append(a.get("displayName") or a.get("id") or "?")
    return groups


def main(argv: list[str]) -> int:
    args = list(argv[1:])
    tenant = None
    if "--tenant" in args:
        i = args.index("--tenant")
        tenant = args[i + 1] if i + 1 < len(args) else None
        del args[i:i + 2]

    bundle = read_input([argv[0], *args])
    records = transform(bundle, tenant_id=tenant)

    groups = blueprint_summary(bundle)
    if groups:
        print(f"# {len(records)} agent identities across {len(groups)} blueprint(s)",
              file=sys.stderr)
        for bp, names in sorted(groups.items()):
            print(f"#   {bp}: {len(names)} — {', '.join(sorted(names)[:6])}"
                  + (" …" if len(names) > 6 else ""), file=sys.stderr)

    emit(records)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
