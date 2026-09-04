# nhi-scan collectors

Generate an nhi-scan inventory from your real environment instead of writing it by hand.

Each collector is a **pure transform**: you run a read-only source command, pipe (or save) its
JSON, and the collector maps it to nhi-scan records. Collectors never touch credentials
themselves — auth stays with the `az` / `aws` / `gcloud` CLIs you already trust. That also makes
them testable offline; see [`tests/test_collectors.py`](../../tests/test_collectors.py), which runs
every collector against the recorded samples in [`../samples`](../samples).

The flow is always: **collect (per source) → merge → scan.**

**Prerequisites & roles** — for the CLI each source needs (with macOS/Windows install commands)
and the least-privilege read-only role per platform (Entra, Entra Agent ID, AWS, GCP, and
Okta/Ping via CSV), see [Prerequisites](../../README.md#prerequisites) and
[Required roles & permissions](../../README.md#required-roles--permissions) in the top-level README.
Each section below also states its own read-only permission.

> **Running the collectors.** Invoke them as modules from the **repository root** (the folder
> containing `tools/`), e.g. `python -m tools.collectors.entra ...`. Running from inside
> `tools/collectors/` raises `ModuleNotFoundError: No module named 'tools'`. The collectors are
> **cross-platform** (Linux, macOS, Windows) — the `gather_*` scripts locate `az`/`aws`/`gcloud`
> on `PATH` on every OS, and every collector reads JSON tolerant of a UTF-8 BOM, so bundles
> produced by Windows PowerShell (`>` / `Out-File`) feed straight back in.

## Entra ID (Azure AD)

Read-only permission: `Application.Read.All` (or `Directory.Read.All`); Global Reader is a
sufficient directory role.

```bash
# with granted permissions (app roles + delegated scopes) — recommended
az login --tenant <YOUR_TENANT_ID>
python -m tools.collectors.gather_entra > entra-sp-bundle.json
python -m tools.collectors.entra entra-sp-bundle.json > entra-nhi.json

# names/credentials only — one call, no permission data
az ad sp list --all -o json | python -m tools.collectors.entra --tenant <YOUR_TENANT_ID> > entra-nhi.json
```

Infers credential type (certificate / secret / federated — and **managed** for
`ManagedIdentity` principals, whose keyCredentials are Azure platform-issued, auto-rotated
certs, not stored secrets: classifying those as certificates produces false NHI7/NHI4
findings), rotation age from the newest credential, and third-party status from the app's
owning tenant. The `gather_entra` path also collects each principal's **owners** (with
`accountEnabled`), so the transform can tell owned from orphaned instead of flagging every SP
under NHI1 — and sets `owner_active` so a principal whose recorded owner is a **deprovisioned**
account is treated as effectively orphaned (owner *validity*, not just presence). `owner_active`
is tri-state: `true` (enabled), `false` (disabled/deleted → NHI1 High), omitted (unknown, e.g. a
group owner or a fast scan without owner expansion → backward-compatible, not orphaned). With the `gather_entra` path,
each principal's **app-role assignments and delegated grants** populate `scopes` and drive
`privilege`, so overprivilege (NHI5) and wildcard detection can fire. `privilege` is also raised
by **directory-role membership** (`memberOf`): a principal in an admin-tier Entra role (e.g.
Application Administrator) is `admin` and any other directory role is `privileged`, catching
elevation the app-scope path alone would miss. The expansion also attaches each principal's
**last sign-in** (from the beta `servicePrincipalSignInActivities` report, best-effort — needs
`AuditLog.Read.All`; on a permission gap it's skipped, not fatal) so `last_used_days` drives
staleness (NHI1 offboarding). And when a principal has multiple owners, a **live human owner is
chosen over a disabled one** rather than blindly taking the first. Without grant data,
`privilege`/`scopes` are omitted rather than guessed — and overprivilege findings won't fire
for those records. Expansion reads four relationships per principal (owners, delegated grants,
app-role assignments, directory-role membership) plus one lookup per referenced resource and a
tenant-wide sign-in report, all issued through Microsoft
Graph `$batch` (20 sub-requests per call) — so hundreds of principals finish in a couple of
minutes rather than one `az rest` per read; `--no-expand` or `--filter <substring>` limit it.
Agent identities (`ServiceIdentity`) are excluded — use the Entra Agent ID collector below, and
merging the two stays double-count-free.

## Entra Agent ID (AI agent identities)

Read-only permission: `AgentIdentity.Read.All` + `Application.Read.All` (or `Directory.Read.All`).
Directory role: Global Reader is sufficient.

Agent identities inherit from servicePrincipal, so the collector above *sees* them — but flattens
them into `type: service_principal` and drops the attributes that make an agent worth governing.
Use this collector instead:

```bash
az login --tenant <YOUR_TENANT_ID>
python -m tools.collectors.gather_entra_agents > entra-agents-bundle.json
python -m tools.collectors.entra_agents entra-agents-bundle.json > entra-agents-nhi.json
nhi-scan scan entra-agents-nhi.json
```

`gather_entra_agents` reads the `microsoft.graph.agentIdentity` cast on Graph v1.0 (`--beta` for
the beta endpoint) and expands each agent's sponsors, owners, app-role assignments, and delegated
grants. Auth stays with `az` — the script only issues GETs through your existing session.

What the transform infers:

| Emitted | Derived from |
| --- | --- |
| `type: ai_agent` | every agent identity, so the agent rules and autonomy tiering actually fire |
| `autonomous` | **application** permissions (`appRoleAssignments`, the `roles` claim) — an agent acting with no user present. Delegated-only agents (`oauth2PermissionGrants`, `scp`) are *not* marked autonomous |
| `owner` | the **sponsor** (Entra Agent ID's accountable human), falling back to owner. No sponsor and no owner → no `owner` → flagged orphaned under NHI1 |
| `privilege` | granted role values — wildcards and `Directory.ReadWrite.All`-class roles → `admin`, other `*.ReadWrite.All`/directory-adjacent → `privileged` |
| `scopes` | app-role values plus delegated scopes |
| `credential` | `keyCredentials` → certificate, `passwordCredentials` → static secret, neither → federated |
| `third_party` | `appOwnerOrganizationId` differing from your tenant |

Blueprint groupings print to **stderr** (stdout stays clean JSON) — agents created from one
blueprint share one access model, so a finding against a blueprint is a finding against every
agent under it.

**Reach (`tools`) is not in Entra.** An agent's tool/connector manifest lives in Agent 365,
Copilot Studio, or its MCP config. Collect it with the [agent tool-manifest collector](#agent-tool-manifests-agent-reach)
and merge on `id` to make `nhi-scan diff` able to catch reach growth.

## Okta

Read-only permission: a **Read-Only Administrator** SSWS token, or an OAuth token with
`okta.apps.read` + `okta.apiTokens.read`. Okta has no CLI session to borrow, so auth comes from
your environment and is used only to sign the read-only GETs (never stored):

```bash
export OKTA_ORG_URL=https://your-org.okta.com
export OKTA_API_TOKEN=<SSWS token>        # PowerShell: $env:OKTA_API_TOKEN="..."
python -m tools.collectors.gather_okta > okta-bundle.json
python -m tools.collectors.okta okta-bundle.json > okta-nhi.json
```

Inventories the two non-human identity classes Okta exposes:

| Emitted | Derived from |
| --- | --- |
| `type: oauth_app` | OAuth **service apps** (the `client_credentials` grant — machine-to-machine). `--all-apps` includes every app; default is service apps only |
| `credential` | `private_key_jwt` → certificate; `client_secret_*` → static secret; `none` → federated |
| `scopes` / `privilege` | each app's **granted OAuth scopes** (`okta.*.manage` → privileged, `okta.*` → admin). Gathered per app; `--no-expand` skips it, and then privilege/scopes are omitted rather than guessed |
| `type: api_key` | org **API tokens** (`/api/v1/api-tokens`) — long-lived static secrets, so NHI4 fires; rotation age from the token's creation date surfaces never-rotated tokens under NHI7 |
| `owner` (API tokens) | the token's creator (`userId`) — the closest accountable human |

Uses only the Python standard library (no extra HTTP dependency). Pagination follows Okta's
`Link: rel="next"` cursor.

## AWS IAM

Read-only permission: the AWS-managed `IAMReadOnlyAccess` policy.

```bash
python -m tools.collectors.gather_aws > aws-bundle.json
python -m tools.collectors.aws aws-bundle.json > aws-nhi.json
```

One record per access key. Privilege is inferred from the **union** of attached user policies,
inline user policies, and policies inherited through group membership — attached-only
gathering is how a group-granted administrator scores as `scoped`. The gather also scans
reachable policy documents and sets a wildcard flag when any statement grants `"Action": "*"`,
which surfaces as a wildcard scope (NHI5). `--no-documents` skips the document scan; group and
policy lookups are cached. Owner and environment come from `owner`/`team` and `env` tags;
rotation and staleness from key dates. Older attached-only bundles still transform, with
correspondingly narrower inference.

## GCP service accounts

Read-only role: `roles/iam.securityReviewer` (or project viewer).

```bash
python -m tools.collectors.gather_gcp > gcp-accounts.json        # active project
python -m tools.collectors.gather_gcp --project a --project b > gcp-accounts.json
python -m tools.collectors.gcp gcp-accounts.json > gcp-nhi.json
```

Gathers service accounts, their keys, and — via one `projects get-iam-policy` read per
project — each account's **IAM role bindings**. Bindings populate `scopes` and drive
`privilege`: `roles/owner`/`roles/editor` are project-wide write and map to `admin`;
`*Admin` and `roles/iam.*` roles map to `privileged`. A user-managed key is treated as a
long-lived static credential; accounts without one are `managed`. Bundles without `roles`
(the older path) omit `privilege`/`scopes` rather than guess. Caveat: bindings are
project-level — folder/org-level and resource-level grants are not gathered, so an account
can hold **more** than shown, never less.

## Agent tool manifests (agent *reach*)

An AI agent's reach — the tools/connectors it can invoke — can grow without touching privilege,
credential age, or owner, so it needs to be inventoried as a first-class input (the `tools` field)
and diffed between scans (`nhi-scan diff`). The `mcp` collector builds an agent record from its
connected servers/tools:

```bash
python -m tools.collectors.mcp mcp-agents.json > agents-nhi.json
```

Input is an agent-to-servers manifest (see [`../samples/mcp-agents.json`](../samples/mcp-agents.json));
server tools are namespaced `<server>.<tool>`. **Where to get the manifest:**

| Source | What to pull |
| --- | --- |
| MCP client/host config | the servers each agent is wired to; tool names from each server's `tools/list` |
| Agent framework (LangChain / Semantic Kernel / AutoGen) | the agent's registered tool/function list |
| Copilot Studio / Microsoft Agent 365 / Entra Agent ID | the agent's registered plugins, connectors, and actions |

Snapshot the manifest on each run, then `nhi-scan diff before.json after.json` flags added/removed
tools — turning "the agent got a new connector" from an invisible change into a diffable one.
(The CSV collector also accepts a `tools` column: separate values with `;`, `|`, or `,`.)

## CSV export (no cloud CLI needed)

Export a spreadsheet whose header row uses nhi-scan field names (see
[`../samples/identities.csv`](../samples/identities.csv)), then:

```bash
python -m tools.collectors.csv_import identities.csv > csv-nhi.json
```

## Merge and scan

Combine every source into one inventory and scan it:

```bash
# with jq
jq -s 'add' entra-nhi.json aws-nhi.json gcp-nhi.json csv-nhi.json > inventory.json

# or without jq
python -c "import json,sys; json.dump([r for f in sys.argv[1:] for r in json.load(open(f))], open('inventory.json','w'))" entra-nhi.json aws-nhi.json gcp-nhi.json csv-nhi.json

nhi-scan scan inventory.json
```

## Run it on a schedule

Wire the collect → merge → scan pipeline into a nightly or weekly job (cron, a scheduled task, or
a CI pipeline with read-only cloud credentials) so the inventory stays live rather than being a
one-time snapshot. Emit `--json` and feed it into a dashboard or ticketing system.

## Writing your own collector

Add a module here that exposes `transform(raw, now=None) -> list[dict]`, using
[`common.record()`](common.py) to build records and `common.days_since()` for credential ages.
Keep it a pure function of already-fetched data, drop a sample into [`../samples`](../samples), and
add a test. That's the whole contract.
