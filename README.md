# nhi-scan

**Every workload, integration, and AI agent now has an identity — and nobody owns most of them.**
`nhi-scan` inventories your **non-human & agent identities**, assigns each a **defensible risk
tier**, and maps its posture to the [OWASP Non-Human Identities (NHI) Top 10](https://owasp.org/www-project-non-human-identities-top-10/)
— with a least-privilege remediation for every finding.

It runs entirely locally and is **deterministic**: the same inventory always produces the same
tiers and findings, so an assessment is explainable to an engineer and defensible to an auditor.
No LLM is in the verdict path.

See **[PITCH.md](PITCH.md)** for the why, with sourced market data — and
**[A Control Framework for Non-Human & Agentic Identity](docs/nhi-agentic-control-framework.md)**
for the control model this tool implements (30 controls mapped to OWASP NHI Top 10, NIST AI RMF,
CSF 2.0, and 800-53).

> Machine identities now outnumber human ones by [more than 82:1](https://www.cyberark.com/press/machine-identities-outnumber-humans-by-more-than-80-to-1-new-report-exposes-the-exponential-threats-of-fragmented-identity-security/)
> (CyberArk, 2025), and **AI agents** are the fastest-growing class — each one a privileged,
> often autonomous identity. `nhi-scan` treats the agent as what it is: an NHI that needs an
> owner, least privilege, short-lived credentials, and a tier.

## Why this exists

Discovery tools tell you *how many* secrets and service accounts you have. A CISO needs the next
two answers: **which ones are crown jewels**, and **what do I fix first**. `nhi-scan` is that
prioritization layer.

- **Risk-tiering, not a flat list.** A transparent floor-tier rules engine assigns Tier 1–4 from
  posture (privilege, credential type, rotation age, ownership, exposure, autonomy). The most
  severe rule that matches sets the tier, and every matching rule is recorded — so you can always
  answer *"why is this Tier 1?"*
- **OWASP NHI Top 10 mapping.** Ten posture checks emit findings tied to NHI1–NHI10, each with the
  concrete evidence and a remediation. The regulatory content is a versioned data layer
  ([`owasp.py`](nhiscan/owasp.py)), not code.
- **Agent-aware.** Autonomous AI agents with elevated privilege tier as crown jewels — the emerging
  gap that classic secret scanners don't model.

## Install

```bash
pip install -e .            # core, zero third-party dependencies (JSON inventories)
pip install -e '.[yaml]'    # + YAML inventory support
pip install -e '.[dev]'     # + pytest
```

## Usage

```bash
nhi-scan inventory examples/sample-inventory.json     # counts by type and risk tier
nhi-scan scan      examples/sample-inventory.json     # full Markdown risk report
nhi-scan scan      examples/sample-inventory.json --json   # machine-readable JSON
nhi-scan diff      examples/sample-inventory.json examples/sample-inventory-after.json   # drift between two scans
```

See [`examples/sample-report.md`](examples/sample-report.md) for a full rendered report.

### What a scan surfaces

```
8 identities · 21 findings · 1 orphaned · 3 long-lived secrets

🔴 Critical  3     🟠 High  1     🟡 Moderate  4     🟢 Baseline  0
```

The top-ranked identity in the sample is an **autonomous collections AI agent** holding
`ledger:*` in production — flagged Tier 1 (critical) for overprivilege and autonomy, exactly the
kind of NHI that never appears on a human-identity review.

## The inventory format

A JSON or YAML list of NHI records. Only `id` and `name` are required; everything else defaults to
a safe, conservative posture, so a partial inventory still assesses.

```json
{
  "id": "agent-collections",
  "name": "collections-ai-agent",
  "type": "ai_agent",
  "owner": "cx-automation@bank.example",
  "environment": "prod",
  "privilege": "privileged",
  "credential": "static_secret",
  "secret_storage": "env",
  "last_rotated_days": 30,
  "last_used_days": 0,
  "exposure": "internal",
  "scopes": ["accounts:read", "accounts:update", "ledger:*"],
  "autonomous": true
}
```

| Field | Values | Drives |
| --- | --- | --- |
| `type` | `service_account`, `api_key`, `oauth_app`, `service_principal`, `managed_identity`, `workload_identity`, `ci_cd_token`, `pat`, `webhook`, `secret`, `ai_agent` | inventory + agent rules |
| `privilege` | `admin`, `privileged`, `scoped`, `read_only` | tiering, NHI5 |
| `credential` | `static_secret`, `api_key`, `certificate`, `federated`, `managed`, `short_lived_token`, `none` | NHI4, NHI7 |
| `secret_storage` | `vault`, `env`, `plaintext`, `none` | NHI2 |
| `last_rotated_days` / `last_used_days` | integer or null | NHI7 / NHI1 |
| `exposure` | `internet`, `external_partner`, `internal` | tiering, NHI6 |
| `scopes` | list of strings (`*` / `:*` = wildcard) | NHI5 |
| `tools` | list of strings — an agent's tools / connectors / MCP servers | agent **reach** (drift) |
| `autonomous`, `third_party`, `human_used`, `shared_across_env`, `used_by` | booleans / list | agent rules, NHI3/8/9/10 |

## Detecting drift — when an agent's reach grows

Privilege, credential age, and owner change only when someone *touches* the identity. An AI
agent's **reach** doesn't: give it a new tool, connector, or MCP server and its blast radius
grows while those attributes — and often the risk tier — look identical. `nhi-scan diff`
compares two inventories and surfaces exactly that:

```bash
nhi-scan diff before.json after.json          # Markdown
nhi-scan diff before.json after.json --json    # machine-readable
```

It reports added/removed identities, **tier escalations**, and — most importantly — a
**"reach grew without a tier change"** section: identities that gained `tools` or `scopes` while
privilege, credential age, and owner stayed the same. Run it on a schedule (or in CI) to catch
reach creep between point-in-time scans.

**Where `tools` comes from.** `nhi-scan` reads the agent's declared tool manifest — it doesn't
infer reach. Populate `tools` from wherever an agent's capabilities are defined: its **MCP server
config** (the tools each server exposes), its **agent-framework manifest** (LangChain / Semantic
Kernel / AutoGen function lists), or its registered **plugins / connectors / actions** in
platforms like **Copilot Studio, Microsoft Agent 365 / Entra Agent ID**. Feeding that manifest in
is what turns "an agent got a new connector" from an invisible change into a diffable one.

### Preparing your inventory

Copy [`examples/template-inventory.json`](examples/template-inventory.json) — it's an annotated
template with the allowed values inline and both a minimal and a fully-populated record. Then
build one record per identity by pulling from where your NHIs actually live:

| Source | What to pull |
| --- | --- |
| Entra / Okta / Ping | service principals, enterprise & OAuth apps, workload identities |
| AWS / Azure / GCP | IAM users & access keys, roles, service accounts, managed identities |
| Secrets managers / vaults | stored secrets and their rotation age |
| GitHub / GitLab / CI | PATs, deploy tokens, pipeline credentials |
| Agent platforms (e.g. Entra Agent ID) | your AI agents — set `type: ai_agent` and `autonomous` |

**Start minimal, then enrich.** Begin with the fields you can get cheaply — `id`, `name`, `type`,
`owner`, `environment`, `privilege` — run a scan, then add `credential`, `last_rotated_days`, and
`scopes` to sharpen the results. Missing fields fall back to conservative defaults rather than
failing, so a partial inventory still produces a useful report.

### Generate the inventory automatically

For anything past a pilot, don't hand-write the file — **generate it** from your environment with
the [collectors](tools/collectors/README.md). Each is a read-only transform (source API JSON in →
nhi-scan JSON out) for **Entra ID, Entra Agent ID, AWS IAM, GCP service accounts, and CSV exports** — each paired with a read-only `gather_*` script that collects the identity's **granted permissions** (app roles and delegated scopes; attached, inline, and group-inherited IAM policies; project role bindings), so privilege is measured, not guessed:

```bash
python -m tools.collectors.gather_entra        | python -m tools.collectors.entra        > entra-nhi.json
python -m tools.collectors.gather_entra_agents | python -m tools.collectors.entra_agents > agents-nhi.json
python -m tools.collectors.gather_aws          | python -m tools.collectors.aws          > aws-nhi.json
python -m tools.collectors.gather_gcp          | python -m tools.collectors.gcp          > gcp-nhi.json
python -m tools.collectors.csv_import identities.csv > csv-nhi.json
# merge every source, then scan
jq -s 'add' *-nhi.json > inventory.json && nhi-scan scan inventory.json
```

Run the collect → merge → scan pipeline on a schedule to keep the inventory live. See the
[collectors guide](tools/collectors/README.md) for the read-only permissions and gather scripts.

## Risk policy

Tiering rules live in [`nhiscan/tiering.py`](nhiscan/tiering.py); OWASP checks in
[`nhiscan/checks.py`](nhiscan/checks.py). Both are ordered, pure-function lists — edit them to
match your control standard. Thresholds (rotation window, staleness window, wildcard scopes) are
constants at the top of [`nhiscan/models.py`](nhiscan/models.py).

## Tests

```bash
pytest -q
```

## License

MIT.
