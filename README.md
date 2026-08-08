# nhi-scan

**Every workload, integration, and AI agent now has an identity — and nobody owns most of them.**
`nhi-scan` inventories your **non-human & agent identities**, assigns each a **defensible risk
tier**, and maps its posture to the [OWASP Non-Human Identities (NHI) Top 10](https://owasp.org/www-project-non-human-identities-top-10/)
— with a least-privilege remediation for every finding.

It runs entirely locally and is **deterministic**: the same inventory always produces the same
tiers and findings, so an assessment is explainable to an engineer and defensible to an auditor.
No LLM is in the verdict path.

See **[PITCH.md](PITCH.md)** for the why, with sourced market data.

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
| `autonomous`, `third_party`, `human_used`, `shared_across_env`, `used_by` | booleans / list | agent rules, NHI3/8/9/10 |

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
