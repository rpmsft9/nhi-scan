# Non-Human Identity Risk Report

**8** identities · **21** findings · **1** orphaned · **3** long-lived secrets

## Risk tiers

| Tier | Identities |
| --- | ---: |
| 🔴 Critical | 3 |
| 🟠 High | 1 |
| 🟡 Moderate | 4 |
| 🟢 Baseline | 0 |

## OWASP NHI Top 10 findings

| OWASP | Title | Count |
| --- | --- | ---: |
| NHI10:2025 | Human Use of NHI | 1 |
| NHI1:2025 | Improper Offboarding | 2 |
| NHI2:2025 | Secret Leakage | 3 |
| NHI3:2025 | Vulnerable Third-Party NHI | 1 |
| NHI4:2025 | Insecure Authentication | 6 |
| NHI5:2025 | Overprivileged NHI | 2 |
| NHI6:2025 | Insecure Cloud Deployment Configurations | 1 |
| NHI7:2025 | Long-Lived Secrets | 3 |
| NHI8:2025 | Environment Isolation | 1 |
| NHI9:2025 | NHI Reuse | 1 |

_Mapped to the [OWASP NHI Top 10](https://owasp.org/www-project-non-human-identities-top-10/)._

## Identities by risk

### 🔴 Critical — legacy-etl-api-key `(api_key)`
- **Owner:** _orphaned_ · **Env:** prod · **Privilege:** privileged · **Score:** 84
- **Why this tier:** Privileged identity is reachable from the public internet.
- **Findings:**
  - `CRITICAL` **NHI2:2025 Secret Leakage** — Static secret stored in plaintext (hardcoded/committed/config). _→ Move the secret to a managed vault, rotate it immediately, and scan history for exposure._
  - `CRITICAL` **NHI6:2025 Insecure Cloud Deployment Configurations** — Identity is reachable from the public internet. _→ Place behind private networking / an allow-list; restrict source ranges and add egress controls._
  - `HIGH` **NHI1:2025 Improper Offboarding** — Unused for 220 days (staleness window is 90). _→ Deprovision or disable; if still required, re-justify ownership and set an expiry._
  - `HIGH` **NHI7:2025 Long-Lived Secrets** — Static secret with no recorded rotation (never rotated). _→ Rotate now and automate rotation; prefer short-lived, auto-issued credentials._
  - `MEDIUM` **NHI4:2025 Insecure Authentication** — Authenticates with api_key rather than federated/managed identity. _→ Migrate to workload identity federation (OIDC) or a cloud-managed identity — no stored secret._

### 🔴 Critical — payments-batch-runner `(service_account)`
- **Owner:** payments-platform@bank.example · **Env:** prod · **Privilege:** admin · **Score:** 60
- **Why this tier:** Admin-level identity authenticating with a long-lived static secret — a stealable crown-jewel credential.
- **Findings:**
  - `HIGH` **NHI5:2025 Overprivileged NHI** — Holds admin privilege. _→ Right-size to the specific permissions the workload uses; remove standing admin._
  - `HIGH` **NHI7:2025 Long-Lived Secrets** — Static secret last rotated 410 days ago (max is 90). _→ Rotate now and automate rotation; prefer short-lived, auto-issued credentials._
  - `MEDIUM` **NHI4:2025 Insecure Authentication** — Authenticates with static_secret rather than federated/managed identity. _→ Migrate to workload identity federation (OIDC) or a cloud-managed identity — no stored secret._

### 🔴 Critical — collections-ai-agent `(ai_agent)`
- **Owner:** cx-automation@bank.example · **Env:** prod · **Privilege:** privileged · **Score:** 56
- **Why this tier:** Autonomous AI agent holds elevated privilege and acts without per-action human approval.
- **Findings:**
  - `HIGH` **NHI5:2025 Overprivileged NHI** — Carries wildcard/full-access scope: accounts:read, accounts:update, ledger:*. _→ Replace wildcard scopes with the explicit, minimal set the workload calls._
  - `MEDIUM` **NHI2:2025 Secret Leakage** — Static secret injected via environment variable (readable by the process and crash dumps). _→ Source the secret from a vault at runtime; avoid long-lived env injection._
  - `MEDIUM` **NHI4:2025 Insecure Authentication** — Authenticates with static_secret rather than federated/managed identity. _→ Migrate to workload identity federation (OIDC) or a cloud-managed identity — no stored secret._

### 🟠 High — oncall-shared-pat `(pat)`
- **Owner:** sre@bank.example · **Env:** prod · **Privilege:** privileged · **Score:** 44
- **Why this tier:** A human authenticates interactively with this shared non-human identity (no individual attribution).
- **Findings:**
  - `HIGH` **NHI10:2025 Human Use of NHI** — A human authenticates interactively with this non-human identity. _→ Give humans their own identities; reserve this NHI for automation and block interactive login._
  - `HIGH` **NHI7:2025 Long-Lived Secrets** — Static secret last rotated 200 days ago (max is 90). _→ Rotate now and automate rotation; prefer short-lived, auto-issued credentials._
  - `MEDIUM` **NHI2:2025 Secret Leakage** — Static secret injected via environment variable (readable by the process and crash dumps). _→ Source the secret from a vault at runtime; avoid long-lived env injection._
  - `MEDIUM` **NHI4:2025 Insecure Authentication** — Authenticates with static_secret rather than federated/managed identity. _→ Migrate to workload identity federation (OIDC) or a cloud-managed identity — no stored secret._

### 🟡 Moderate — github-actions-deployer `(ci_cd_token)`
- **Owner:** devsecops@bank.example · **Env:** prod · **Privilege:** privileged · **Score:** 24
- **Why this tier:** Identity operates in production.
- **Findings:**
  - `HIGH` **NHI8:2025 Environment Isolation** — Same identity/credential is used across production and non-production. _→ Split into per-environment identities so a non-prod compromise cannot reach prod._
  - `MEDIUM` **NHI4:2025 Insecure Authentication** — Authenticates with static_secret rather than federated/managed identity. _→ Migrate to workload identity federation (OIDC) or a cloud-managed identity — no stored secret._
  - `MEDIUM` **NHI9:2025 NHI Reuse** — Shared across 3 workloads: web-app, batch, mobile-bff. _→ Issue a dedicated identity per workload to restore least privilege and attribution._

### 🟡 Moderate — analytics-vendor-connector `(service_principal)`
- **Owner:** data-eng@bank.example · **Env:** prod · **Privilege:** scoped · **Score:** 16
- **Why this tier:** Identity operates in production.
- **Findings:**
  - `MEDIUM` **NHI3:2025 Vulnerable Third-Party NHI** — Identity is issued to / operated by an external third party. _→ Constrain to least-privilege scopes, require short-lived credentials, and monitor its access._
  - `MEDIUM` **NHI4:2025 Insecure Authentication** — Authenticates with static_secret rather than federated/managed identity. _→ Migrate to workload identity federation (OIDC) or a cloud-managed identity — no stored secret._

### 🟡 Moderate — sandbox-webhook `(webhook)`
- **Owner:** qa@bank.example · **Env:** sandbox · **Privilege:** read_only · **Score:** 12
- **Why this tier:** Identity is stale (unused beyond the staleness window).
- **Findings:**
  - `MEDIUM` **NHI1:2025 Improper Offboarding** — Unused for 400 days (staleness window is 90). _→ Deprovision or disable; if still required, re-justify ownership and set an expiry._

### 🟡 Moderate — fraud-scoring-workload `(workload_identity)`
- **Owner:** fraud-ml@bank.example · **Env:** prod · **Privilege:** scoped · **Score:** 8
- **Why this tier:** Identity operates in production.

