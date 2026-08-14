# Non-Human Identity Drift Report

**2** changed · **1** added · **1** removed · **5** unchanged · **2** risk escalations

## ⚠️ Reach grew without a tier change

_These identities gained tools or scopes while privilege, credential age, and owner stayed the same — the blind spot a point-in-time tier misses._

### collections-ai-agent `(agent-collections)`
  - Tier: 🔴 Critical → 🔴 Critical ＝ (same)
  - **Tools added (reach ↑):** crm_lookup, email_send, payment_refund_api, customer_db_query
  - **Scopes added (reach ↑):** payments:refund

## 🔺 Risk escalations

### analytics-vendor-connector `(sp-analytics-vendor)`
  - Tier: 🟡 Moderate → 🟠 High 🔺 (escalated)
  - **Scopes added (reach ↑):** reports:*
  - Scopes removed: reports:read
  - `NEW` finding: NHI5:2025 Overprivileged NHI

## Added identities

- **partner-payments-integration** `(svc-new-integration)` — 🟡 Moderate

## Removed identities

- sandbox-webhook `(hook-sandbox-test)` — was 🟡 Moderate

