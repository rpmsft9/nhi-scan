# Changelog

All notable changes to **nhi-scan** are documented here. The project inventories non-human &
agent identities, risk-tiers them, and maps posture to the OWASP NHI Top 10 — deterministically,
with no LLM in the verdict path.

The format follows [Keep a Changelog](https://keepachangelog.com/); this project uses semantic
versioning.

## [0.3.0] — Collector enrichment & owner validity

Since the last release, nhi-scan got materially better at telling *real* risk from noise —
especially for ownership, staleness, and privilege — and gained a new source and big speed/portability wins.

### Added
- **Owner *validity*, not just presence (NHI1).** A new tri-state `owner_active` distinguishes a
  live, accountable owner from one whose account is **disabled/deleted**. An identity whose
  recorded owner has left is now flagged as effectively orphaned — **NHI1 High** — the real
  "improper offboarding" case. Never-owned stays Medium. Backward compatible (`owner_active`
  unknown → prior behavior).
- **Native staleness.** The Entra collector now attaches each service principal's **last sign-in**
  (Microsoft Graph `servicePrincipalSignInActivities`, best-effort; needs `AuditLog.Read.All`),
  populating `last_used_days` so **NHI1 stale/offboarding** fires from a default scan instead of
  needing manual enrichment.
- **Directory-role privilege.** Collectors now read `memberOf`; a service principal or agent that
  holds an Entra **directory role** (e.g. *Application Administrator*) is tiered `admin`
  (admin-tier roles) or `privileged` (any other role) — elevation the app-scope path alone missed.
  Groups in `memberOf` are correctly ignored.
- **Okta collector** — service apps (client-credentials) and org API tokens, via a Read-Only
  Administrator token (`gather_okta` → `okta`), no CLI required.

### Changed
- **Best-owner selection.** When an identity has multiple owners/sponsors, a **live human** owner
  is chosen over a disabled first entry, instead of blindly taking `owners[0]`.
- **~20× faster enriched Entra gather.** Per-principal Microsoft Graph reads (owners, grants,
  app-role assignments, directory-role membership) are issued through Graph **`$batch`** (20
  sub-requests per call). A ~600-service-principal tenant drops from ~40 minutes to ~2.
- **Cross-platform.** Collectors run on Linux, macOS, **and Windows** — CLI shims are launched
  correctly and JSON is read tolerant of the UTF-8 BOM that Windows PowerShell writes.

### Fixed
- **Managed identities are no longer false positives.** Azure managed identities (platform-issued,
  auto-rotating certs) are classified `credential: managed` and no longer generate NHI7
  (long-lived secret) / NHI4 findings — the single biggest source of noise on real tenants.

## [0.2.0] — Drift detection & agent reach

### Added
- **Drift detection (`nhi-scan diff`).** Compares two inventories and surfaces added/removed
  identities, **tier escalations**, and a **"reach grew without a tier change"** section — an
  agent that gained a tool/connector while privilege, credential age, and owner look unchanged.
- **Agent reach (`tools`).** A first-class field for an agent's tools / connectors / MCP servers,
  so blast-radius growth is diffable.
- **MCP collector.** Builds agent records (server-namespaced tools) from an agent tool manifest.

## [0.1.0] — Initial release

### Added
- Deterministic **floor-tier risk engine** (Tier 1–4) from posture (privilege, credential type,
  rotation age, ownership, exposure, autonomy) — every matching rule recorded, so any tier is
  explainable.
- **OWASP NHI Top 10** posture checks (NHI1–NHI10), each with evidence and a least-privilege
  remediation; regulatory content as a versioned data layer.
- **CLI**: `inventory` and `scan` (Markdown + JSON), JSON/YAML inventories.
- **Read-only collectors** for Microsoft Entra, AWS IAM, GCP, and CSV import.
