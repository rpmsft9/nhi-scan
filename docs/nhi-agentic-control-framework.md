# A Control Framework for Non-Human & Agentic Identity

**Version 1.4 · August 2026 · Raj Penchala**

_A practitioner reference. Companion to the open-source scanner [nhi-scan](https://github.com/rpmsft9/nhi-scan), and to [The Non-Human Identity Reckoning](/articles/the-non-human-identity-reckoning). Canonical version:
[rajpenchala.com/articles/control-framework-non-human-agentic-identity](https://www.rajpenchala.com/articles/control-framework-non-human-agentic-identity)._

---

A practical control framework for governing the enterprise's fastest-growing and least-governed identity population: non-human identities (NHIs) — service accounts, API keys, OAuth apps, service principals, workload identities, CI/CD tokens — and the new class among them, **autonomous AI agents**.

It is deliberately implementation-oriented. Every control is stated as something a team can build and an auditor can test, and every control maps to established frameworks — the [OWASP Non-Human Identities Top 10](https://owasp.org/www-project-non-human-identities-top-10/), the [NIST AI Risk Management Framework](https://www.nist.gov/itl/ai-risk-management-framework), [NIST CSF 2.0](https://www.nist.gov/cyberframework), and [NIST SP 800-53 Rev 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) — so it slots into programs you already run.

## 1. Why a dedicated framework

Machine identities outnumber human ones by 82:1 (CyberArk, 2025) and the population grew 44% in a single year (Entro Labs, 2025). We spent two decades maturing the *human* identity lifecycle — provisioning, MFA, access review, offboarding. NHIs receive a fraction of that rigor, and AI agents add a property no prior NHI had: **autonomy**. An agent authenticates, holds privileges, and *acts* — increasingly without a human approving each action.

Human-identity governance assumes a person behind the account, a manager to attest, and a joiner-mover-leaver rhythm. NHIs and agents break all three assumptions. This framework restates identity discipline for a population that has no manager, no login session, and — in the case of agents — its own agency.

**Scope:** all non-human identities across cloud, SaaS, on-premises, and CI/CD, including AI agents. **Out of scope:** human workforce and consumer (CIAM) identity, except where a human delegates authority to an agent.

## 2. Principles

1. **Identity-first.** Every non-human actor — including every agent — is an identity to be inventoried, owned, tiered, authenticated, authorized, and retired.
2. **An owner for everything.** No NHI exists without a named, accountable human owner and a business justification.
3. **Least privilege, always.** Scope to what the workload actually uses. No wildcards, no standing admin, no "just in case."
4. **Short-lived by default.** Prefer federated/managed and just-in-time credentials over stored secrets. Long-lived secrets are the exception that must be justified.
5. **Bounded autonomy.** An agent's freedom to act is a function of the risk of the action. High-impact actions require a human in the loop.
6. **Everything attributable.** Every action by an NHI or agent is traceable to the identity and, for agents, to the originating principal.
7. **Contain by design.** You can revoke any NHI's credentials and halt any agent immediately.
8. **Risk drives rigor.** Control intensity scales with the identity's risk tier.

## 3. Risk tiering

Control rigor is proportional to risk. Tier every NHI and agent from its posture, not its type.

| Tier | Meaning | Typical drivers |
| --- | --- | --- |
| **Tier 1 — Critical** | Crown jewel; strongest, immediate governance | Admin + long-lived secret; privileged & internet-exposed; **autonomous agent with elevated privilege**; privileged & orphaned |
| **Tier 2 — High** | Elevated scrutiny | Overprivileged/wildcard scopes; production long-lived secret; orphaned; autonomous agent; human use of an NHI |
| **Tier 3 — Moderate** | Standard governance | Production identity; long-lived secret; stale; third-party |
| **Tier 4 — Baseline** | Minimum governance | Everything inventoried gets a floor of control |

The tiering is deterministic and explainable: the most severe driver that applies sets the tier, and each driver is recorded. A reference implementation ships in [nhi-scan](https://github.com/rpmsft9/nhi-scan).

## 4. Control domains

Thirty-five controls across eight domains. Each control lists the tiers at which it is **mandatory** and its framework mappings.

### D1 · Discovery & Inventory (INV)

| ID | Control | Mandatory | Maps to |
| --- | --- | --- | --- |
| INV-1 | Continuously updated inventory of all NHIs, agents included, across cloud, SaaS, on-prem, and CI/CD. | All | NHI (all); AI RMF MAP; CSF ID.AM; CM-8, AC-2 |
| INV-2 | Classify each NHI by type — including third-party-issued and vendor-integration identities — by environment, and by the workload or agent it serves. | All | NHI3; AI RMF MAP; CSF ID.AM; CM-8 |
| INV-3 | Continuously detect and reconcile shadow / unmanaged NHIs and agents. | T1–T3 | NHI1; CSF DE.CM; CA-7, CM-8 |

### D2 · Ownership & Accountability (OWN)

| ID | Control | Mandatory | Maps to |
| --- | --- | --- | --- |
| OWN-1 | Every NHI has a named human owner and a recorded business justification. | All | NHI1; CSF GV.RR; AC-2 |
| OWN-2 | Re-attest ownership on a defined cadence and on owner departure. | T1–T2 | NHI1; CSF GV.RR; AC-2, PS-4/5 |
| OWN-3 | Quarantine and remediate orphaned NHIs within a defined SLA. | T1–T3 | NHI1; AI RMF MANAGE; AC-2(3) |

### D3 · Authentication & Credentials (CRED)

| ID | Control | Mandatory | Maps to |
| --- | --- | --- | --- |
| CRED-1 | Prefer workload identity federation and managed identities over stored secrets; scope federated (OIDC) trusts with audience and subject claim restrictions — especially in CI/CD. | T1–T2 | NHI4,6; CSF PR.AA; IA-5, IA-9 |
| CRED-2 | Where a secret is unavoidable, source it from a managed vault — never plaintext, committed, or hardcoded. | All | NHI2; CSF PR.DS; IA-5, SC-12, SC-28 |
| CRED-3 | Enforce a maximum credential lifetime with automated rotation; prefer short-lived, JIT credentials. | T1–T3 | NHI7; CSF PR.AA; IA-5(1) |
| CRED-4 | Bind each credential to a single identity and workload; prohibit sharing and reuse. | T1–T2 | NHI9; CSF PR.AA; IA-5, AC-2 |

### D4 · Authorization & Least Privilege (AUTHZ)

| ID | Control | Mandatory | Maps to |
| --- | --- | --- | --- |
| AUTHZ-1 | Grant the minimum scopes the workload uses; prohibit wildcard scopes and standing admin. | All | NHI5; CSF PR.AA; AC-6 |
| AUTHZ-2 | Review and right-size entitlements on a cadence and on material change. | T1–T2 | NHI5; AI RMF MANAGE; AC-6, AC-2 |
| AUTHZ-3 | Enforce environment isolation — distinct identities per environment; no prod/non-prod reuse. | T1–T3 | NHI8; CSF PR.IR; SC-7, CM-2 |
| AUTHZ-4 | Constrain network exposure and egress; deny internet reachability unless justified. | T1–T2 | CSF PR.IR; SC-7 |
| AUTHZ-5 | Govern NHIs granted to third-party apps, extensions, and integrations: review and approve requested scopes before install, time-bound the grant, re-attest it, and revoke on vendor offboarding or vendor compromise. | T1–T3 | NHI3; CSF GV.SC, ID.AM; SR-3, AC-20, CM-7 |
| AUTHZ-6 | Prohibit interactive human use of NHI credentials — people act under their own identity. Where break-glass is unavoidable, require prior approval, time-limit it, and attribute the session to a named person. | All | NHI10; CSF PR.AA, GV.RR; AC-2, AC-6(2), IA-2 |

### D5 · Lifecycle (LIFE)

| ID | Control | Mandatory | Maps to |
| --- | --- | --- | --- |
| LIFE-1 | Provision NHIs only through an approved, automated workflow tied to an owner and justification. | T1–T3 | NHI1; CSF GV.RR, PR.AA; AC-2 |
| LIFE-2 | Deprovision on workload or owner offboarding; automatically disable stale identities. | All | NHI1; AI RMF MANAGE; AC-2(3) |
| LIFE-3 | Track credential and identity expiry; deny indefinite lifetimes. | T1–T3 | NHI7; CSF PR.AA; AC-2, IA-5(1) |

### D6 · Agentic Controls (AGENT) — the differentiated core

The controls that classic NHI programs and secret scanners do not model. They govern the one property agents add: **agency**. An agent's authority is *delegated* from a human principal, exercised through a short-lived scoped credential, gated by action risk, and recorded end-to-end.

| ID | Control | Mandatory | Maps to |
| --- | --- | --- | --- |
| AGENT-1 | Treat every AI agent as a first-class identity — inventoried, owned, tiered, credentialed — and distinct from the human or service it acts for. | Agents | NHI1,5; AI RMF GOVERN/MAP; AC-2, IA-9 |
| AGENT-2 | Bound autonomy to action risk: define a risk taxonomy (read / write / irreversible-or-financial) and require human approval above a set threshold. | Agents | AI RMF MANAGE; CSF GV.RR; AC-3, AC-6 |
| AGENT-3 | Issue just-in-time, per-session, narrowly scoped credentials to agents; no long-lived broad grants. | Agents | NHI7; CSF PR.AA; IA-5(1), AC-6 |
| AGENT-4 | Derive an agent's authority from an originating principal via a verifiable, traceable delegation (on-behalf-of) chain. | Agents | AI RMF MAP; CSF PR.AA; AC-3, IA-9, AU-10 |
| AGENT-5 | Make every agent action attributable to both the agent identity and the originating principal in tamper-evident logs. | Agents | AI RMF MEASURE; CSF DE.AE; AU-2, AU-10 |
| AGENT-6 | Constrain which tools and resources an agent may invoke; enforce guardrails against injection-driven privilege abuse. | Agents | OWASP LLM; AI RMF MANAGE; AC-3, SI-10 |
| AGENT-7 | Authenticate, authorize, and scope agent-to-agent (A2A) interactions; no implicit inter-agent trust. | T1–T2 agents | CSF PR.AA; IA-9, AC-4 |
| AGENT-8 | Provide containment: instantly revoke an agent's credentials and halt its actions (kill switch). | Agents | CSF RS.MI; IR-4, AC-2(3) |

### D7 · Monitoring, Detection & Response (MON)

| ID | Control | Mandatory | Maps to |
| --- | --- | --- | --- |
| MON-1 | Log all NHI/agent authentication and high-risk actions to a central, tamper-evident store. | T1–T2 | CSF DE.CM; AU-2, AU-6 |
| MON-2 | Baseline normal behavior and alert on anomalies (new scope use, off-hours, volume, geography, interactive human-pattern use of an NHI). | T1–T2 | NHI10; AI RMF MEASURE; CSF DE.AE; SI-4, AU-6 |
| MON-3 | Detect credential exposure / leakage and automatically trigger rotation. | T1–T3 | NHI2; CSF DE.CM, RS.MI; IA-5, IR-4 |
| MON-4 | Maintain incident runbooks for NHI/agent compromise, including mass revocation. | T1–T2 | CSF RS.MA; IR-4, IR-8 |

### D8 · Governance & Risk (GOV)

| ID | Control | Mandatory | Maps to |
| --- | --- | --- | --- |
| GOV-1 | Risk-tier every NHI and agent from posture; drive control rigor by tier. | All | AI RMF GOVERN/MAP; CSF GV.RM; RA-3, PM-9 |
| GOV-2 | Map controls to applicable regulatory and industry frameworks and retain audit evidence. | All | CSF GV.OC; CA-2, PM |
| GOV-3 | Define a risk appetite for autonomous agents; approve high-tier agents at the appropriate altitude. | T1–T2 agents | AI RMF GOVERN; CSF GV.RM; PM |
| GOV-4 | Measure program coverage and report NHI/agent risk to leadership on a cadence. | All | AI RMF MEASURE; CSF GV.OV; CA-7, PM |

## 5. Agentic identity threat model

Threats are numbered **A1…A11** — *A* for agentic. The control tables above use **T1–T4** for
*risk tiers*; the two schemes are unrelated, and the letter keeps them apart.

| # | Threat | Description | Primary controls |
| --- | --- | --- | --- |
| A1 | **Excessive agency** | An over-privileged agent takes actions beyond its intended task. | AUTHZ-1, AGENT-2, AGENT-6 |
| A2 | **Credential theft & replay** | Long-lived agent/NHI secrets are stolen and reused. | CRED-1, CRED-3, AGENT-3 |
| A3 | **Confused deputy / delegation abuse** | An agent is tricked into using its authority on an attacker's behalf. | AGENT-4, AGENT-5, AUTHZ-1 |
| A4 | **Prompt-injection → privilege abuse** | Malicious input redirects an agent to misuse its tools/permissions. | AGENT-6, AGENT-2, MON-2 |
| A5 | **Malicious or compromised tool** | A poisoned or compromised MCP server, connector, or plugin subverts the agent through a tool it already trusts. No credential is stolen and the identity looks unchanged, so identity-centric controls alone never see it. | AUTHZ-5, AGENT-6, MON-2 |
| A6 | **Inter-agent trust abuse** | One agent trusts another implicitly and is used to reach what the calling agent could not reach on its own — delegation laundering across an agent mesh. | AGENT-7, AGENT-4, AGENT-5 |
| A7 | **Agent & NHI sprawl** | Unmanaged, shadow agents and identities proliferate. | INV-1, INV-3, OWN-1 |
| A8 | **Improper offboarding** | Identities outlive the workload or owner they served. | OWN-3, LIFE-2 |
| A9 | **Non-repudiation gap** | An action cannot be attributed to an actor. | AGENT-5, MON-1 |
| A10 | **Lateral movement via reuse** | A shared or cross-environment identity bridges blast radius. | CRED-4, AUTHZ-3 |
| A11 | **Runaway autonomous action** | An agent acts at speed and scale with no containment. | AGENT-8, AGENT-2, MON-4 |

**A5 and A6 are the ones classic NHI programs miss.** Both attack an agent's *reach* rather than
its credentials: every identity attribute — privilege, credential age, owner, tier — can look
unchanged while the agent's effective blast radius grows. That is why reach belongs in the
inventory as a first-class input, and why it needs diffing between scans rather than a
point-in-time check.

## 6. Maturity model

- **Level 1 — Ad hoc.** NHIs unmanaged; secrets long-lived and scattered; agents piloted without identity governance. No inventory, no tiering.
- **Level 2 — Managed.** Inventory and owners exist; secrets vaulted; access reviews manual and periodic. Agents recognized as identities.
- **Level 3 — Defined.** Tiering in place; least privilege and isolation enforced; JIT credentials; agentic controls implemented; monitoring active.
- **Level 4 — Optimized.** Lifecycle automated; entitlements continuously verified; autonomy dynamically bounded with real-time containment; measured and reported.

Regulated and high-autonomy environments should target Level 3+.

## 7. Operationalizing the framework

1. **Discover & inventory** every NHI and agent (D1).
2. **Assign owners** and **risk-tier** the fleet (D2, GOV-1). An open-source reference engine for tiering and OWASP NHI mapping is [nhi-scan](https://github.com/rpmsft9/nhi-scan).
3. **Remediate by tier** — start with Tier 1: kill long-lived admin secrets, right-size privilege, and bring autonomous agents under AGENT-1…8.
4. **Instrument** monitoring and containment (D7, AGENT-8).
5. **Govern** — map to your frameworks, set autonomy risk appetite, measure and report (D8).

## 8. Framework mapping summary

| Domain | OWASP NHI | NIST AI RMF | NIST CSF 2.0 | 800-53 families |
| --- | --- | --- | --- | --- |
| D1 Inventory | foundational; NHI1,3 | MAP | ID.AM, DE.CM | CM, CA, AC |
| D2 Ownership | NHI1 | MANAGE | GV.RR | AC, PS |
| D3 Credentials | NHI2,4,6,7,9 | — | PR.AA, PR.DS | IA, SC, AC |
| D4 Authorization | NHI3,5,8,10 | MANAGE | PR.AA, PR.IR, GV.SC, GV.RR, ID.AM | AC, SC, SR, CM, IA |
| D5 Lifecycle | NHI1,7 | MANAGE | GV.RR, PR.AA | AC, IA |
| D6 Agentic | NHI1,5,7 + LLM | GOVERN, MAP, MEASURE, MANAGE | GV.RR, PR.AA, DE.AE, RS.MI | AC, IA, AU, IR, SI |
| D7 Monitoring | NHI2,10 | MEASURE | DE.CM, DE.AE, RS.MA, RS.MI | AU, SI, IR, IA |
| D8 Governance | program-wide | GOVERN, MAP, MEASURE | GV.RM, GV.OC, GV.OV | CA, PM, RA |

## References

- OWASP — [Non-Human Identities Top 10](https://owasp.org/www-project-non-human-identities-top-10/)
- OWASP — [Top 10 for LLM Applications & Agentic Security Initiative](https://genai.owasp.org/)
- NIST — [AI Risk Management Framework (AI 100-1)](https://www.nist.gov/itl/ai-risk-management-framework)
- NIST — [Cybersecurity Framework 2.0](https://www.nist.gov/cyberframework)
- NIST — [SP 800-53 Rev 5](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final)
- Cloud Security Alliance — [Non-Human Identity & Agentic AI Governance](https://labs.cloudsecurityalliance.org/research/csa-whitepaper-nonhuman-identity-agentic-ai-governance-v1-cs/)
- Entro Labs — [NHI growth research, 2024→2025](https://www.cybersecuritytribe.com/news/research-reveals-44-growth-in-nhis-from-2024-to-2025)
- CyberArk — [2025 Identity Security Landscape](https://www.cyberark.com/press/machine-identities-outnumber-humans-by-more-than-80-to-1-new-report-exposes-the-exponential-threats-of-fragmented-identity-security/)

_Offered as a practitioner reference, not legal or compliance advice. Framework mappings are indicative and should be validated against the current text of each source and your own control environment._
