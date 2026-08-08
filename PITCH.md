# Why nhi-scan

**The enterprise's largest identity population is the one nobody governs — and AI agents just made it urgent.**

## The problem, in numbers

Non-human identities (NHIs) — service accounts, API keys, OAuth apps, service principals,
workload identities, CI/CD tokens, and now **AI agents** — have quietly become the dominant
identity population in every enterprise:

- **82 to 1.** Machine identities outnumber human identities by more than 82:1, per the
  [CyberArk 2025 Identity Security Landscape Study](https://www.cyberark.com/press/machine-identities-outnumber-humans-by-more-than-80-to-1-new-report-exposes-the-exponential-threats-of-fragmented-identity-security/).
  In cloud-native environments the ratio runs far higher.
- **+44% in one year.** The NHI population grew 44% between 2024 and 2025, with the
  cloud-native ratio climbing from 92:1 to 144:1, per
  [Entro Labs H1 2025 research](https://www.cybersecuritytribe.com/news/research-reveals-44-growth-in-nhis-from-2024-to-2025).
- **A governance vacuum.** The Cloud Security Alliance now treats NHI and agentic-AI identity
  as a distinct governance gap in its
  [Non-Human Identity & Agentic AI Governance research](https://labs.cloudsecurityalliance.org/research/csa-whitepaper-nonhuman-identity-agentic-ai-governance-v1-cs/).

We spent twenty years perfecting the *human* identity lifecycle — provisioning, MFA, access
reviews, offboarding. NHIs get a fraction of that rigor: no consistent owner, static secrets
that were minted years ago and never rotated, wildcard scopes, and no offboarding when the
workload they served is gone.

## Why AI agents make it urgent

An AI agent is a non-human identity with a dangerous new property: **autonomy**. It
authenticates, holds privileges, and *acts* — increasingly without a human approving each
action. A privileged, autonomous agent with a long-lived secret in production is a credential
that can reason its way into places a static service account never could. The identity
questions don't change — who owns it, what can it reach, how does it authenticate, when is it
revoked — but the blast radius does.

## What the market is missing

Discovery and secret-scanning tools answer *how many* credentials you have. A security leader
needs the next two answers:

1. **Which ones are crown jewels?**
2. **What do I fix first?**

Almost nothing yet treats an **autonomous agent as a first-class identity** that needs a risk
tier, an owner, least privilege, short-lived credentials, and a kill switch.

## What nhi-scan does

`nhi-scan` is the prioritization layer:

- **Deterministic risk-tiering (Tier 1–4)** from real posture — privilege, credential
  longevity, ownership, exposure, and **autonomy**. Every tier is explainable ("why is this
  Tier 1?") and reproducible, because the rules are pure functions of the inventory. No LLM in
  the verdict path.
- **OWASP NHI Top 10 mapping** — ten posture checks emit findings tied to NHI1–NHI10, each
  with concrete evidence and a least-privilege remediation, over a versioned content layer.
- **Agent-aware by design** — autonomous agents with elevated privilege surface as crown
  jewels, the gap classic scanners don't model.

It runs locally, has zero core dependencies, and ships with a worked example and a full test
suite. It's deliberately small and readable: the tiering and check logic *is* a control model
you can adapt to your own standard.

## Who it's for

Security leaders and platform teams who need to move from "we have thousands of secrets and
service accounts" to "here are our 12 crown-jewel non-human identities and the fix order" —
and who are starting to ask the same questions about their AI agents.

---

*Built by [Raj Penchala](https://rajpenchala.com) — identity security leader working at the
intersection of IAM and AI. See also [mcp-triage](https://github.com/rpmsft9/mcp-triage) for
MCP security triage and governance.*
