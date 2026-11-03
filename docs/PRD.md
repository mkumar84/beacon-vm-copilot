# PRD: Beacon — Risk-Based Vulnerability Management Copilot

**Company (fictional):** Maple & Main Retail — 140 stores, e-commerce, loyalty app, card payments in PCI scope
**Owner:** Product (Director, Threat & Vulnerability Management Platforms)
**Status:** v1 prototype, synthetic data only
**Framing lens:** Frame → Design with intent → Prove it → Earn the scale

---

## 1. Frame the problem

### The problem
Maple & Main's security team tracks a few hundred findings (about 110 open at any time in this prototype) from six scanner types (internal, external, database, SAST/DAST/SCA, mobile). Scanners rank by CVSS. CVSS measures severity in a vacuum, not risk to *this* business. Result:

- **Noise:** Most "Critical" findings sit on isolated or low-sensitivity assets with no sign of exploitation, yet they consume the same remediation capacity as real exposure.
- **Hidden risk:** Medium-CVSS findings on internet-facing, PCI-scoped systems that attackers are *actively exploiting* sit in the middle of the queue.
- **Slow zero-day response:** When a new CVE drops, answering "which of our assets are exposed and who owns them?" takes hours of spreadsheet work.
- **Weak assurance:** Executives get static counts, auditors and PCI assessors ask for evidence that takes days to assemble, and nobody can show *why* a given item was prioritized.

### Who it is for
| Persona | Job to be done |
|---|---|
| **AVP, Threat & Vulnerability Management (primary)** | Run one enterprise vulnerability lifecycle: identify, prioritize, report, govern remediation, monitor compliance |
| **Remediation owners (store systems, e-commerce, data platform, mobile)** | Know what to fix first, why, and by when |
| **CISO / executive committee** | See posture trend and exposure in one page; trust the numbers |
| **Audit, PCI QSA, regulators, enterprise clients** | Get evidence fast, with an auditable decision trail |

### Outcome (what "good" looks like)
Reduce the time and effort between "a vulnerability exists" and "the right owner is fixing the right thing," while keeping every consequential decision explainable and human-governed.

### Constraints
- PCI DSS scope (payment systems, cardholder data stores)
- Remediation capacity is finite; prioritization must respect it
- Every AI-influenced decision must be explainable and auditable
- Synthetic data only; the product prioritizes and governs, it never exploits

---

## 2. Role-to-product mapping

This prototype is built against the responsibilities of an enterprise Threat & Vulnerability Management leader.

| Role responsibility | Product capability |
|---|---|
| Enterprise vulnerability lifecycle: identification, prioritization, reporting, remediation governance, compliance monitoring | Findings ledger with lifecycle states, risk engine, SLA clock, overdue escalation by owner |
| Internal and external scanning, database scanning | Multi-source ingestion model (internal, external, database) with source-level coverage view |
| Application security scanning: static, dynamic, software composition, mobile | SAST / DAST / SCA / mobile finding sources unified into one queue |
| Security scorecard monitoring | External attack-surface trend and grade on the executive scorecard |
| Threat-intel-driven vulnerability monitoring | Intel enrichment (known-exploited flag, exploit probability, active campaigns) drives priority |
| Classification and zero-day response | Zero-day workflow: new CVE → exposed assets → owners → P0 proposals awaiting approval |
| Audit, client and regulatory responses | Evidence export (PCI-scope findings with SLA state and decision trail) |
| Management of VM platforms | Source/coverage health and data-freshness indicators |
| Senior leadership and executive reporting | One-page scorecard, trend, and an AI-drafted executive brief |
| Penetration testing of critical applications annually | Pen-test coverage tracker with overdue flags |
| Govern maturity, drive AI-assisted remediation and testing | Governed AI: human approval gates, model-health tracking, override analytics |

---

## 3. Design with intent

### Where AI acts, and where a human stays in control
Autonomy is matched to risk, not ambition.

| Decision | Who decides | Rationale |
|---|---|---|
| Score and tier P1–P3 findings, set SLA clock | **Risk engine, automatically** | High volume, low individual blast radius, fully explainable |
| Promote any finding to **P0** | **Engine proposes, human approves** | P0 triggers an emergency change; wrong calls are expensive |
| Demote any finding that is internet-facing, PCI-scoped, or on a crown-jewel asset | **Engine proposes, human approves** | Under-reaction on critical assets is the costly error |
| Accept risk on a finding | **Human approval required** | Policy and accountability decision |
| Zero-day exposure ranking | **Engine automatically; P0 actions need approval** | Speed matters, commitment needs a person |
| Executive brief wording | **LLM drafts from computed facts only** | Narrative, not numbers; numbers are never model-generated |

### Risk engine (v1): transparent by design
A weighted, explainable score from 0–100:

- Technical severity (CVSS)
- Threat intelligence: known-exploited flag, exploit probability, public exploit availability, active campaign
- Exposure: internet-facing
- Business context: PCI scope, crown-jewel asset, asset criticality

Every finding carries a plain-English rationale listing the factors that moved it. v1 is deliberately **not a black box**: explainability is what lets an assessor, an executive, and a remediation owner all trust it. A learned model is a Phase 3 decision that must be earned (see section 5).

### Architecture
- **Backend (Railway):** FastAPI service plus Postgres. Findings, assets, intel, proposals, pen-tests, and a hash-chained audit log.
- **Frontend (Lovable):** Executive scorecard, prioritized queue with rationale, zero-day console, governance inbox, audit and evidence views.
- **Audit log:** Append-only and hash-chained, so tampering is detectable. A verification endpoint proves integrity.

---

## 4. Prove it, don't assume it

### Quality bars (decided before building)
| Metric | Bar | How it is measured in the prototype |
|---|---|---|
| **Noise reduction** | At least 30% of CVSS-Critical items correctly demoted below P0/P1 | Comparison endpoint: CVSS-only queue vs. risk-based queue |
| **Hidden-risk recovery** | 100% of known-exploited findings on exposed assets land in P0/P1 | Computed check on seeded data |
| **Zero-day time-to-exposure-list** | Under 60 seconds from CVE entry to ranked, owner-assigned list | Zero-day endpoint latency and output |
| **SLA compliance (P0/P1)** | At least 90% | Scorecard |
| **Pen-test coverage (critical apps)** | 100% within 12 months | Pen-test tracker |
| **Decision explainability** | 100% of findings carry a rationale; 100% of approvals carry an actor and note | Test suite |
| **Audit integrity** | Audit chain verifies end to end | Verification endpoint |
| **Model agreement with analysts** | At least 85% of AI proposals approved without change (trailing 8 weeks) | Model-health panel |

### Feedback loop after launch
- Every analyst approval or rejection is a labeled outcome.
- Rejections are reviewed weekly; a repeated rejection pattern becomes a **policy change** (for example, the seeded story where analysts kept rejecting demotions on crown-jewel assets, which led to a mandatory approval gate).
- Model-health panel tracks agreement rate, override rate by tier, and drift over time.

### Test suite
Automated tests cover scoring behavior, policy gates, SLA clocks, zero-day matching, audit-chain integrity, and the quality bars above.

---

## 5. Earn the scale

### Roadmap
| Phase | Scope | Gate to enter |
|---|---|---|
| **v1 (this prototype)** | Transparent risk engine, governed workflow, zero-day console, scorecard, evidence export | Quality bars above met on synthetic data |
| **v2** | Real scanner connectors, CMDB owner sync, ticketing integration, SLA escalation notifications | 90 days of agreement rate at or above 85% on a pilot business unit |
| **v3** | Learned prioritization model trained on analyst decisions; AI-assisted remediation suggestions (patch PRs, config fixes) behind approval gates | Override rate below 10% for two consecutive quarters; model-risk review passed |
| **v4** | Autonomous remediation for low-tier, high-confidence fixes with automatic rollback | Demonstrated safe v3 operation; change-management sign-off |

### What this prototype does not claim
- It does not scan anything. All findings, assets, and intel are synthetic.
- Real CVE identifiers appear for realism; threat-intel flags and probabilities shown are simulated.
- The zero-day scenario uses a fictional CVE and component.
- It never generates or runs exploit code.

---

## 6. Non-goals (v1)
- Replacing scanners
- Patch deployment
- Full SOC / SIEM functionality
- Multi-tenant access control (single-tenant demo)

## 7. Risks and mitigations
| Risk | Mitigation |
|---|---|
| Engine over-demotes real risk | Hard approval gate on demotion of exposed, PCI, or crown-jewel items |
| Analysts rubber-stamp approvals | Override and time-to-decision analytics; sampling review |
| Executive brief hallucinates numbers | LLM receives computed facts only; template fallback if unavailable |
| Audit log tampering | Hash chain with verification endpoint |
| Scope creep into a scanner | Explicit non-goal; ingestion contract only |
