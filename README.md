# Beacon: Risk-Based Vulnerability Management Copilot

A working product prototype for a **fictional retailer, Maple & Main Retail**, built to show how an enterprise
Threat & Vulnerability Management leader would run one governed vulnerability lifecycle:
identify, prioritize, report, govern remediation, and monitor compliance, with AI where it helps and a human where it matters.

> Everything here is synthetic. CVE identifiers are real for readability, but assets, owners, findings and all
> threat-intel flags are simulated. The zero-day demo uses a fictional CVE and component. The product prioritizes
> and governs; it never scans or exploits anything.

Read the product thinking first: [`docs/PRD.md`](docs/PRD.md).

## What it does

| Capability | Endpoint |
|---|---|
| Executive scorecard: posture grade, 12-week trend, SLA, overdue by team, KEV exposure, pen-test coverage, scan-source health | `GET /api/scorecard` |
| Explainable prioritization: every finding carries a score, factor breakdown and plain-English rationale | `GET /api/findings`, `GET /api/findings/{id}` |
| CVSS-only vs risk-based queue (the core value proof) | `GET /api/compare` |
| Zero-day console: blast-radius preview, declare, ranked exposure by owner | `GET /api/zeroday/preview`, `POST /api/zeroday`, `GET /api/zeroday/{cve}/exposure` |
| Human-in-the-loop approvals (P0 promotion, risky demotions, risk acceptance), single and bulk | `GET /api/governance/proposals`, `POST .../{id}/decision`, `POST .../bulk` |
| Model health: agreement and override rate, trend, rejection reasons | `GET /api/governance/model-health` |
| Tamper-evident audit log (hash chain) and verification | `GET /api/audit`, `GET /api/audit/verify` |
| PCI evidence export (JSON or CSV) with approvals and audit-chain status | `GET /api/evidence/pci?format=csv` |
| Executive brief: LLM drafts from computed facts only; numbers validated, template fallback | `GET /api/brief` |
| Pen-test coverage and scan-source health | `GET /api/pentests`, `GET /api/sources` |

## Design decisions worth knowing

- **Risk engine is transparent on purpose.** Score = severity + threat intel + exposure + business context. A learned model is a roadmap item that must be earned from analyst decisions (see PRD section 5).
- **Autonomy matches risk.** Tiers P1-P3 are scored automatically. Promotion to P0, demotion of exposed/PCI/crown-jewel findings, and risk acceptance all need a named human. P0 candidates enter at P1 until approved.
- **The LLM never produces numbers.** The brief is drafted from computed facts; if the model emits a number that is not in the facts, the response is rejected and a template is used. Set `ANTHROPIC_API_KEY` to enable it (`BRIEF_MODEL` optional).
- **Audit log is hash-chained.** Editing any past entry breaks verification.

## Run locally

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload        # SQLite by default; seeds on first start
pytest                               # 22 tests, including the PRD quality bars
```

Postgres: set `DATABASE_URL`. Disable auto-seed with `AUTO_SEED=false`. `POST /api/admin/reseed` requires an `ADMIN_TOKEN` env var and matching `X-Admin-Token` header.

## Known limitations (prototype)

- Single tenant, no authentication; CORS is open for the demo frontend.
- Audit chain assumes a single writer; production would serialize writes or use a ledger store.
- Scoring weights are hand-set and documented in `app/scoring.py`; they have not been validated against real incident data.
- Seeded data is designed to exhibit the problem (noise, hidden risk, SLA breach, stale feed), so headline percentages illustrate the mechanism, not real-world benchmarks.
