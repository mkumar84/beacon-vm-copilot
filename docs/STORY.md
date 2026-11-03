# Beacon: the story, with numbers you can quote

Seed is deterministic (`random.Random(20261102)`, explicit ordering, frozen-clock tests in `tests/test_story.py`).
The live demo resets every 12 hours (`DEMO_RESET_HOURS`), so what visitors see matches this file within a day.
Check `/api/demo` for the current seed timestamp.

## Time-stable figures (safe to cite without a date)
| Claim | Value |
|---|---|
| CVSS-Critical findings | 31 |
| Demoted below P0/P1 by context | 25 (80.6%) vs. a 30% bar |
| Hidden-risk findings promoted | 8 |
| Known-exploited AND internet-exposed | 5. Risk-based top 25 catches 5/5; a CVSS-only top 25 catches 1/5 |
| Model agreement with analysts | 71.7% all-time, 89.4% over the last 8 weeks (47 decisions) after the crown-jewel gate |
| Open tier mix at seed | P0 3, P1 11, P2 28, P3 62 (104 open) |
| Pending P0 approvals | 5 |
| Pen-test overdue | loyalty-app-android |
| Stale scan feed | db_scan |

## Narrative arcs
1. **Noise.** xz-utils at CVSS 10.0 on an isolated dev build box lands at P3 (score 33.6).
2. **Hidden risk.** HTTP/2 Rapid Reset at CVSS 7.5 on the payment gateway is P0 (score 95.3).
3. **Stuck P0s.** Three open P0s on POS regions, all owned by Store Systems Ops, 8/15/22 days past due. Store Systems Ops carries most of the overdue queue.
4. **Governance learned from overrides.** Analysts kept rejecting demotions on crown-jewel assets; that became a mandatory approval gate; agreement rose from 71.7% to 89.4%.
5. **Zero-day.** Fictional CVE-2026-99001 (libcartstream) to a ranked, owner-assigned list in seconds, with P0 actions held for approval.

## Time-drifting figures (cite with an "as of" date)
Overdue count, P0/P1 SLA %, posture grade (65.6 / D at seed), approval age. These worsen between resets by design.
