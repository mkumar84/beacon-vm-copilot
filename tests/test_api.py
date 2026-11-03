import time

import pytest

from app.db import SessionLocal
from app.models import AuditEntry


def test_health_and_disclaimer(client):
    assert client.get("/health").json()["status"] == "ok"
    assert "fictional" in client.get("/").json()["disclaimer"]


def test_every_finding_has_rationale_and_sla(client):
    items = client.get("/api/findings?limit=500&status=open").json()["items"]
    items += client.get("/api/findings?limit=500&status=in_remediation").json()["items"]
    assert items
    assert all(f["rationale"] and f["due_date"] and f["factors"] for f in items)


def test_scorecard_shape(client):
    sc = client.get("/api/scorecard").json()
    for key in ("posture", "open", "sla", "threat", "governance", "pentest", "coverage", "prioritization"):
        assert key in sc
    assert len(sc["posture"]["trend"]) == 12
    assert sc["pentest"]["overdue"], "seeded story: one overdue pen test"
    assert any(s["status"] == "stale" for s in sc["coverage"]), "seeded story: stale DB scan feed"


# ---------------------------------------------------------------- quality bars
def test_bar_noise_reduction(client):
    s = client.get("/api/compare").json()["summary"]
    assert s["noise_reduction_pct"] >= 30


def test_bar_hidden_risk_recovered(client):
    s = client.get("/api/compare").json()["summary"]
    assert s["known_exploited_exposed"] > 0
    assert s["known_exploited_exposed_in_p0_p1"] == s["known_exploited_exposed"]
    assert s["real_risk_in_top_risk_based"] > s["real_risk_in_top_cvss_only"]


def test_bar_model_agreement_recent(client):
    mh = client.get("/api/governance/model-health").json()
    assert mh["recent_8w_agreement_pct"] >= 85
    assert mh["agreement_pct"] < mh["recent_8w_agreement_pct"], "policy change improved agreement"


def test_bar_audit_chain_verifies(client):
    v = client.get("/api/audit/verify").json()
    assert v["valid"] and v["entries"] > 100


# ------------------------------------------------------------------ governance
def _pending_p0(client):
    return [p for p in client.get("/api/governance/proposals?status=pending").json() if p["to_tier"] == "P0"]


def test_p0_candidates_enter_at_p1_until_approved(client):
    pend = _pending_p0(client)
    assert pend
    f = pend[0]["finding"]
    assert f["ai_tier"] == "P0" and f["tier"] == "P1"


def test_decision_requires_actor_and_note_on_reject(client):
    pid = _pending_p0(client)[0]["id"]
    r = client.post(f"/api/governance/proposals/{pid}/decision", json={"decision": "reject", "actor": "t.user", "note": ""})
    assert r.status_code == 422
    r = client.post(f"/api/governance/proposals/{pid}/decision", json={"decision": "approve", "actor": "x", "note": ""})
    assert r.status_code == 422  # actor too short (schema)


def test_approval_promotes_and_is_audited(client):
    p = _pending_p0(client)[0]
    r = client.post(f"/api/governance/proposals/{p['id']}/decision",
                    json={"decision": "approve", "actor": "t.approver", "note": "Confirmed exposure"})
    assert r.status_code == 200
    assert r.json()["finding"]["tier"] == "P0"
    detail = client.get(f"/api/findings/{p['finding_id']}").json()
    assert any(e["action"] == "proposal_approved" and e["actor"] == "t.approver" for e in detail["audit_trail"])
    assert client.post(f"/api/governance/proposals/{p['id']}/decision",
                       json={"decision": "approve", "actor": "t.approver", "note": "again"}).status_code == 422


def test_rejection_keeps_p1(client):
    pend = _pending_p0(client)
    p = pend[0]
    r = client.post(f"/api/governance/proposals/{p['id']}/decision",
                    json={"decision": "reject", "actor": "t.reviewer", "note": "Virtual patch in place"})
    assert r.json()["finding"]["tier"] == "P1"
    assert r.json()["finding"]["awaiting_approval"] is False


def test_risk_acceptance_needs_justification_and_approval(client):
    f = client.get("/api/findings?tier=P2&limit=1").json()["items"][0]
    bad = client.post(f"/api/findings/{f['id']}/status", json={"status": "risk_accepted", "actor": "t.owner", "note": "no"})
    assert bad.status_code == 422
    ok = client.post(f"/api/findings/{f['id']}/status",
                     json={"status": "risk_accepted", "actor": "t.owner", "note": "Isolated lab network, decommission in Q1"})
    assert ok.json()["result"] == "approval_required"
    pid = ok.json()["proposal"]["id"]
    assert client.get(f"/api/findings/{f['id']}").json()["status"] != "risk_accepted"  # not yet
    client.post(f"/api/governance/proposals/{pid}/decision",
                json={"decision": "approve", "actor": "t.ciso", "note": "Accepted until Q1 decommission"})
    assert client.get(f"/api/findings/{f['id']}").json()["status"] == "risk_accepted"


def test_tampering_breaks_chain(client):
    assert client.get("/api/audit/verify").json()["valid"]
    with SessionLocal() as db:
        e = db.get(AuditEntry, 5)
        original = dict(e.detail)
        e.detail = {**original, "tampered": True}
        db.commit()
    broken = client.get("/api/audit/verify").json()
    assert broken["valid"] is False and broken["broken_at"] == 5
    with SessionLocal() as db:
        db.get(AuditEntry, 5).detail = original
        db.commit()
    assert client.get("/api/audit/verify").json()["valid"]


# -------------------------------------------------------------------- zero-day
def test_zeroday_end_to_end(client):
    sample = client.get("/api/zeroday/sample").json()
    pv = client.get("/api/zeroday/preview", params={"component": sample["component"]}).json()
    assert pv["assets_matched"] >= 8
    t0 = time.perf_counter()
    r = client.post("/api/zeroday", json=sample | {"actor": "t.lead"})
    assert time.perf_counter() - t0 < 60  # quality bar
    assert r.status_code == 200
    d = r.json()
    assert d["summary"]["assets_exposed"] == pv["assets_matched"]
    assert d["summary"]["p0_candidates"] > 0
    assert d["summary"]["pending_approval"] == d["summary"]["p0_candidates"]
    scores = [f["score"] for f in d["exposure"]]
    assert scores == sorted(scores, reverse=True)
    assert all(f["owner_team"] for f in d["exposure"])
    again = client.post("/api/zeroday", json=sample | {"actor": "t.lead"}).json()
    assert again["already_declared"] is True
    assert again["summary"]["assets_exposed"] == d["summary"]["assets_exposed"]


def test_zeroday_validates_cve(client):
    r = client.post("/api/zeroday", json={"cve": "not-a-cve", "title": "bad input here", "cvss": 9.0,
                                          "component": "nginx", "actor": "t.lead"})
    assert r.status_code == 422


# -------------------------------------------------------------- evidence/brief
def test_evidence_export(client):
    j = client.get("/api/evidence/pci").json()
    assert j["meta"]["audit_chain"]["valid"] and j["findings"]
    csv_text = client.get("/api/evidence/pci?format=csv").text
    assert csv_text.splitlines()[0].startswith("finding_id,asset")


def test_brief_numbers_are_grounded(client):
    b = client.get("/api/brief?refresh=true").json()
    assert b["source"] in ("template", "llm") and b["numbers_validated"] is True
    assert str(b["facts"]["open_p0"]) in b["narrative"]


def test_bulk_decision_audits_each_item(client):
    props = [p for p in client.get("/api/governance/proposals?status=pending").json() if p["finding"]["cve"] == "CVE-2026-99001"]
    if not props:
        pytest.skip("zero-day not declared yet")
    ids = [p["id"] for p in props[:3]]
    r = client.post("/api/governance/proposals/bulk", json={"proposal_ids": ids, "decision": "approve",
                                                           "actor": "t.lead", "note": "Zero-day confirmed in telemetry"}).json()
    assert sorted(r["decided"]) == sorted(ids) and not r["failed"]
    again = client.post("/api/governance/proposals/bulk", json={"proposal_ids": ids[:1], "decision": "approve",
                                                               "actor": "t.lead", "note": "x"}).json()
    assert again["failed"]
    assert client.get("/api/audit/verify").json()["valid"]
