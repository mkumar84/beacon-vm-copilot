"""The seeded story is part of the product's proof. These tests keep it stable and deterministic.

They build their own in-memory database and freeze the clock, so they do not depend on
(or disturb) the shared database used by test_api.py.
"""
import json
from datetime import datetime

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.governance as governance
import app.models as models
import app.reports as reports
import app.seed as seed_mod
from app.db import Base
from app.models import Finding

FROZEN = datetime(2026, 11, 3, 12, 0, 0)


def _build(monkeypatch):
    for mod in (models, governance, reports, seed_mod):
        monkeypatch.setattr(mod, "now", lambda: FROZEN)
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)()
    seed_mod.seed(db)
    return db


def _fingerprint(db):
    sc = reports.scorecard(db)
    mh = reports.model_health(db)
    chain = governance.verify_chain(db)
    open_ids = [f.id for f in db.execute(select(Finding).order_by(Finding.id)).scalars() if f.status in reports.OPEN]
    return json.dumps({"sc": sc, "mh": mh, "chain_head": chain["head"], "open_ids": open_ids}, sort_keys=True, default=str)


def test_seed_is_deterministic(monkeypatch):
    a = _fingerprint(_build(monkeypatch))
    b = _fingerprint(_build(monkeypatch))
    assert a == b


def test_story_invariants(monkeypatch):
    db = _build(monkeypatch)
    sc = reports.scorecard(db)
    cmp_ = sc["prioritization"]

    # 1. Noise: most CVSS-Critical findings are not real risk
    assert cmp_["cvss_critical_demoted"] / cmp_["cvss_critical_open"] >= 0.5
    # 2. Hidden risk: risk-based queue finds every exploited-and-exposed finding; CVSS-only misses most
    assert cmp_["known_exploited_exposed"] >= 4
    assert cmp_["real_risk_in_top_risk_based"] == cmp_["known_exploited_exposed"]
    assert cmp_["real_risk_in_top_cvss_only"] <= cmp_["known_exploited_exposed"] // 2
    # 3. SLA breach: open approved P0s are stuck with Store Systems Ops, past due
    p0 = [f for f in db.execute(select(Finding)).scalars()
          if f.status in reports.OPEN and f.tier == "P0"]
    assert len(p0) >= 2
    assert all(f.owner_team == "Store Systems Ops" and f.due_date < FROZEN for f in p0)
    assert sc["sla"]["overdue_by_team"][0]["team"] == "Store Systems Ops"
    # 4. Human gate: fresh P0 candidates wait for approval
    assert sc["governance"]["pending_p0"] >= 4
    # 5. Coverage gaps
    assert [s["name"] for s in sc["coverage"] if s["status"] == "stale"] == ["db_scan"]
    assert [p["asset"] for p in sc["pentest"]["overdue"]] == ["loyalty-app-android"]
    # 6. Governance learning: agreement improved after the policy change
    mh = reports.model_health(db)
    assert mh["recent_8w_agreement_pct"] >= 85 > mh["agreement_pct"]
    # 7. Audit chain intact
    assert governance.verify_chain(db)["valid"]
