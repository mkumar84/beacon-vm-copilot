import asyncio
import os
from contextlib import asynccontextmanager

from datetime import timedelta

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import governance, reports, zeroday
from .db import Base, SessionLocal, engine, get_db
from .models import Asset, AuditEntry, Finding, Intel, Proposal, ZeroDayEvent, iso, now
from .seed import reset_and_seed, seed, seeded_at

DISCLAIMER = ("Maple & Main Retail is fictional. All assets, findings, owners and threat-intel flags are synthetic; "
              "CVE identifiers are real for readability. This product prioritizes and governs; it never scans or exploits.")


# Demo data is relative to "now", so it ages (feeds go stale, approvals pile up) and a visitor can
# empty the approvals inbox. Reset it on a schedule. DEMO_RESET_HOURS=0 disables (data then ages).
DEMO_RESET_HOURS = float(os.getenv("DEMO_RESET_HOURS", "12"))


def _refresh_demo_if_stale():
    """Seed an empty database, or reset demo data older than DEMO_RESET_HOURS."""
    with SessionLocal() as db:
        empty = db.execute(select(func.count(Asset.id))).scalar() == 0
        stamp = seeded_at(db)
        stale = DEMO_RESET_HOURS > 0 and (stamp is None or (now() - stamp).total_seconds() > DEMO_RESET_HOURS * 3600)
        if empty or stale:
            reset_and_seed(db)
            reports._brief_cache.update(ts=0, data=None)


async def _demo_reset_loop():
    while True:
        await asyncio.sleep(600)
        try:
            await asyncio.to_thread(_refresh_demo_if_stale)
        except Exception as exc:  # keep serving even if a reset fails
            print(f"demo reset failed: {exc}", flush=True)


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    if os.getenv("AUTO_SEED", "true").lower() == "true":
        await asyncio.to_thread(_refresh_demo_if_stale)
    task = asyncio.create_task(_demo_reset_loop()) if DEMO_RESET_HOURS > 0 else None
    yield
    if task:
        task.cancel()


app = FastAPI(title="Beacon: Vulnerability Management Copilot", version="1.0.0", lifespan=lifespan,
              description=DISCLAIMER)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ------------------------------------------------------------------ schemas
class StatusChange(BaseModel):
    status: str
    actor: str = Field(min_length=2)
    note: str = ""


class Decision(BaseModel):
    decision: str
    actor: str = Field(min_length=2)
    note: str = ""


class ZeroDayIn(BaseModel):
    cve: str
    title: str = Field(min_length=5)
    cvss: float = Field(ge=0, le=10)
    component: str = Field(min_length=2)
    summary: str = ""
    exploited_in_wild: bool = True
    exploit_probability: float = Field(default=0.8, ge=0, le=1)
    actor: str = Field(min_length=2)


def _guard(fn, *a, **kw):
    try:
        return fn(*a, **kw)
    except governance.GovernanceError as e:
        raise HTTPException(status_code=422, detail=str(e))


# ------------------------------------------------------------------- basics
@app.get("/")
def root():
    return {"name": "Beacon", "docs": "/docs", "disclaimer": DISCLAIMER}


@app.get("/health")
def health(db: Session = Depends(get_db)):
    n = db.execute(select(func.count(Finding.id))).scalar()
    return {"status": "ok", "findings": n, "time": iso(now())} | _demo_info(db)


def _demo_info(db):
    stamp = seeded_at(db)
    nxt = stamp + timedelta(hours=DEMO_RESET_HOURS) if (stamp and DEMO_RESET_HOURS > 0) else None
    return {"demo_seeded_at": iso(stamp), "demo_next_reset_at": iso(nxt), "demo_reset_every_hours": DEMO_RESET_HOURS}


@app.get("/api/demo")
def demo_info(db: Session = Depends(get_db)):
    """When the synthetic data was generated and when it will next reset."""
    return _demo_info(db)


@app.get("/api/scorecard")
def scorecard(db: Session = Depends(get_db)):
    return reports.scorecard(db)


@app.get("/api/brief")
def brief(refresh: bool = False, db: Session = Depends(get_db)):
    return reports.brief(db, force=refresh)


@app.get("/api/compare")
def compare(capacity: int = Query(25, ge=5, le=100), db: Session = Depends(get_db)):
    return reports.compare_prioritization(db, capacity)


# ------------------------------------------------------------------- assets
@app.get("/api/assets")
def assets(db: Session = Depends(get_db)):
    rows = db.execute(select(Asset).order_by(Asset.name)).scalars().all()
    open_counts = dict(db.execute(select(Finding.asset_id, func.count(Finding.id)).where(
        Finding.status.in_(reports.OPEN)).group_by(Finding.asset_id)).all())
    return [a.as_dict() | {"open_findings": open_counts.get(a.id, 0)} for a in rows]


# ----------------------------------------------------------------- findings
@app.get("/api/findings")
def findings(tier: str | None = None, status: str | None = None, source: str | None = None,
             team: str | None = None, overdue: bool | None = None, awaiting_approval: bool | None = None,
             q: str | None = None, sort: str = "score", limit: int = Query(50, ge=1, le=500), offset: int = 0,
             db: Session = Depends(get_db)):
    stmt = select(Finding)
    if tier:
        stmt = stmt.where(Finding.tier == tier.upper())
    if status:
        stmt = stmt.where(Finding.status == status)
    else:
        stmt = stmt.where(Finding.status.in_(reports.OPEN))
    if source:
        stmt = stmt.where(Finding.source == source)
    if team:
        stmt = stmt.where(Finding.owner_team == team)
    if awaiting_approval is not None:
        stmt = stmt.where(Finding.awaiting_approval == awaiting_approval)
    if overdue:
        stmt = stmt.where(Finding.due_date < now())
    if q:
        stmt = stmt.where(Finding.title.ilike(f"%{q}%") | Finding.cve.ilike(f"%{q}%"))
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar()
    order = {"score": Finding.score.desc(), "cvss": Finding.cvss.desc(), "due": Finding.due_date.asc(),
             "age": Finding.first_seen.asc()}.get(sort, Finding.score.desc())
    rows = db.execute(stmt.order_by(order, Finding.id).limit(limit).offset(offset)).scalars().all()
    amap = {a.id: a for a in db.execute(select(Asset)).scalars()}
    imap = {i.cve: i for i in db.execute(select(Intel)).scalars()}
    return {"total": total, "items": [f.as_dict(asset=amap[f.asset_id], intel=imap.get(f.cve)) for f in rows]}


@app.get("/api/findings/{finding_id}")
def finding_detail(finding_id: int, db: Session = Depends(get_db)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    props = db.execute(select(Proposal).where(Proposal.finding_id == f.id).order_by(Proposal.id)).scalars().all()
    trail = db.execute(select(AuditEntry).where(
        ((AuditEntry.entity == "finding") & (AuditEntry.entity_id == str(f.id))) |
        ((AuditEntry.entity == "proposal") & (AuditEntry.entity_id.in_([str(p.id) for p in props]) if props else False))
    ).order_by(AuditEntry.id)).scalars().all()
    return f.as_dict(asset=db.get(Asset, f.asset_id), intel=db.get(Intel, f.cve) if f.cve else None) | {
        "proposals": [p.as_dict() for p in props], "audit_trail": [e.as_dict() for e in trail]}


@app.post("/api/findings/{finding_id}/status")
def change_status(finding_id: int, body: StatusChange, db: Session = Depends(get_db)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    result = _guard(governance.set_status, db, f, body.status, body.actor, body.note)
    db.commit()
    if isinstance(result, Proposal):
        return {"result": "approval_required", "proposal": result.as_dict()}
    return {"result": "updated", "finding": f.as_dict()}


@app.post("/api/findings/{finding_id}/rescore")
def rescore(finding_id: int, db: Session = Depends(get_db)):
    f = db.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    p = governance.rescore_finding(db, f)
    db.commit()
    return {"finding": f.as_dict(), "proposal": p.as_dict() if p else None}


# --------------------------------------------------------------- governance
@app.get("/api/governance/proposals")
def proposals(status: str | None = "pending", limit: int = Query(100, ge=1, le=500), db: Session = Depends(get_db)):
    stmt = select(Proposal)
    if status and status != "all":
        stmt = stmt.where(Proposal.status == status)
    rows = db.execute(stmt.order_by(Proposal.created_at.desc()).limit(limit)).scalars().all()
    fmap = {f.id: f for f in db.execute(select(Finding).where(Finding.id.in_([p.finding_id for p in rows]))).scalars()} if rows else {}
    amap = {a.id: a for a in db.execute(select(Asset)).scalars()}
    out = []
    for p in rows:
        f = fmap[p.finding_id]
        a = amap[f.asset_id]
        out.append(p.as_dict() | {"finding": {"id": f.id, "title": f.title, "cve": f.cve, "cvss": f.cvss, "score": f.score,
                                              "tier": f.tier, "ai_tier": f.ai_tier, "rationale": f.rationale,
                                              "asset": a.name, "owner_team": a.owner_team,
                                              "internet_facing": a.internet_facing, "pci_scope": a.pci_scope,
                                              "crown_jewel": a.crown_jewel}})
    return out


@app.post("/api/governance/proposals/{proposal_id}/decision")
def decide(proposal_id: int, body: Decision, db: Session = Depends(get_db)):
    p = db.get(Proposal, proposal_id)
    if not p:
        raise HTTPException(404, "Proposal not found")
    _guard(governance.decide, db, p, body.decision, body.actor, body.note)
    db.commit()
    f = db.get(Finding, p.finding_id)
    return {"proposal": p.as_dict(), "finding": f.as_dict()}


class BulkDecision(BaseModel):
    proposal_ids: list[int] = Field(min_length=1, max_length=50)
    decision: str
    actor: str = Field(min_length=2)
    note: str = ""


@app.post("/api/governance/proposals/bulk")
def bulk_decide(body: BulkDecision, db: Session = Depends(get_db)):
    """Batch decision (e.g. one zero-day across many assets). Each item is still decided and audited individually."""
    done, failed = [], []
    for pid in body.proposal_ids:
        p = db.get(Proposal, pid)
        if not p:
            failed.append({"id": pid, "error": "not found"})
            continue
        try:
            governance.decide(db, p, body.decision, body.actor, body.note)
            done.append(pid)
        except governance.GovernanceError as e:
            failed.append({"id": pid, "error": str(e)})
    db.commit()
    return {"decided": done, "failed": failed}


@app.get("/api/governance/model-health")
def model_health(db: Session = Depends(get_db)):
    return reports.model_health(db)


# ---------------------------------------------------------------- audit log
@app.get("/api/audit")
def audit_log(action: str | None = None, entity: str | None = None, limit: int = Query(50, ge=1, le=500),
              db: Session = Depends(get_db)):
    stmt = select(AuditEntry)
    if action:
        stmt = stmt.where(AuditEntry.action == action)
    if entity:
        stmt = stmt.where(AuditEntry.entity == entity)
    rows = db.execute(stmt.order_by(AuditEntry.id.desc()).limit(limit)).scalars().all()
    return [e.as_dict() for e in rows]


@app.get("/api/audit/verify")
def audit_verify(db: Session = Depends(get_db)):
    return governance.verify_chain(db)


# ----------------------------------------------------------------- zero-day
@app.get("/api/zeroday/sample")
def zeroday_sample():
    return zeroday.SAMPLE


@app.get("/api/zeroday/preview")
def zeroday_preview(component: str, cvss: float = 9.8, db: Session = Depends(get_db)):
    return zeroday.preview(db, component, cvss)


@app.get("/api/zeroday/events")
def zeroday_events(db: Session = Depends(get_db)):
    rows = db.execute(select(ZeroDayEvent).order_by(ZeroDayEvent.created_at.desc())).scalars().all()
    return [{"cve": e.cve, "title": e.title, "cvss": e.cvss, "component": e.component, "declared_at": iso(e.created_at),
             "declared_by": e.created_by, "assets_matched": e.assets_matched, "findings_created": e.findings_created,
             "elapsed_ms": e.elapsed_ms} for e in rows]


@app.post("/api/zeroday")
def zeroday_declare(body: ZeroDayIn, db: Session = Depends(get_db)):
    try:
        return zeroday.declare(db, body.model_dump(), body.actor)
    except ValueError as e:
        raise HTTPException(422, str(e))


@app.get("/api/zeroday/{cve}/exposure")
def zeroday_exposure(cve: str, db: Session = Depends(get_db)):
    data = zeroday.exposure(db, cve.upper())
    if not data:
        raise HTTPException(404, "No zero-day event for that CVE")
    return data


# --------------------------------------------------------- pen tests/sources
@app.get("/api/pentests")
def pentests(db: Session = Depends(get_db)):
    return reports.pentest_status(db)


@app.get("/api/sources")
def sources(db: Session = Depends(get_db)):
    return reports.source_health(db)


# ----------------------------------------------------------------- evidence
@app.get("/api/evidence/pci")
def evidence(format: str = Query("json", pattern="^(json|csv)$"), db: Session = Depends(get_db)):
    data = reports.evidence_pci(db, format)
    if format == "csv":
        return PlainTextResponse(data, media_type="text/csv",
                                 headers={"Content-Disposition": "attachment; filename=pci-evidence.csv"})
    return data


# -------------------------------------------------------------------- admin
@app.post("/api/admin/reseed")
def reseed(x_admin_token: str | None = Header(default=None)):
    token = os.getenv("ADMIN_TOKEN")
    if not token or x_admin_token != token:
        raise HTTPException(403, "Reseed disabled or token invalid")
    with SessionLocal() as db:
        result = reset_and_seed(db)
    reports._brief_cache.update(ts=0, data=None)
    return {"status": "reseeded", **result}
