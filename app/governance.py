"""Governance: policy gates, human-in-the-loop proposals, hash-chained audit log."""
import hashlib
import json
from datetime import timedelta

from sqlalchemy import select

from .models import Asset, AuditEntry, Finding, Intel, Proposal, now
from .scoring import SLA_DAYS, TIER_RANK, score_finding

P0_GATE = "Promotion to P0 declares an emergency change and requires human confirmation."
DEMOTE_GATE = ("Demotion of an internet-facing, PCI-scoped or crown-jewel finding "
               "requires human confirmation (under-reaction on critical assets is the costly error).")


# ---------------------------------------------------------------- audit log
def audit(db, actor, action, entity, entity_id, detail=None, ts=None):
    head = db.info.get("audit_head")
    if head is None:
        last = db.execute(select(AuditEntry).order_by(AuditEntry.id.desc()).limit(1)).scalar_one_or_none()
        head = last.hash if last else "GENESIS"
    ts = ts or now()
    detail = json.loads(json.dumps(detail or {}, default=str, sort_keys=True))
    digest = _digest(head, ts, actor, action, entity, str(entity_id), detail)
    entry = AuditEntry(ts=ts, actor=actor, action=action, entity=entity, entity_id=str(entity_id),
                       detail=detail, prev_hash=head, hash=digest)
    db.add(entry)
    db.flush()
    db.info["audit_head"] = digest
    return entry


def _digest(prev, ts, actor, action, entity, entity_id, detail):
    payload = json.dumps({"ts": ts.isoformat(), "actor": actor, "action": action, "entity": entity,
                          "entity_id": entity_id, "detail": detail}, sort_keys=True)
    return hashlib.sha256((prev + payload).encode()).hexdigest()


def verify_chain(db):
    prev = "GENESIS"
    count = 0
    for e in db.execute(select(AuditEntry).order_by(AuditEntry.id)).scalars():
        expected = _digest(prev, e.ts, e.actor, e.action, e.entity, e.entity_id, e.detail)
        if e.prev_hash != prev or e.hash != expected:
            return {"valid": False, "entries": count, "broken_at": e.id, "head": prev}
        prev = e.hash
        count += 1
    return {"valid": True, "entries": count, "broken_at": None, "head": prev}


# -------------------------------------------------------------------- policy
def gate_reason(old_tier, new_tier, asset):
    """Return the policy reason if moving old->new needs human approval, else None."""
    if new_tier == "P0" and old_tier != "P0":
        return P0_GATE
    if TIER_RANK[new_tier] > TIER_RANK[old_tier] and (asset.internet_facing or asset.pci_scope or asset.crown_jewel):
        return DEMOTE_GATE
    return None


def _due(finding, tier, base):
    return base + timedelta(days=SLA_DAYS[tier])


# ------------------------------------------------------------ engine actions
def ingest_finding(db, finding, asset, intel, ts=None, actor="risk-engine"):
    """Score a brand-new finding. P0 candidates enter at P1 with a pending P0 proposal."""
    ts = ts or now()
    res = score_finding(finding.cvss, asset, intel)
    finding.score, finding.ai_tier = res.score, res.tier
    finding.rationale, finding.factors = res.rationale, res.factors
    finding.owner_team = asset.owner_team
    if res.tier == "P0":
        finding.tier = "P1"
        finding.awaiting_approval = True
    else:
        finding.tier = res.tier
        finding.awaiting_approval = False
    finding.due_date = _due(finding, finding.tier, finding.first_seen)
    db.add(finding)
    db.flush()
    audit(db, actor, "finding_scored", "finding", finding.id,
          {"score": res.score, "ai_tier": res.tier, "effective_tier": finding.tier, "cve": finding.cve,
           "asset": asset.name}, ts)
    proposal = None
    if res.tier == "P0":
        proposal = Proposal(finding_id=finding.id, kind="priority_change", origin="engine",
                            from_tier="P1", to_tier="P0", reason=f"{P0_GATE} {res.rationale}",
                            status="pending", created_at=ts, requested_by=actor)
        db.add(proposal)
        db.flush()
        audit(db, actor, "proposal_created", "proposal", proposal.id,
              {"finding_id": finding.id, "kind": "priority_change", "from": "P1", "to": "P0"}, ts)
    return proposal


def rescore_finding(db, finding, actor="risk-engine", ts=None):
    """Re-run the engine (e.g. after new intel). Gated moves become proposals."""
    ts = ts or now()
    asset = db.get(Asset, finding.asset_id)
    intel = db.get(Intel, finding.cve) if finding.cve else None
    res = score_finding(finding.cvss, asset, intel)
    finding.score, finding.ai_tier = res.score, res.tier
    finding.rationale, finding.factors = res.rationale, res.factors
    if res.tier == finding.tier:
        finding.awaiting_approval = False
        db.flush()
        return None
    reason = gate_reason(finding.tier, res.tier, asset)
    if reason is None:
        old = finding.tier
        finding.tier = res.tier
        finding.due_date = _due(finding, res.tier, ts if TIER_RANK[res.tier] < TIER_RANK[old] else finding.first_seen)
        audit(db, actor, "priority_auto_applied", "finding", finding.id,
              {"from": old, "to": res.tier, "score": res.score}, ts)
        db.flush()
        return None
    existing = db.execute(select(Proposal).where(
        Proposal.finding_id == finding.id, Proposal.status == "pending",
        Proposal.kind == "priority_change", Proposal.to_tier == res.tier)).scalar_one_or_none()
    if existing:
        return existing
    finding.awaiting_approval = True
    proposal = Proposal(finding_id=finding.id, kind="priority_change", origin="engine",
                        from_tier=finding.tier, to_tier=res.tier, reason=f"{reason} {res.rationale}",
                        status="pending", created_at=ts, requested_by=actor)
    db.add(proposal)
    db.flush()
    audit(db, actor, "proposal_created", "proposal", proposal.id,
          {"finding_id": finding.id, "kind": "priority_change", "from": finding.tier, "to": res.tier}, ts)
    return proposal


# ------------------------------------------------------------ human actions
class GovernanceError(ValueError):
    pass


def decide(db, proposal, decision, actor, note, ts=None):
    ts = ts or now()
    if proposal.status != "pending":
        raise GovernanceError("Proposal already decided.")
    if decision not in ("approve", "reject"):
        raise GovernanceError("decision must be 'approve' or 'reject'.")
    actor = (actor or "").strip()
    note = (note or "").strip()
    if not actor:
        raise GovernanceError("An accountable actor is required.")
    if (decision == "reject" or proposal.kind == "risk_accept") and len(note) < 5:
        raise GovernanceError("A decision note is required for rejections and risk acceptance.")

    finding = db.get(Finding, proposal.finding_id)
    proposal.status = "approved" if decision == "approve" else "rejected"
    proposal.decided_by, proposal.decided_at, proposal.decision_note = actor, ts, note or None

    if decision == "approve":
        if proposal.kind == "priority_change":
            old = finding.tier
            finding.tier = proposal.to_tier
            finding.due_date = _due(finding, finding.tier,
                                    ts if TIER_RANK[finding.tier] < TIER_RANK[old] else finding.first_seen)
        elif proposal.kind == "risk_accept":
            finding.status = "risk_accepted"
            finding.remediated_at = None
    finding.awaiting_approval = db.execute(select(Proposal.id).where(
        Proposal.finding_id == finding.id, Proposal.status == "pending", Proposal.id != proposal.id)
    ).first() is not None
    audit(db, actor, f"proposal_{proposal.status}", "proposal", proposal.id,
          {"finding_id": finding.id, "kind": proposal.kind, "from": proposal.from_tier,
           "to": proposal.to_tier, "note": note}, ts)
    db.flush()
    return proposal


def set_status(db, finding, status, actor, note, ts=None):
    ts = ts or now()
    if status not in ("open", "in_remediation", "remediated", "risk_accepted"):
        raise GovernanceError("Unknown status.")
    actor = (actor or "").strip()
    if not actor:
        raise GovernanceError("An accountable actor is required.")
    if status == "risk_accepted":
        if len((note or "").strip()) < 10:
            raise GovernanceError("Risk acceptance needs a justification of at least 10 characters.")
        pending = db.execute(select(Proposal).where(Proposal.finding_id == finding.id,
                                                    Proposal.kind == "risk_accept",
                                                    Proposal.status == "pending")).scalar_one_or_none()
        if pending:
            return pending
        p = Proposal(finding_id=finding.id, kind="risk_accept", origin="analyst", from_tier=finding.tier,
                     to_tier=None, reason=note.strip(), status="pending", created_at=ts, requested_by=actor)
        db.add(p)
        db.flush()
        finding.awaiting_approval = True
        audit(db, actor, "risk_acceptance_requested", "proposal", p.id,
              {"finding_id": finding.id, "justification": note.strip()}, ts)
        return p
    old = finding.status
    finding.status = status
    finding.remediated_at = ts if status == "remediated" else None
    audit(db, actor, "status_changed", "finding", finding.id,
          {"from": old, "to": status, "note": (note or "").strip()}, ts)
    db.flush()
    return finding
