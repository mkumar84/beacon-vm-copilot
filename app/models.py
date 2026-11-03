from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base


def now() -> datetime:
    """Naive UTC timestamp (consistent across SQLite and Postgres)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def iso(dt):
    return dt.isoformat() + "Z" if dt else None


class Asset(Base):
    __tablename__ = "assets"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    asset_type: Mapped[str] = mapped_column(String(20))  # server | app | database | mobile
    business_unit: Mapped[str] = mapped_column(String(60))
    owner_team: Mapped[str] = mapped_column(String(60))
    environment: Mapped[str] = mapped_column(String(10), default="prod")
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    pci_scope: Mapped[bool] = mapped_column(Boolean, default=False)
    crown_jewel: Mapped[bool] = mapped_column(Boolean, default=False)
    criticality: Mapped[int] = mapped_column(Integer, default=3)  # 1..5
    data_class: Mapped[str] = mapped_column(String(20), default="internal")  # cardholder|pii|internal|public
    components: Mapped[list] = mapped_column(JSON, default=list)

    def as_dict(self):
        return {
            "id": self.id, "name": self.name, "asset_type": self.asset_type,
            "business_unit": self.business_unit, "owner_team": self.owner_team,
            "environment": self.environment, "internet_facing": self.internet_facing,
            "pci_scope": self.pci_scope, "crown_jewel": self.crown_jewel,
            "criticality": self.criticality, "data_class": self.data_class,
            "components": self.components,
        }


class Intel(Base):
    """Simulated threat-intel enrichment keyed by CVE."""
    __tablename__ = "intel"
    cve: Mapped[str] = mapped_column(String(24), primary_key=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False)  # known exploited in the wild
    epss: Mapped[float] = mapped_column(Float, default=0.0)  # exploit probability 0..1
    exploit_public: Mapped[bool] = mapped_column(Boolean, default=False)
    campaign: Mapped[str | None] = mapped_column(String(120), nullable=True)
    simulated: Mapped[bool] = mapped_column(Boolean, default=True)

    def as_dict(self):
        return {"cve": self.cve, "kev": self.kev, "epss": self.epss,
                "exploit_public": self.exploit_public, "campaign": self.campaign,
                "simulated": self.simulated}


class Finding(Base):
    __tablename__ = "findings"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), index=True)
    source: Mapped[str] = mapped_column(String(20), index=True)
    cve: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(200))
    cvss: Mapped[float] = mapped_column(Float)
    first_seen: Mapped[datetime] = mapped_column(DateTime)
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)
    remediated_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    due_date: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    owner_team: Mapped[str] = mapped_column(String(60), index=True)
    score: Mapped[float] = mapped_column(Float, default=0.0)
    ai_tier: Mapped[str] = mapped_column(String(2), default="P3")  # what the engine recommends
    tier: Mapped[str] = mapped_column(String(2), default="P3", index=True)  # effective, human-governed
    awaiting_approval: Mapped[bool] = mapped_column(Boolean, default=False)
    rationale: Mapped[str] = mapped_column(Text, default="")
    factors: Mapped[list] = mapped_column(JSON, default=list)

    def as_dict(self, asset=None, intel=None):
        d = {
            "id": self.id, "asset_id": self.asset_id, "source": self.source, "cve": self.cve,
            "title": self.title, "cvss": self.cvss, "first_seen": iso(self.first_seen),
            "status": self.status, "remediated_at": iso(self.remediated_at),
            "due_date": iso(self.due_date), "owner_team": self.owner_team,
            "score": self.score, "ai_tier": self.ai_tier, "tier": self.tier,
            "awaiting_approval": self.awaiting_approval, "rationale": self.rationale,
            "factors": self.factors,
            "overdue": bool(self.status in ("open", "in_remediation") and self.due_date and self.due_date < now()),
        }
        if asset is not None:
            d["asset"] = {"id": asset.id, "name": asset.name, "internet_facing": asset.internet_facing,
                          "pci_scope": asset.pci_scope, "crown_jewel": asset.crown_jewel,
                          "criticality": asset.criticality, "asset_type": asset.asset_type,
                          "business_unit": asset.business_unit}
        if intel is not None:
            d["intel"] = intel.as_dict()
        return d


class Proposal(Base):
    """An AI recommendation that needs a human decision."""
    __tablename__ = "proposals"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(ForeignKey("findings.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # priority_change | risk_accept
    origin: Mapped[str] = mapped_column(String(20), default="engine")  # engine | zero_day | analyst
    from_tier: Mapped[str | None] = mapped_column(String(2), nullable=True)
    to_tier: Mapped[str | None] = mapped_column(String(2), nullable=True)
    reason: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(10), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime)
    requested_by: Mapped[str] = mapped_column(String(60), default="risk-engine")
    decided_by: Mapped[str | None] = mapped_column(String(60), nullable=True)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    decision_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    def as_dict(self):
        return {
            "id": self.id, "finding_id": self.finding_id, "kind": self.kind, "origin": self.origin,
            "from_tier": self.from_tier, "to_tier": self.to_tier, "reason": self.reason,
            "status": self.status, "created_at": iso(self.created_at),
            "requested_by": self.requested_by, "decided_by": self.decided_by,
            "decided_at": iso(self.decided_at), "decision_note": self.decision_note,
        }


class AuditEntry(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime)
    actor: Mapped[str] = mapped_column(String(60))
    action: Mapped[str] = mapped_column(String(40), index=True)
    entity: Mapped[str] = mapped_column(String(20), index=True)
    entity_id: Mapped[str] = mapped_column(String(40), index=True)
    detail: Mapped[dict] = mapped_column(JSON, default=dict)
    prev_hash: Mapped[str] = mapped_column(String(64))
    hash: Mapped[str] = mapped_column(String(64))

    def as_dict(self):
        return {"id": self.id, "ts": iso(self.ts), "actor": self.actor, "action": self.action,
                "entity": self.entity, "entity_id": self.entity_id, "detail": self.detail,
                "prev_hash": self.prev_hash, "hash": self.hash}


class Pentest(Base):
    __tablename__ = "pentests"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("assets.id"), unique=True)
    last_tested: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    due_date: Mapped[datetime] = mapped_column(DateTime)
    vendor: Mapped[str] = mapped_column(String(60), default="Independent assessor")
    findings_open: Mapped[int] = mapped_column(Integer, default=0)


class ScanSource(Base):
    __tablename__ = "scan_sources"
    name: Mapped[str] = mapped_column(String(20), primary_key=True)
    label: Mapped[str] = mapped_column(String(60))
    last_ingest_at: Mapped[datetime] = mapped_column(DateTime)
    expected_every_hours: Mapped[int] = mapped_column(Integer, default=24)
    assets_covered: Mapped[int] = mapped_column(Integer, default=0)


class ZeroDayEvent(Base):
    __tablename__ = "zeroday_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    cve: Mapped[str] = mapped_column(String(24), unique=True)
    title: Mapped[str] = mapped_column(String(200))
    cvss: Mapped[float] = mapped_column(Float)
    component: Mapped[str] = mapped_column(String(60))
    summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime)
    created_by: Mapped[str] = mapped_column(String(60))
    assets_matched: Mapped[int] = mapped_column(Integer, default=0)
    findings_created: Mapped[int] = mapped_column(Integer, default=0)
    elapsed_ms: Mapped[int] = mapped_column(Integer, default=0)


class Snapshot(Base):
    """Weekly posture snapshot used for trend lines."""
    __tablename__ = "snapshots"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    week_start: Mapped[datetime] = mapped_column(DateTime, unique=True)
    posture_score: Mapped[float] = mapped_column(Float)
    p0_open: Mapped[int] = mapped_column(Integer)
    overdue_open: Mapped[int] = mapped_column(Integer)
    sla_pct: Mapped[float] = mapped_column(Float)
    kev_open: Mapped[int] = mapped_column(Integer)
    ext_rating: Mapped[float] = mapped_column(Float)


class Meta(Base):
    """Key/value bookkeeping, e.g. when the demo data was last seeded."""
    __tablename__ = "meta"
    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    value: Mapped[str] = mapped_column(String(200))
