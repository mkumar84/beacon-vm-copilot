"""Zero-day response: new CVE -> exposed assets -> owners -> governed P0 proposals."""
import re
import time

from sqlalchemy import select

from .governance import audit, ingest_finding
from .models import Asset, Finding, Intel, ZeroDayEvent, iso, now
from .seed import _source_for

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")

# Fictional sample so the demo never implies a real vulnerability.
SAMPLE = {
    "cve": "CVE-2026-99001",
    "title": "libcartstream deserialization flaw allows unauthenticated remote code execution (FICTIONAL)",
    "cvss": 9.8,
    "component": "libcartstream",
    "summary": "Simulated zero-day in a fictional shopping-cart streaming library embedded across Maple & Main services.",
    "exploited_in_wild": True,
    "exploit_probability": 0.85,
}


def _matches(db, component):
    comp = component.strip().lower()
    return [a for a in db.execute(select(Asset)).scalars() if comp in [c.lower() for c in (a.components or [])]]


def _rank(db, assets, cve, cvss):
    intel = db.get(Intel, cve)
    from .scoring import score_finding
    rows = []
    for a in assets:
        r = score_finding(cvss, a, intel)
        rows.append((r.score, a, r))
    rows.sort(key=lambda x: (-x[0], x[1].name))
    return rows


def preview(db, component, cvss=9.8, exploited=True, epss=0.85):
    """Blast radius without writing anything."""
    from .models import Intel as I
    assets = _matches(db, component)
    fake = I(cve="PREVIEW", kev=exploited, epss=epss, exploit_public=exploited, campaign=None)
    from .scoring import score_finding
    rows = sorted(((score_finding(cvss, a, fake), a) for a in assets), key=lambda x: (-x[0].score, x[1].name))
    return {"component": component, "assets_matched": len(assets),
            "internet_facing": sum(a.internet_facing for _, a in rows), "pci_scope": sum(a.pci_scope for _, a in rows),
            "exposure": [{"asset": a.name, "owner_team": a.owner_team, "internet_facing": a.internet_facing,
                          "pci_scope": a.pci_scope, "crown_jewel": a.crown_jewel, "score": r.score, "tier": r.tier}
                         for r, a in rows]}


def declare(db, payload, actor):
    started = time.perf_counter()
    cve = payload["cve"].strip().upper()
    if not CVE_RE.match(cve):
        raise ValueError("CVE id must look like CVE-YYYY-NNNN.")
    existing = db.execute(select(ZeroDayEvent).where(ZeroDayEvent.cve == cve)).scalar_one_or_none()
    if existing:
        return exposure(db, cve) | {"already_declared": True}

    intel = db.get(Intel, cve)
    if intel is None:
        intel = Intel(cve=cve, kev=bool(payload.get("exploited_in_wild", True)),
                      epss=float(payload.get("exploit_probability", 0.8)),
                      exploit_public=bool(payload.get("exploited_in_wild", True)), campaign=None, simulated=True)
        db.add(intel)
        db.flush()

    assets = _matches(db, payload["component"])
    ranked = _rank(db, assets, cve, float(payload["cvss"]))
    created = 0
    for _score, a, _r in ranked:
        dup = db.execute(select(Finding).where(Finding.asset_id == a.id, Finding.cve == cve)).scalar_one_or_none()
        if dup:
            continue
        f = Finding(asset_id=a.id, source=_source_for(a, "cve"), cve=cve, title=payload["title"],
                    cvss=float(payload["cvss"]), first_seen=now(), status="open", owner_team=a.owner_team)
        p = ingest_finding(db, f, a, intel, actor="risk-engine")
        if p is not None:
            p.origin = "zero_day"
        created += 1
    elapsed = int((time.perf_counter() - started) * 1000)
    ev = ZeroDayEvent(cve=cve, title=payload["title"], cvss=float(payload["cvss"]), component=payload["component"],
                      summary=payload.get("summary", ""), created_at=now(), created_by=actor,
                      assets_matched=len(assets), findings_created=created, elapsed_ms=elapsed)
    db.add(ev)
    audit(db, actor, "zeroday_declared", "zeroday", cve,
          {"component": payload["component"], "cvss": payload["cvss"], "assets_matched": len(assets),
           "findings_created": created})
    db.commit()
    return exposure(db, cve) | {"already_declared": False}


def exposure(db, cve):
    ev = db.execute(select(ZeroDayEvent).where(ZeroDayEvent.cve == cve)).scalar_one_or_none()
    if ev is None:
        return None
    rows = db.execute(select(Finding).where(Finding.cve == cve)).scalars().all()
    assets = {a.id: a for a in db.execute(select(Asset)).scalars()}
    rows.sort(key=lambda f: -f.score)
    teams = {}
    for f in rows:
        t = teams.setdefault(f.owner_team, {"team": f.owner_team, "assets": 0, "p0_candidates": 0})
        t["assets"] += 1
        t["p0_candidates"] += f.ai_tier == "P0"
    return {
        "event": {"cve": ev.cve, "title": ev.title, "cvss": ev.cvss, "component": ev.component,
                  "declared_at": iso(ev.created_at), "declared_by": ev.created_by,
                  "elapsed_ms": ev.elapsed_ms},
        "summary": {"assets_exposed": len(rows), "internet_facing": sum(assets[f.asset_id].internet_facing for f in rows),
                    "pci_scope": sum(assets[f.asset_id].pci_scope for f in rows),
                    "p0_candidates": sum(f.ai_tier == "P0" for f in rows),
                    "pending_approval": sum(f.awaiting_approval for f in rows)},
        "by_team": sorted(teams.values(), key=lambda t: -t["assets"]),
        "exposure": [f.as_dict(asset=assets[f.asset_id]) for f in rows],
    }
