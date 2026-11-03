"""Read-side analytics: scorecard, prioritization comparison, model health, brief, evidence."""
import csv
import io
import json
import os
import re
import statistics
import time
from collections import Counter, defaultdict
from datetime import timedelta

import httpx
from sqlalchemy import select

from .governance import verify_chain
from .models import (Asset, Finding, Intel, Pentest, Proposal, ScanSource, Snapshot, iso, now)

OPEN = ("open", "in_remediation")


def _all(db):
    findings = db.execute(select(Finding)).scalars().all()
    assets = {a.id: a for a in db.execute(select(Asset)).scalars()}
    intel = {i.cve: i for i in db.execute(select(Intel)).scalars()}
    return findings, assets, intel


def source_health(db):
    out = []
    n = now()
    for s in db.execute(select(ScanSource).order_by(ScanSource.name)).scalars():
        age_h = (n - s.last_ingest_at).total_seconds() / 3600
        status = "healthy" if age_h <= s.expected_every_hours * 1.5 else "stale"
        out.append({"name": s.name, "label": s.label, "last_ingest_at": iso(s.last_ingest_at),
                    "hours_since_ingest": round(age_h, 1), "expected_every_hours": s.expected_every_hours,
                    "assets_covered": s.assets_covered, "status": status})
    return out


def pentest_status(db):
    out = []
    n = now()
    for p in db.execute(select(Pentest)).scalars():
        a = db.get(Asset, p.asset_id)
        days_left = (p.due_date - n).days
        status = "overdue" if days_left < 0 else ("due_soon" if days_left <= 60 else "current")
        out.append({"asset": a.name, "owner_team": a.owner_team, "last_tested": iso(p.last_tested),
                    "due_date": iso(p.due_date), "days_to_due": days_left, "status": status,
                    "vendor": p.vendor, "findings_open": p.findings_open})
    return sorted(out, key=lambda x: x["days_to_due"])


def sla_stats(findings):
    """On-time / late / overdue-open by effective tier (remediated within 90 days, or still open)."""
    n = now()
    horizon = n - timedelta(days=90)
    stats = {t: {"on_time": 0, "late": 0, "overdue_open": 0} for t in ("P0", "P1", "P2", "P3")}
    for f in findings:
        if f.status == "remediated" and f.remediated_at and f.remediated_at >= horizon and f.due_date:
            stats[f.tier]["on_time" if f.remediated_at <= f.due_date else "late"] += 1
        elif f.status in OPEN and f.due_date and f.due_date < n:
            stats[f.tier]["overdue_open"] += 1
    for t, s in stats.items():
        tot = s["on_time"] + s["late"] + s["overdue_open"]
        s["compliance_pct"] = round(100 * s["on_time"] / tot, 1) if tot else 100.0
    return stats


def posture_inputs(db):
    findings, assets, intel = _all(db)
    n = now()
    open_f = [f for f in findings if f.status in OPEN]
    sla = sla_stats(findings)
    hi = ("P0", "P1")
    hi_on = sum(sla[t]["on_time"] for t in hi)
    hi_tot = sum(sla[t]["on_time"] + sla[t]["late"] + sla[t]["overdue_open"] for t in hi)
    exposed = [f for f in open_f if assets[f.asset_id].internet_facing]
    ext = 100 - 5 * sum(f.tier == "P0" for f in exposed) - 2 * sum(f.tier == "P1" for f in exposed) \
        - 0.5 * sum(f.tier == "P2" for f in exposed)
    kev_open = sum(1 for f in open_f if f.cve and intel.get(f.cve) and intel[f.cve].kev)
    return {
        "p0_open": sum(f.tier == "P0" for f in open_f),
        "p1_open": sum(f.tier == "P1" for f in open_f),
        "overdue_open": sum(1 for f in open_f if f.due_date and f.due_date < n),
        "kev_open": kev_open,
        "stale_sources": sum(1 for s in source_health(db) if s["status"] == "stale"),
        "overdue_pentests": sum(1 for p in pentest_status(db) if p["status"] == "overdue"),
        "sla_pct": round(100 * hi_on / hi_tot, 1) if hi_tot else 100.0,
        "ext_rating": round(max(0.0, ext), 1),
    }


def posture_score(i):
    penalty = (i["p0_open"] * 2.5 + i["p1_open"] * 0.5 + i["overdue_open"] * 0.2 + i["kev_open"] * 0.8
               + i["stale_sources"] * 3 + i["overdue_pentests"] * 3)
    score = round(max(0.0, 100 - penalty), 1)
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    return {**i, "score": score, "grade": grade}


def scorecard(db):
    findings, assets, intel = _all(db)
    n = now()
    open_f = [f for f in findings if f.status in OPEN]
    inputs = posture_inputs(db)
    posture = posture_score(inputs)
    snaps = db.execute(select(Snapshot).order_by(Snapshot.week_start)).scalars().all()
    trend = [{"week_start": iso(s.week_start), "posture_score": s.posture_score, "p0_open": s.p0_open,
              "overdue_open": s.overdue_open, "sla_pct": s.sla_pct, "kev_open": s.kev_open,
              "ext_rating": s.ext_rating} for s in snaps[:-1]]
    trend.append({"week_start": iso(n.replace(hour=0, minute=0, second=0, microsecond=0)),
                  "posture_score": posture["score"], "p0_open": posture["p0_open"],
                  "overdue_open": posture["overdue_open"], "sla_pct": posture["sla_pct"],
                  "kev_open": posture["kev_open"], "ext_rating": posture["ext_rating"]})
    prev = trend[-2]["posture_score"] if len(trend) > 1 else posture["score"]

    by_tier = Counter(f.tier for f in open_f)
    sla = sla_stats(findings)
    overdue_team = defaultdict(lambda: {"count": 0, "oldest_days": 0})
    for f in open_f:
        if f.due_date and f.due_date < n:
            d = overdue_team[f.owner_team]
            d["count"] += 1
            d["oldest_days"] = max(d["oldest_days"], (n - f.due_date).days)
    mttr = {}
    for t in ("P0", "P1", "P2", "P3"):
        ds = [(f.remediated_at - f.first_seen).total_seconds() / 86400 for f in findings
              if f.status == "remediated" and f.tier == t and f.remediated_at]
        mttr[t] = round(statistics.mean(ds), 1) if ds else None

    pend = db.execute(select(Proposal).where(Proposal.status == "pending")).scalars().all()
    exposed_hi = [f for f in open_f if f.tier in ("P0", "P1") and assets[f.asset_id].internet_facing]
    pts = pentest_status(db)
    cmp_ = compare_prioritization(db)
    return {
        "generated_at": iso(n),
        "posture": {"score": posture["score"], "grade": posture["grade"], "delta_vs_last_week": round(posture["score"] - prev, 1),
                    "ext_rating": posture["ext_rating"], "trend": trend},
        "open": {"total": len(open_f), "by_tier": {t: by_tier.get(t, 0) for t in ("P0", "P1", "P2", "P3")},
                 "in_remediation": sum(f.status == "in_remediation" for f in open_f)},
        "sla": {"target_pct": 90.0, "p0_p1_compliance_pct": posture["sla_pct"], "by_tier": sla,
                "overdue_total": posture["overdue_open"],
                "overdue_by_team": sorted(({"team": k, **v} for k, v in overdue_team.items()), key=lambda x: -x["count"])},
        "mttr_days_by_tier": mttr,
        "threat": {"kev_open": posture["kev_open"],
                   "kev_on_exposed_assets": sum(1 for f in open_f if f.cve and intel.get(f.cve) and intel[f.cve].kev and assets[f.asset_id].internet_facing),
                   "active_campaign_open": sum(1 for f in open_f if f.cve and intel.get(f.cve) and intel[f.cve].campaign),
                   "internet_facing_p0_p1": len(exposed_hi)},
        "governance": {"pending_approvals": len(pend),
                       "pending_p0": sum(1 for p in pend if p.to_tier == "P0"),
                       "oldest_pending_hours": round(max(((n - p.created_at).total_seconds() / 3600 for p in pend), default=0), 1)},
        "pentest": {"total": len(pts), "current": sum(p["status"] == "current" for p in pts),
                    "coverage_pct": round(100 * sum(p["status"] != "overdue" for p in pts) / len(pts), 1) if pts else 100.0,
                    "overdue": [p for p in pts if p["status"] == "overdue"],
                    "due_soon": [p for p in pts if p["status"] == "due_soon"]},
        "coverage": source_health(db),
        "prioritization": cmp_["summary"],
    }


def compare_prioritization(db, capacity=25):
    """CVSS-only queue vs risk-based queue: the product's core value proof."""
    findings, assets, intel = _all(db)
    open_f = [f for f in findings if f.status in OPEN]

    def real_risk(f):  # known-exploited on an internet-facing asset
        i = intel.get(f.cve) if f.cve else None
        return bool(i and i.kev and assets[f.asset_id].internet_facing)

    crit = [f for f in open_f if f.cvss >= 9.0]
    demoted = [f for f in crit if f.tier in ("P2", "P3")]
    hidden = [f for f in open_f if f.cvss < 9.0 and f.tier in ("P0", "P1")]
    risky = [f for f in open_f if real_risk(f)]
    cvss_q = sorted(open_f, key=lambda f: (-f.cvss, f.id))[:capacity]
    risk_q = sorted(open_f, key=lambda f: (-f.score, f.id))[:capacity]
    cvss_hits = sum(1 for f in cvss_q if real_risk(f))
    risk_hits = sum(1 for f in risk_q if real_risk(f))
    summary = {
        "open_findings": len(open_f),
        "cvss_critical_open": len(crit),
        "cvss_critical_demoted": len(demoted),
        "noise_reduction_pct": round(100 * len(demoted) / len(crit), 1) if crit else 0.0,
        "hidden_risk_promoted": len(hidden),
        "known_exploited_exposed": len(risky),
        "known_exploited_exposed_in_p0_p1": sum(1 for f in risky if f.tier in ("P0", "P1") or f.ai_tier in ("P0", "P1")),
        "capacity": capacity,
        "real_risk_in_top_cvss_only": cvss_hits,
        "real_risk_in_top_risk_based": risk_hits,
    }

    def row(f):
        a = assets[f.asset_id]
        return {"id": f.id, "title": f.title, "asset": a.name, "cvss": f.cvss, "score": f.score, "tier": f.tier,
                "cve": f.cve, "real_risk": real_risk(f)}
    return {"summary": summary, "cvss_only_queue": [row(f) for f in cvss_q], "risk_based_queue": [row(f) for f in risk_q],
            "demoted_examples": [row(f) | {"rationale": f.rationale} for f in sorted(demoted, key=lambda f: -f.cvss)[:6]],
            "hidden_risk_examples": [row(f) | {"rationale": f.rationale} for f in sorted(hidden, key=lambda f: -f.score)[:6]]}


def model_health(db):
    props = db.execute(select(Proposal).where(Proposal.kind == "priority_change",
                                              Proposal.status.in_(("approved", "rejected")))).scalars().all()
    decided = len(props)
    approved = [p for p in props if p.status == "approved"]
    agree = round(100 * len(approved) / decided, 1) if decided else None
    by_to = defaultdict(lambda: [0, 0])
    for p in props:
        by_to[p.to_tier][1] += 1
        by_to[p.to_tier][0] += p.status == "approved"
    weekly = defaultdict(lambda: [0, 0])
    for p in props:
        wk = (p.decided_at - timedelta(days=p.decided_at.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        weekly[wk][1] += 1
        weekly[wk][0] += p.status == "approved"
    hours = [(p.decided_at - p.created_at).total_seconds() / 3600 for p in props]
    reasons = Counter(p.decision_note for p in props if p.status == "rejected")
    pending = db.execute(select(Proposal).where(Proposal.status == "pending")).scalars().all()
    recent_cut = now() - timedelta(days=56)
    recent = [p for p in props if p.decided_at >= recent_cut]
    recent_agree = round(100 * sum(p.status == "approved" for p in recent) / len(recent), 1) if recent else None
    return {
        "decided": decided, "pending": len(pending), "agreement_pct": agree,
        "recent_8w_agreement_pct": recent_agree, "recent_8w_decided": len(recent),
        "override_pct": round(100 - agree, 1) if agree is not None else None, "target_agreement_pct": 85.0,
        "median_hours_to_decision": round(statistics.median(hours), 1) if hours else None,
        "by_proposed_tier": {t: {"decided": v[1], "agreement_pct": round(100 * v[0] / v[1], 1)} for t, v in sorted(by_to.items())},
        "weekly": [{"week_start": iso(k), "decided": v[1], "agreement_pct": round(100 * v[0] / v[1], 1)} for k, v in sorted(weekly.items())],
        "top_rejection_reasons": [{"reason": r, "count": c} for r, c in reasons.most_common(5)],
    }


# ------------------------------------------------------------------- brief
_brief_cache = {"ts": 0, "data": None}


def _facts(db):
    sc = scorecard(db)
    findings, assets, intel = _all(db)
    open_f = [f for f in findings if f.status in OPEN]
    top = sorted(open_f, key=lambda f: -f.score)[:3]
    return {
        "posture_score": sc["posture"]["score"], "grade": sc["posture"]["grade"],
        "change_vs_last_week": sc["posture"]["delta_vs_last_week"],
        "open_p0": sc["open"]["by_tier"]["P0"], "open_p1": sc["open"]["by_tier"]["P1"],
        "p0_awaiting_approval": sc["governance"]["pending_p0"],
        "overdue_findings": sc["sla"]["overdue_total"], "sla_p0_p1_pct": sc["sla"]["p0_p1_compliance_pct"],
        "sla_target_pct": 90,
        "known_exploited_open": sc["threat"]["kev_open"], "known_exploited_on_exposed": sc["threat"]["kev_on_exposed_assets"],
        "overdue_pentests": [p["asset"] for p in sc["pentest"]["overdue"]],
        "stale_scan_sources": [s["label"] for s in sc["coverage"] if s["status"] == "stale"],
        "worst_overdue_team": (sc["sla"]["overdue_by_team"][0] if sc["sla"]["overdue_by_team"] else None),
        "cvss_critical_deprioritized": sc["prioritization"]["cvss_critical_demoted"],
        "cvss_critical_total": sc["prioritization"]["cvss_critical_open"],
        "top_risks": [{"title": f.title, "asset": assets[f.asset_id].name, "score": f.score, "tier": f.tier, "cve": f.cve}
                      for f in top],
    }


def _template_brief(f):
    lines = [
        f"Posture is {f['grade']} ({f['posture_score']}/100), a change of {f['change_vs_last_week']:+} points versus last week.",
        f"There are {f['open_p0']} open P0 and {f['open_p1']} open P1 findings; {f['p0_awaiting_approval']} proposed P0 "
        f"declarations are waiting on human approval.",
        f"P0/P1 SLA compliance is {f['sla_p0_p1_pct']}% against a {f['sla_target_pct']}% target, with {f['overdue_findings']} findings overdue.",
        f"{f['known_exploited_open']} open findings are known to be exploited in the wild, {f['known_exploited_on_exposed']} of them on internet-facing assets.",
    ]
    if f["worst_overdue_team"]:
        t = f["worst_overdue_team"]
        lines.append(f"{t['team']} carries the most overdue items ({t['count']}), the oldest {t['oldest_days']} days past due.")
    if f["overdue_pentests"]:
        lines.append("Annual penetration tests are overdue for: " + ", ".join(f["overdue_pentests"]) + ".")
    if f["stale_scan_sources"]:
        lines.append("Scan coverage gap: " + ", ".join(f["stale_scan_sources"]) + " has not reported within its expected window.")
    lines.append(f"Risk-based prioritization deprioritized {f['cvss_critical_deprioritized']} of {f['cvss_critical_total']} CVSS-Critical findings that show no exploitation or exposure.")
    return " ".join(lines)


def _numbers(text):
    return set(re.findall(r"\d+(?:\.\d+)?", text))


def _llm_brief(facts):
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return None
    prompt = ("You write a short executive security brief (max 120 words, plain prose, no markdown) for a CISO. "
              "Use ONLY the facts in this JSON. Do not invent, round, or compute any number; copy numbers exactly.\n\n"
              + json.dumps(facts))
    try:
        r = httpx.post("https://api.anthropic.com/v1/messages",
                       headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
                       json={"model": os.getenv("BRIEF_MODEL", "claude-haiku-5-5"), "max_tokens": 400,
                             "messages": [{"role": "user", "content": prompt}]}, timeout=20)
        r.raise_for_status()
        return r.json()["content"][0]["text"].strip()
    except Exception:
        return None


def brief(db, force=False):
    if not force and _brief_cache["data"] and time.time() - _brief_cache["ts"] < 300:
        return _brief_cache["data"]
    facts = _facts(db)
    allowed = _numbers(json.dumps(facts))
    text, source, validated = None, "template", True
    llm = _llm_brief(facts)
    if llm:
        extra = _numbers(llm) - allowed
        if not extra:
            text, source = llm, "llm"
        else:
            validated = False  # LLM produced numbers not in the facts: reject and fall back
    if text is None:
        text = _template_brief(facts)
    data = {"generated_at": iso(now()), "source": source, "numbers_validated": validated, "narrative": text, "facts": facts}
    _brief_cache.update(ts=time.time(), data=data)
    return data


# ---------------------------------------------------------------- evidence
def evidence_pci(db, fmt="json"):
    findings, assets, intel = _all(db)
    n = now()
    chain = verify_chain(db)
    rows = []
    for f in sorted(findings, key=lambda f: (f.tier, f.id)):
        a = assets[f.asset_id]
        if not a.pci_scope:
            continue
        props = db.execute(select(Proposal).where(Proposal.finding_id == f.id)).scalars().all()
        rows.append({
            "finding_id": f.id, "asset": a.name, "source": f.source, "cve": f.cve or "", "title": f.title,
            "cvss": f.cvss, "priority": f.tier, "risk_score": f.score, "status": f.status,
            "first_seen": iso(f.first_seen), "due_date": iso(f.due_date), "remediated_at": iso(f.remediated_at) or "",
            "sla_state": ("met" if f.remediated_at and f.due_date and f.remediated_at <= f.due_date else
                          "missed" if f.status == "remediated" else
                          "overdue" if f.status in OPEN and f.due_date and f.due_date < n else
                          "accepted" if f.status == "risk_accepted" else "on_track"),
            "approvals": "; ".join(f"{p.kind}:{p.status}:{p.decided_by or 'pending'}" for p in props),
        })
    meta = {"generated_at": iso(n), "scope": "PCI-scoped assets",
            "reference": "Supports evidence requests mapped to PCI DSS v4.0 requirements 6.3.3, 11.3 and 11.4 (verify against your assessor's current guidance).",
            "records": len(rows), "audit_chain": chain,
            "pentests": [p for p in pentest_status(db) if True]}
    if fmt == "csv":
        buf = io.StringIO()
        if rows:
            w = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
            w.writeheader()
            w.writerows(rows)
        return buf.getvalue()
    return {"meta": meta, "findings": rows}
