"""Synthetic data for Maple & Main Retail (fictional).

CVE identifiers are real so the demo reads naturally, but ALL threat-intel flags,
exploit probabilities, assets, owners and findings are simulated. The zero-day
scenario uses a fictional CVE and component.
"""
import random
from datetime import datetime, timedelta

from sqlalchemy import select

from .governance import audit, decide, ingest_finding
from .models import (Asset, Finding, Intel, Pentest, Proposal, ScanSource, Snapshot, now)
from .scoring import SLA_DAYS

ANALYSTS = ["a.okafor", "j.tremblay", "p.sharma", "m.lefebvre"]

# ---- vulnerability catalogue: (cve, title, cvss, component, kev, epss, exploit_public, campaign)
VULNS = [
    ("CVE-2021-44228", "Apache Log4j2 remote code execution (Log4Shell)", 10.0, "log4j", True, 0.97, True, "Opportunistic mass exploitation"),
    ("CVE-2022-22965", "Spring Framework data binding RCE (Spring4Shell)", 9.8, "spring-boot", True, 0.96, True, None),
    ("CVE-2023-34362", "Managed file transfer SQL injection leading to data theft", 9.8, "managed-file-transfer", True, 0.94, True, "Data-extortion campaign"),
    ("CVE-2023-44487", "HTTP/2 Rapid Reset denial of service", 7.5, "nginx", True, 0.82, True, None),
    ("CVE-2023-4863", "libwebp heap buffer overflow", 8.8, "libwebp", True, 0.71, True, None),
    ("CVE-2021-3156", "sudo heap overflow privilege escalation", 7.8, "linux", True, 0.88, True, None),
    ("CVE-2019-0708", "Remote Desktop Services remote code execution (BlueKeep)", 9.8, "windows-rds", True, 0.95, True, "Ransomware initial access"),
    ("CVE-2020-1472", "Netlogon elevation of privilege (Zerologon)", 10.0, "active-directory", True, 0.96, True, "Ransomware initial access"),
    ("CVE-2022-0778", "OpenSSL infinite loop in certificate parsing", 7.5, "openssl", False, 0.15, True, None),
    ("CVE-2023-0286", "OpenSSL X.400 address type confusion", 7.4, "openssl", False, 0.03, False, None),
    ("CVE-2023-2650", "OpenSSL excessive resource use in ASN.1 parsing", 6.5, "openssl", False, 0.01, False, None),
    ("CVE-2021-23337", "lodash command injection via template", 7.2, "node", False, 0.04, False, None),
    ("CVE-2023-32233", "Linux kernel netfilter use-after-free", 7.8, "linux", False, 0.06, True, None),
    # --- "scary-looking" CVSS-Critical findings with weak real-world signals (the noise)
    ("CVE-2024-3094", "xz-utils backdoored release tarball", 10.0, "xz-utils", False, 0.30, False, None),
    ("CVE-2022-42889", "Apache Commons Text variable interpolation RCE (Text4Shell)", 9.8, "commons-text", False, 0.28, True, None),
    ("CVE-2022-37434", "zlib heap buffer overflow in inflate", 9.8, "zlib", False, 0.02, False, None),
    ("CVE-2023-45853", "zlib MiniZip integer overflow", 9.8, "zlib", False, 0.01, False, None),
    ("CVE-2023-38545", "curl SOCKS5 heap buffer overflow", 9.8, "curl", False, 0.03, False, None),
]
INTEL_ONLY = {  # CVEs enriched in intel but never auto-attached randomly
}

# ---- non-CVE findings: (kind, title, cvss)
LOCAL = {
    "web": [("Reflected cross-site scripting in search parameter", 6.1),
            ("SQL injection in order-status endpoint", 8.8),
            ("Verbose error messages disclose stack traces", 5.3),
            ("Missing HTTP security headers", 4.3),
            ("TLS 1.0/1.1 still enabled on public endpoint", 5.9)],
    "code": [("Hardcoded credential detected in repository", 7.5),
             ("Insecure deserialization pattern", 8.1),
             ("Weak cryptographic hash (MD5) used for tokens", 5.9)],
    "config": [("Default administrative account enabled", 8.1),
               ("Database audit logging disabled", 5.5),
               ("Excessive privileges granted to service account", 6.5),
               ("Password policy below standard", 4.9)],
    "mobile": [("Missing certificate pinning", 5.3),
               ("Sensitive data written to device logs", 5.5),
               ("Exported component without permission check", 6.5)],
}

# (name, type, business_unit, owner_team, env, internet, pci, crown, crit, data_class, components)
KEY_ASSETS = [
    ("mapleshop-web", "app", "E-commerce", "Web Platform", "prod", True, True, False, 5, "cardholder", ["nginx", "node", "libwebp", "libcartstream", "openssl"]),
    ("payment-gateway-api", "app", "E-commerce", "Payments Engineering", "prod", True, True, True, 5, "cardholder", ["spring-boot", "nginx", "openssl", "libcartstream", "linux"]),
    ("checkout-service", "app", "E-commerce", "Web Platform", "prod", True, True, False, 5, "cardholder", ["node", "libcartstream", "nginx", "linux"]),
    ("customer-db-prod", "database", "Data & Analytics", "Data Platform", "prod", False, True, True, 5, "cardholder", ["postgres", "linux", "openssl"]),
    ("cardvault-tokenization", "server", "E-commerce", "Payments Engineering", "prod", False, True, True, 5, "cardholder", ["spring-boot", "openssl", "linux"]),
    ("loyalty-app-ios", "mobile", "Loyalty & Marketing", "Loyalty Mobile", "prod", True, False, False, 4, "pii", ["libwebp", "libcartstream"]),
    ("loyalty-app-android", "mobile", "Loyalty & Marketing", "Loyalty Mobile", "prod", True, False, False, 4, "pii", ["libwebp", "libcartstream", "zlib"]),
    ("loyalty-api", "app", "Loyalty & Marketing", "Loyalty Mobile", "prod", True, False, False, 4, "pii", ["spring-boot", "nginx", "node", "linux"]),
    ("loyalty-db", "database", "Loyalty & Marketing", "Data Platform", "prod", False, False, True, 4, "pii", ["postgres", "linux"]),
    ("sft-gateway", "server", "Supply Chain", "Supply Chain Systems", "prod", True, False, False, 4, "internal", ["managed-file-transfer", "windows-rds", "openssl"]),
    ("vpn-gateway", "server", "Corporate IT", "Corporate IT Ops", "prod", True, False, False, 4, "internal", ["openssl", "linux", "curl"]),
    ("corp-ad-dc01", "server", "Corporate IT", "Corporate IT Ops", "prod", False, False, True, 5, "internal", ["active-directory", "windows-rds"]),
    ("corp-ad-dc02", "server", "Corporate IT", "Corporate IT Ops", "prod", False, False, True, 5, "internal", ["active-directory", "windows-rds"]),
    ("wms-app", "app", "Supply Chain", "Supply Chain Systems", "prod", False, False, False, 3, "internal", ["spring-boot", "log4j", "linux"]),
    ("analytics-warehouse", "database", "Data & Analytics", "Data Platform", "prod", False, False, False, 3, "internal", ["postgres", "linux", "zlib"]),
    ("marketing-site-wp", "app", "Loyalty & Marketing", "Loyalty Mobile", "prod", True, False, False, 2, "public", ["nginx", "linux", "openssl", "libwebp"]),
]
POS_REGIONS = ["east", "west", "central", "north", "atlantic", "prairies"]


def _make_assets(db):
    assets = []
    for (name, typ, bu, team, env, net, pci, crown, crit, dc, comps) in KEY_ASSETS:
        assets.append(Asset(name=name, asset_type=typ, business_unit=bu, owner_team=team, environment=env,
                            internet_facing=net, pci_scope=pci, crown_jewel=crown, criticality=crit,
                            data_class=dc, components=comps))
    for r in POS_REGIONS:
        assets.append(Asset(name=f"pos-region-{r}", asset_type="server", business_unit="Store Systems",
                            owner_team="Store Systems Ops", environment="prod", internet_facing=False,
                            pci_scope=True, crown_jewel=False, criticality=4, data_class="cardholder",
                            components=["windows-rds", "openssl", "curl", "zlib", "libcartstream"]))
    for i in range(1, 11):
        assets.append(Asset(name=f"store-gw-{i:02d}", asset_type="server", business_unit="Store Systems",
                            owner_team="Store Systems Ops", environment="prod", internet_facing=False,
                            pci_scope=True, crown_jewel=False, criticality=3, data_class="internal",
                            components=["linux", "openssl", "zlib", "curl"]))
    for i in range(1, 9):
        assets.append(Asset(name=f"dev-build-{i:02d}", asset_type="server", business_unit="Corporate IT",
                            owner_team="Corporate IT Ops" if i % 2 else "Web Platform", environment="dev",
                            internet_facing=False, pci_scope=False, crown_jewel=False, criticality=1,
                            data_class="internal", components=["linux", "xz-utils", "commons-text", "zlib", "curl", "log4j"]))
    db.add_all(assets)
    db.flush()
    return assets


def _source_for(asset, kind):
    if kind == "web":
        return "dast"
    if kind == "code":
        return "sast"
    if kind == "mobile":
        return "mobile"
    if kind == "config":
        return "db_scan" if asset.asset_type == "database" else ("external_scan" if asset.internet_facing else "internal_scan")
    # component CVE
    if asset.asset_type == "database":
        return "db_scan"
    if asset.asset_type == "mobile":
        return "sca"
    if asset.asset_type == "app":
        return "sca"
    return "external_scan" if asset.internet_facing else "internal_scan"


def _simulate_remediation(rng, db, f, asset, now_dt):
    """Decide if/when a seeded finding was fixed, using the finding's effective tier SLA."""
    sla = SLA_DAYS[f.tier]
    age = (now_dt - f.first_seen).total_seconds() / 86400
    slow = asset.owner_team == "Store Systems Ops"  # holiday change freeze story
    if slow and f.tier == "P0" and 1.5 < age < 40 and rng.random() < 0.85:
        if rng.random() < 0.5:
            f.status = "in_remediation"
        return  # approved P0 still open under the change freeze: the SLA-breach story
    if slow:
        ttf = sla * rng.uniform(1.6, 3.2) if rng.random() < 0.55 else sla * rng.uniform(0.6, 1.0)
    else:
        ttf = sla * rng.uniform(0.35, 1.05) if rng.random() < 0.85 else sla * rng.uniform(1.2, 2.4)
    if f.awaiting_approval:
        return
    if age > ttf:
        f.status = "remediated"
        f.remediated_at = f.first_seen + timedelta(days=ttf)
        audit(db, rng.choice(ANALYSTS), "status_changed", "finding", f.id,
              {"from": "open", "to": "remediated", "note": "Patched / mitigated"}, f.remediated_at)
    elif rng.random() < 0.35:
        f.status = "in_remediation"


def seed(db, rng=None):
    rng = rng or random.Random(20261102)
    now_dt = now()

    # --- scan sources (platform health)
    sources = [("internal_scan", "Internal network scanner", 20, 24, 38), ("external_scan", "External attack-surface scanner", 14, 24, 9),
               ("db_scan", "Database configuration scanner", 9 * 24 + 6, 72, 4), ("sast", "Static code analysis", 30, 24, 14),
               ("dast", "Dynamic application testing", 40, 48, 8), ("sca", "Software composition analysis", 26, 24, 22),
               ("mobile", "Mobile app analysis", 3 * 24, 168, 2)]
    for name, label, hrs, every, cov in sources:
        db.add(ScanSource(name=name, label=label, last_ingest_at=now_dt - timedelta(hours=hrs),
                          expected_every_hours=every, assets_covered=cov))

    # --- intel
    for (cve, _t, _c, _comp, kev, epss, pub, camp) in VULNS:
        db.add(Intel(cve=cve, kev=kev, epss=epss, exploit_public=pub, campaign=camp, simulated=True))
    db.flush()

    assets = _make_assets(db)
    by_name = {a.name: a for a in assets}
    intel = {i.cve: i for i in db.execute(select(Intel)).scalars()}
    vuln_by_cve = {v[0]: v for v in VULNS}

    # --- governance story: policy tightened after analysts kept rejecting demotions
    audit(db, "governance-board", "policy_change", "policy", "demotion-gate",
          {"change": "Mandatory human approval for demotion of internet-facing, PCI-scoped or crown-jewel findings",
           "reason": "Analysts rejected 41% of automated demotions on crown-jewel assets in the prior month"},
          now_dt - timedelta(weeks=8))
    audit(db, "governance-board", "policy_change", "policy", "p0-gate",
          {"change": "Promotion to P0 requires named human confirmation", "reason": "P0 declares an emergency change"},
          now_dt - timedelta(weeks=12))

    def make(asset, title, cvss, cve, source, first_seen):
        f = Finding(asset_id=asset.id, source=source, cve=cve, title=title, cvss=cvss, first_seen=first_seen,
                    status="open", owner_team=asset.owner_team)
        ingest_finding(db, f, asset, intel.get(cve) if cve else None, ts=first_seen)
        return f

    created = []
    fresh_pairs = [("payment-gateway-api", "CVE-2023-44487", 3), ("mapleshop-web", "CVE-2023-44487", 5),
                   ("sft-gateway", "CVE-2023-34362", 7), ("corp-ad-dc01", "CVE-2020-1472", 11),
                   ("pos-region-east", "CVE-2019-0708", 20)]
    fresh_keys = set()
    for (an, cve, hrs) in fresh_pairs:
        a = by_name[an]
        v = vuln_by_cve[cve]
        f = make(a, v[1], v[2], cve, _source_for(a, "cve"), now_dt - timedelta(hours=hrs))
        created.append((f, a, True))
        fresh_keys.add((an, cve))

    # --- general population
    for a in assets:
        p = 0.9 if a.name in {k[0] for k in KEY_ASSETS} else 0.65
        for v in VULNS:
            if v[3] in a.components and (a.name, v[0]) not in fresh_keys and rng.random() < p:
                first = now_dt - timedelta(days=rng.uniform(1, 150))
                created.append((make(a, v[1], v[2], v[0], _source_for(a, "cve"), first), a, False))
        kinds = {"app": ["web", "code"], "mobile": ["mobile", "code"], "database": ["config"], "server": ["config"]}[a.asset_type]
        for kind in kinds:
            if a.environment == "dev" and rng.random() < 0.5:
                continue
            for (title, cvss) in rng.sample(LOCAL[kind], k=min(len(LOCAL[kind]), rng.randint(1, 3))):
                if kind == "web" and not a.internet_facing:
                    continue
                first = now_dt - timedelta(days=rng.uniform(1, 150))
                created.append((make(a, title, cvss, None, _source_for(a, kind), first), a, False))

    # story: unencrypted cardholder data in the customer DB
    a = by_name["customer-db-prod"]
    created.append((make(a, "Cardholder data stored without column-level encryption", 9.1, None, "db_scan",
                         now_dt - timedelta(days=21)), a, False))

    # --- human decisions on P0 candidates (older ones decided; fresh ones stay pending)
    pending_p0 = db.execute(select(Proposal).where(Proposal.status == "pending")).scalars().all()
    for p in pending_p0:
        f = db.get(Finding, p.finding_id)
        age_h = (now_dt - f.first_seen).total_seconds() / 3600
        if age_h > 30:
            decided_at = f.first_seen + timedelta(hours=rng.uniform(1, 9))
            if rng.random() < 0.9:
                decide(db, p, "approve", rng.choice(ANALYSTS), "Confirmed exposure with owner; declaring P0", decided_at)
            else:
                decide(db, p, "reject", rng.choice(ANALYSTS), "Compensating control in place (virtual patch); keep at P1", decided_at)

    # --- remediation history
    for (f, a, is_fresh) in created:
        if f.status == "open" and not is_fresh:
            _simulate_remediation(rng, db, f, a, now_dt)

    # --- historical engine proposals (for model-health analytics)
    closed = [f for (f, a, fr) in created if f.status == "remediated"]
    rng.shuffle(closed)
    reject_reasons = ["Asset is crown-jewel; keep priority until owner confirms",
                      "Compensating control in place (WAF virtual patch)",
                      "Intel signal stale; exploitation not observed in our telemetry",
                      "Duplicate of an existing tracked change"]
    approve_notes = ["Confirmed with owner", "Agree with exposure analysis", "Matches current threat briefing"]
    tiers = ["P0", "P1", "P2", "P3"]
    for f in closed[:150]:
        span = (f.remediated_at - f.first_seen).total_seconds()
        if span <= 7200:
            continue
        created_at = f.first_seen + timedelta(seconds=span * rng.uniform(0.1, 0.8))
        weeks_ago = (now_dt - created_at).total_seconds() / (7 * 86400)
        a = db.get(Asset, f.asset_id)
        to = rng.choice([t for t in tiers if t != f.tier])
        old_era = weeks_ago > 8
        demotion = tiers.index(to) > tiers.index(f.tier)
        p_ok = 0.45 if (old_era and demotion and a.crown_jewel) else (0.70 if old_era else 0.93)
        decided_at = min(created_at + timedelta(hours=rng.uniform(1, 30)), now_dt)
        p = Proposal(finding_id=f.id, kind="priority_change", origin="engine", from_tier=f.tier, to_tier=to,
                     reason="Engine rescore after intel update", status="pending", created_at=created_at,
                     requested_by="risk-engine")
        db.add(p)
        db.flush()
        audit(db, "risk-engine", "proposal_created", "proposal", p.id,
              {"finding_id": f.id, "kind": "priority_change", "from": f.tier, "to": to}, created_at)
        ok = rng.random() < p_ok
        # historical decisions don't mutate live finding state (finding already closed)
        p.status = "approved" if ok else "rejected"
        p.decided_by = rng.choice(ANALYSTS)
        p.decided_at = decided_at
        p.decision_note = rng.choice(approve_notes) if ok else (
            reject_reasons[0] if (old_era and demotion and a.crown_jewel) else rng.choice(reject_reasons))
        audit(db, p.decided_by, f"proposal_{p.status}", "proposal", p.id,
              {"finding_id": f.id, "kind": "priority_change", "from": f.tier, "to": to, "note": p.decision_note},
              decided_at)
    db.flush()

    # --- penetration testing of critical applications
    crit_apps = ["mapleshop-web", "payment-gateway-api", "checkout-service", "loyalty-api", "loyalty-app-ios",
                 "loyalty-app-android", "sft-gateway"]
    last_tested_days = {"mapleshop-web": 140, "payment-gateway-api": 340, "checkout-service": 200, "loyalty-api": 90,
                        "loyalty-app-ios": 120, "loyalty-app-android": 430, "sft-gateway": 250}
    for n in crit_apps:
        a = by_name[n]
        last = now_dt - timedelta(days=last_tested_days[n])
        db.add(Pentest(asset_id=a.id, last_tested=last, due_date=last + timedelta(days=365),
                       vendor="Independent assessor", findings_open=rng.randint(0, 4)))
    db.flush()

    # --- weekly snapshots (trend line); the latest week is filled in by reports at read time
    from .reports import posture_inputs, posture_score
    cur = posture_score(posture_inputs(db))
    base_p0 = cur["p0_open"]
    for w in range(11, -1, -1):
        wk = (now_dt - timedelta(weeks=w)).replace(hour=0, minute=0, second=0, microsecond=0)
        k = w / 11.0
        noise = rng.uniform(-1.5, 1.5) if w > 1 else 0.0
        db.add(Snapshot(week_start=wk, posture_score=round(max(20, cur["score"] - 17 * k + noise), 1),
                        p0_open=max(0, int(round(base_p0 + 9 * k + rng.uniform(-1, 1)))),
                        overdue_open=max(0, int(round(cur["overdue_open"] + 22 * k + rng.uniform(-2, 2)))),
                        sla_pct=round(min(99, max(40, cur["sla_pct"] - 18 * k + rng.uniform(-2, 2))), 1),
                        kev_open=max(0, int(round(cur["kev_open"] + 7 * k + rng.uniform(-1, 1)))),
                        ext_rating=round(min(99, max(30, cur["ext_rating"] - 14 * k + rng.uniform(-2, 2))), 1)))
    db.commit()
    return {"assets": len(assets), "findings": len(created) + 1}
