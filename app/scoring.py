"""Transparent, explainable risk engine.

Score 0-100 = technical severity + threat intel + exposure + business context.
Every point is attributable to a named factor, and the rationale is generated
from those factors, so analysts, executives and assessors can all inspect it.
"""
from dataclasses import dataclass

TIER_THRESHOLDS = [(80, "P0"), (55, "P1"), (35, "P2"), (0, "P3")]
SLA_DAYS = {"P0": 3, "P1": 14, "P2": 30, "P3": 90}
TIER_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}

W = {
    "severity": 30.0,       # CVSS/10 * 30
    "kev": 20.0,            # known exploited in the wild
    "epss": 12.0,           # exploit probability * 12
    "exploit_public": 5.0,
    "campaign": 4.0,        # active named campaign
    "internet": 10.0,
    "pci": 7.0,
    "crown": 7.0,
    "criticality_step": 1.5,  # (criticality-1) * 1.5, max 6
    "cardholder": 8.0,
    "pii": 5.0,
}


@dataclass
class ScoreResult:
    score: float
    tier: str
    factors: list
    rationale: str


def tier_for(score: float) -> str:
    for threshold, tier in TIER_THRESHOLDS:
        if score >= threshold:
            return tier
    return "P3"


def score_finding(cvss: float, asset, intel) -> ScoreResult:
    factors = []

    def add(name, label, pts):
        if pts > 0:
            factors.append({"name": name, "label": label, "points": round(pts, 1)})

    sev = cvss / 10.0 * W["severity"]
    add("severity", f"CVSS {cvss}", sev)

    if intel is not None:
        if intel.kev:
            add("kev", "known exploited in the wild", W["kev"])
        if intel.epss and intel.epss > 0:
            add("epss", f"{round(intel.epss * 100)}% exploit likelihood", intel.epss * W["epss"])
        if intel.exploit_public:
            add("exploit_public", "public exploit available", W["exploit_public"])
        if intel.campaign:
            add("campaign", f"active campaign: {intel.campaign}", W["campaign"])

    if asset.internet_facing:
        add("internet", "internet-facing", W["internet"])
    if asset.pci_scope:
        add("pci", "PCI scope", W["pci"])
    if asset.crown_jewel:
        add("crown", "crown-jewel asset", W["crown"])
    add("criticality", f"asset criticality {asset.criticality}/5", (asset.criticality - 1) * W["criticality_step"])
    if asset.data_class == "cardholder":
        add("data", "handles cardholder data", W["cardholder"])
    elif asset.data_class == "pii":
        add("data", "handles customer PII", W["pii"])

    total = min(100.0, round(sum(f["points"] for f in factors), 1))
    tier = tier_for(total)
    return ScoreResult(total, tier, factors, _rationale(cvss, tier, total, factors, sev))


def _rationale(cvss, tier, total, factors, sev):
    drivers = sorted((f for f in factors if f["name"] != "severity"), key=lambda f: -f["points"])
    top = [f for f in drivers if f["points"] >= 3][:4]
    if not top:
        text = f"{tier} (score {total}). Driven by CVSS alone; no known exploitation and no exposure or business-context signals."
    else:
        parts = "; ".join(f"{f['label']} (+{f['points']})" for f in top)
        text = f"{tier} (score {total}). Drivers: {parts}. CVSS {cvss} contributes +{round(sev, 1)}."
    if cvss >= 9.0 and tier in ("P2", "P3"):
        text += f" Deprioritized despite CVSS {cvss}: no evidence of exploitation and low exposure."
    if cvss < 9.0 and tier in ("P0", "P1"):
        text += " Elevated above what CVSS alone would suggest."
    return text


def sla_days(tier: str) -> int:
    return SLA_DAYS[tier]
