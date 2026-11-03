from types import SimpleNamespace as NS

from app import governance
from app.scoring import score_finding

def asset(**kw):
    base = dict(internet_facing=False, pci_scope=False, crown_jewel=False, criticality=1, data_class="internal")
    base.update(kw)
    return NS(**base)

def intel(**kw):
    base = dict(kev=False, epss=0.0, exploit_public=False, campaign=None)
    base.update(kw)
    return NS(**base)


def test_cvss_critical_on_dev_box_without_exploit_is_deprioritized():
    r = score_finding(9.8, asset(), intel(epss=0.02))
    assert r.tier == "P3"
    assert "Deprioritized despite CVSS" in r.rationale


def test_known_exploited_on_exposed_pci_asset_is_p0_even_with_high_cvss_only():
    r = score_finding(7.5, asset(internet_facing=True, pci_scope=True, crown_jewel=True, criticality=5,
                                 data_class="cardholder"), intel(kev=True, epss=0.82, exploit_public=True))
    assert r.tier == "P0"
    assert "Elevated above what CVSS alone would suggest" in r.rationale


def test_rationale_names_its_drivers():
    r = score_finding(6.5, asset(internet_facing=True), intel(kev=True, epss=0.5))
    assert "known exploited" in r.rationale and "internet-facing" in r.rationale
    assert abs(sum(f["points"] for f in r.factors) - r.score) < 0.5 or r.score == 100.0


def test_gates():
    exposed = asset(internet_facing=True)
    internal = asset()
    assert governance.gate_reason("P1", "P0", internal)            # P0 always gated
    assert governance.gate_reason("P1", "P2", exposed)             # demoting exposed asset is gated
    assert governance.gate_reason("P1", "P2", asset(pci_scope=True))
    assert governance.gate_reason("P1", "P2", asset(crown_jewel=True))
    assert governance.gate_reason("P1", "P2", internal) is None    # demoting a plain internal asset is not
    assert governance.gate_reason("P2", "P1", exposed) is None     # promoting to P1 is automatic
