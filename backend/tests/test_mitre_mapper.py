from app.security.mitre_mapper import get_mitre_mapping


def test_port_scan_mitre_mapping():
    result = get_mitre_mapping("PORT_SCAN")

    assert result["mapped"] is True
    assert result["technique_id"] == "T1046"
    assert result["technique"] == "Network Service Scanning"
    assert result["tactic"] == "Discovery"


def test_brute_force_mitre_mapping():
    result = get_mitre_mapping("BRUTE_FORCE")

    assert result["mapped"] is True
    assert result["technique_id"] == "T1110"
    assert result["technique"] == "Brute Force"


def test_ddos_mitre_mapping():
    result = get_mitre_mapping("DDOS")

    assert result["mapped"] is True
    assert result["technique_id"] == "T1498"


def test_unknown_attack_is_safe():
    result = get_mitre_mapping("SOMETHING_NEW")

    assert result["mapped"] is False
    assert result["technique_id"] is None