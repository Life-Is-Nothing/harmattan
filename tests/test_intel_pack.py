"""Intel pack: MITRE, scoring, STIX, GraphML, SNMP encode."""
from modules.mitre_map import map_network
from modules.host_scoring import score_hosts
from modules.export_stix import build_bundle
from modules.export_graphml import build_graphml, build_gexf
from modules.snmp_probe import build_snmp_get, OID_SYSDESCR


def test_mitre_maps_rdp_and_camera():
    arp = [{"ip": "10.0.0.5", "role": "camera", "mac": "AA:BB:CC:00:00:01"}]
    nmap = [
        {
            "ip": "10.0.0.5",
            "ports": [
                {"port": 3389, "state": "open", "service": "ms-wbt-server"},
                {"port": 554, "state": "open", "service": "rtsp"},
            ],
        }
    ]
    m = map_network(arp, nmap, {}, [])
    ids = {t["technique_id"] for t in m["techniques"]}
    assert "T1021.001" in ids  # RDP
    assert m["technique_count"] >= 1


def test_score_hosts_flags_sensitive():
    arp = [
        {"ip": "10.0.0.1", "role": "pc", "mac": "11:11:11:11:11:11"},
        {"ip": "10.0.0.2", "role": "pc", "mac": "22:22:22:22:22:22"},
        {"ip": "10.0.0.3", "role": "iot", "mac": "33:33:33:33:33:33"},
        {
            "ip": "10.0.0.99",
            "role": "server",
            "mac": "99:99:99:99:99:99",
        },
    ]
    nmap = [
        {"ip": "10.0.0.1", "ports": [{"port": 80, "state": "open"}]},
        {"ip": "10.0.0.2", "ports": [{"port": 443, "state": "open"}]},
        {"ip": "10.0.0.3", "ports": [{"port": 1883, "state": "open"}]},
        {
            "ip": "10.0.0.99",
            "ports": [
                {"port": 23, "state": "open"},
                {"port": 445, "state": "open"},
                {"port": 3389, "state": "open"},
                {"port": 1433, "state": "open"},
            ],
        },
    ]
    s = score_hosts(arp, nmap)
    assert s["ok"]
    assert s["host_count"] == 4
    # high-risk host should rank high
    top = s["hosts"][0]
    assert top["ip"] in ("10.0.0.99", "10.0.0.3")


def test_stix_bundle():
    arp = [{"ip": "10.0.0.1", "mac": "aa:bb:cc:dd:ee:ff", "role": "pc", "hostname": "pc1"}]
    nmap = [{"ip": "10.0.0.1", "ports": [{"port": 445, "state": "open", "service": "smb"}]}]
    b = build_bundle(arp, nmap, {"techniques": [{"technique_id": "T1021.002", "technique": "SMB", "count": 1}]})
    assert b["type"] == "bundle"
    types = {o["type"] for o in b["objects"]}
    assert "identity" in types
    assert "infrastructure" in types
    assert "indicator" in types


def test_graphml_gexf():
    nodes = [{"id": "a", "label": "A", "role": "pc"}, {"id": "b", "label": "B", "role": "gateway"}]
    edges = [{"from": "a", "to": "b"}]
    g = build_graphml(nodes, edges)
    assert "<graphml" in g and 'id="a"' in g
    x = build_gexf(nodes, edges)
    assert "<gexf" in x and 'id="a"' in x


def test_snmp_packet_builds():
    pkt = build_snmp_get("public", OID_SYSDESCR)
    assert isinstance(pkt, (bytes, bytearray))
    assert len(pkt) > 20
    assert b"public" in pkt
