from modules.attack_surface import build_attack_surface


def test_attack_surface_basic():
    arp = [
        {
            "ip": "192.168.1.10",
            "mac": "aa:bb:cc:dd:ee:ff",
            "vendor": "Test",
            "hostname": "pc",
            "role": "pc",
            "os_hint": "linux/macos",
            "open_ports": [22, 80],
        }
    ]
    nmap = [
        {
            "ip": "192.168.1.10",
            "ports": [
                {"port": "22", "protocol": "tcp", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.0", "scripts": []},
                {"port": "23", "protocol": "tcp", "state": "open", "service": "telnet", "product": "", "version": "", "scripts": []},
            ],
            "hostnames": [],
            "os_matches": [],
        }
    ]
    report = build_attack_surface(arp, nmap)
    assert report["total_exposures"] >= 2
    assert report["grade"] in list("ABCDF")
    assert any(e["port"] == 23 for h in report["hosts"] for e in h["exposures"])
    assert report["recommendations"]
