from modules.nmap_scanner import _parse_nmap_xml

SAMPLE = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.5" addrtype="ipv4"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="TestCo"/>
    <hostnames><hostname name="host.local"/></hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_prefers_ipv4():
    result = _parse_nmap_xml(SAMPLE, "now", "quick", "192.168.1.5")
    assert result["count"] == 1
    h = result["hosts"][0]
    assert h["ip"] == "192.168.1.5"
    assert h["mac"] == "AA:BB:CC:DD:EE:FF"
    assert h["ports"][0]["service"] == "http"
