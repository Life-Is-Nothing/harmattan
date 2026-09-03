"""API endpoint URL constants for HARMATTAN Desktop GUI."""

BASE_URL = "http://127.0.0.1:8088"
API_PREFIX = "/api/v1"

# System
HEALTH = f"{API_PREFIX}/health"
PREFLIGHT = f"{API_PREFIX}/preflight"
STREAM = f"{API_PREFIX}/stream"
SHUTDOWN = f"{API_PREFIX}/shutdown"
NETWORK_INFO = f"{API_PREFIX}/network-info"
METRICS = f"{API_PREFIX}/metrics"

# Jobs
JOBS = f"{API_PREFIX}/jobs"
JOBS_CANCEL = f"{API_PREFIX}/jobs/{{job_id}}/cancel"  # .format(job_id=...)

# ARP / Discovery
ARP_SCAN = f"{API_PREFIX}/arp-scan"
HOME_SCAN = f"{API_PREFIX}/home-scan"
KNOWN_HOSTS = f"{API_PREFIX}/known-hosts"
DIFF_ARP = f"{API_PREFIX}/diff/arp"

# Nmap
NMAP_SCAN = f"{API_PREFIX}/nmap-scan"
NMAP_PROFILES = f"{API_PREFIX}/nmap-profiles"

# Vuln / Attack
VULN_SCAN = f"{API_PREFIX}/vuln-scan"
ATTACK_SURFACE = f"{API_PREFIX}/attack-surface"
FINDINGS = f"{API_PREFIX}/findings"

# Topology
TOPOLOGY = f"{API_PREFIX}/topology"
HOST_DETAIL = f"{API_PREFIX}/hosts/{{ip}}"

# Traffic
TRAFFIC_START = f"{API_PREFIX}/traffic/start"
TRAFFIC_STOP = f"{API_PREFIX}/traffic/stop"
TRAFFIC_ONESHOT = f"{API_PREFIX}/traffic/oneshot"
TRAFFIC_PACKETS = f"{API_PREFIX}/traffic/packets"
TRAFFIC_SNAPSHOT = f"{API_PREFIX}/traffic/snapshot"
TRAFFIC_PROTO_STATS = f"{API_PREFIX}/traffic/proto-stats"
TRAFFIC_CLEAR = f"{API_PREFIX}/traffic/clear"

# Intel
INTEL_SUMMARY = f"{API_PREFIX}/intel/summary"
MITRE = f"{API_PREFIX}/mitre"
SCORE_HOSTS = f"{API_PREFIX}/score/hosts"
WIFI_SCAN = f"{API_PREFIX}/wifi/scan"
SNMP_PROBE = f"{API_PREFIX}/snmp/probe"
NETBIOS_PROBE = f"{API_PREFIX}/netbios/probe"
LLDP_CDP = f"{API_PREFIX}/lldp-cdp"

# AI
AI_ANALYZE = f"{API_PREFIX}/ai-analyze"
AI_HOST = f"{API_PREFIX}/ai-host/{{ip}}"
REMEDIATION = f"{API_PREFIX}/remediation/script/{{ip}}"

# Tools
TOOLS_CATALOG = f"{API_PREFIX}/tools/catalog"
TOOLS_PING = f"{API_PREFIX}/tools/ping"
TOOLS_TRACEROUTE = f"{API_PREFIX}/tools/traceroute"
TOOLS_BANNER = f"{API_PREFIX}/tools/banner"
TOOLS_DNS = f"{API_PREFIX}/tools/dns"
TOOLS_TLS = f"{API_PREFIX}/tools/tls"
TOOLS_PORT_CHECK = f"{API_PREFIX}/tools/port-check"
TOOLS_PORT_SCAN = f"{API_PREFIX}/tools/port-scan"
TOOLS_WHOIS = f"{API_PREFIX}/tools/whois"
TOOLS_MAC = f"{API_PREFIX}/tools/mac"
TOOLS_SSH_KEYSCAN = f"{API_PREFIX}/tools/ssh-keyscan"

# Notifications
NOTIFICATIONS = f"{API_PREFIX}/notifications"
ALERT_RULES = f"{API_PREFIX}/alerts/rules"
NOTIFICATION_CHANNELS = f"{API_PREFIX}/notification-channels"

# Settings
SETTINGS = f"{API_PREFIX}/settings"

# Export / Reports
REPORT_HTML = f"{API_PREFIX}/report.html"
REPORT_PDF = f"{API_PREFIX}/report.pdf"
REPORT_DOCX = f"{API_PREFIX}/report.docx"
REPORT_JSON = f"{API_PREFIX}/report.json"
EXPORT_CSV = f"{API_PREFIX}/export/csv"
EXPORT_XLSX = f"{API_PREFIX}/export/xlsx"
EXPORT_MD = f"{API_PREFIX}/export/markdown"
EXPORT_STIX = f"{API_PREFIX}/export/stix"
EXPORT_GRAPHML = f"{API_PREFIX}/export/graphml"
EXPORT_SAHEL = f"{API_PREFIX}/export/sahel"

# History / Scans
HISTORY = f"{API_PREFIX}/history"
SCANS = f"{API_PREFIX}/scans"

# Plugins
PLUGINS = f"{API_PREFIX}/plugins"
