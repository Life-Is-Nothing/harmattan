# 🌪️ HARMATTAN — Network Intelligence Suite

[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ethics](https://img.shields.io/badge/Use-Authorized%20only-orange)](#ethics)

**Professional network reconnaissance & visualization** for authorized audits.
ARP discovery, nmap integration, attack surface scoring, CVE correlation, live traffic, topology graph, and **HTML / PDF / DOCX** reports.

> Part of the [HARMATTAN Suite](https://github.com/Life-Is-Nothing/harmattan-suite) · Companion UI: **HARMATTAN 4** (`~/harmattan4`, port **8040**)

---

## Features

| Module | Description |
|---|---|
| **ARP Discovery** | Fast broadcast scan + OUI vendor, hostname, TTL/OS, role inference |
| **Nmap** | Multiple profiles (service, OS, vuln NSE, UDP…) with async jobs |
| **Attack Surface** | Risk scoring, grade A–F, remediation hints |
| **CVE** | NVD correlation with local cache |
| **Topology** | Interactive hierarchical graph (vis-network) |
| **Traffic** | Live capture, top flows, CSV + **PCAP** export |
| **Diff ARP** | New / gone / changed hosts between scans |
| **mDNS / SSDP** | Lightweight IoT discovery |
| **Reports** | Client-ready HTML, PDF, Word |
| **Intel pack** | SNMP · NetBIOS · LLDP/CDP · Wi‑Fi · MITRE · IsolationForest · Suricata · STIX · GraphML |
| **OT / IPv6** | ICS probes + IPv6 neighbor discovery |
| **Metrics** | `/api/metrics` JSON + Prometheus text |
| **AI Analyst** | Cognitive network analysis with MITRE mapping |
| **Auth** | Web login/password + token API auth + multi-role (admin/viewer/scanner) |

### v3.22 — New

| Feature | Description |
|---|---|
| **Cyberpunk Dark Mode** | Full neon theme (cyan/pink/purple) with scanlines, glow, animations |
| **Global Search** | `Ctrl+K` fuzzy search across hosts, scans, tools, navigation |
| **Loading Skeletons** | Animated placeholders during data loading |
| **Dashboard Charts** | CSS-only bar/donut charts for scan history & risk distribution |
| **Modular Frontend** | app.js split into 16 focused JS modules |
| **CI/CD** | GitHub Actions for lint (ruff) + tests (pytest) |
| **Pre-commit** | Automated linting and formatting hooks |

---

## Quick start

```bash
cd ~/harmattan
./harmattan.sh            # CAP_NET_RAW on python3.12 or use sudo -E ./harmattan.sh
# Full suite:
~/suite.sh start
```

Open **http://127.0.0.1:8088** (Network) · **http://127.0.0.1:8077** (Hub) · **http://127.0.0.1:8040** (H4 Command Center)

### Auth (v3.22+)

Web UI: login page at `/login` with admin/admin (change on first login).
API: Token stored in `data/.api_token` and reused across restarts.

```bash
# Web login
open http://127.0.0.1:8088/login

# API with token
curl -H "X-Harmattan-Token: $(cat data/.api_token)" http://127.0.0.1:8088/api/health
curl http://127.0.0.1:8088/api/metrics
```

Rate limit: `HARMATTAN_RATE_LIMIT` (default **180**/min/IP). Set `0` to disable.

### Roles

| Role | Access |
|---|---|
| **admin** | Full access — scans, exports, user management, settings |
| **viewer** | Read-only — view results, no scan/export actions |
| **scanner** | Run scans only — no admin/export access |

---

## Architecture (v3.22)

```text
harmattan/
├── app.py                 # Flask factory, SocketIO, preflight
├── api/                   # Blueprints (system, scan, traffic, intel, …)
├── core/                  # auth, jobs (SQLite), db, metrics, validation
├── modules/               # scanners & analysis
├── templates/ + static/
│   ├── css/               # style, modern, dark-mode, skeletons, search, charts
│   └── js/                # 16 modular JS files (ui, arp, nmap, topology…)
└── tests/
```

### Frontend Modules (v3.22)

| Module | Responsibility |
|---|---|
| `ui.js` | Helpers, navigation, keyboard shortcuts, dark mode |
| `jobs.js` | Async job polling and progress bar |
| `dashboard.js` | Dashboard stats, network context, health panel |
| `arp.js` | ARP scan UI and results rendering |
| `nmap.js` | Nmap scan configuration and results |
| `attack.js` | Attack surface display and scoring |
| `vuln.js` | CVE correlation results |
| `traffic.js` | Wireshark-like packet capture and analysis |
| `tools.js` | Network utility tools (ping, DNS, TLS…) |
| `topology.js` | Interactive network graph (vis-network) |
| `drawer.js` | Host detail sidebar |
| `intel.js` | SNMP, MITRE, ML anomaly detection |
| `ai.js` | AI-powered network analysis |
| `sahel.js` | SAHEL Shield integration |
| `cleanup.js` | Host/history management |
| `init.js` | Global state initialization |

**v3 vs H4:** Network v3 (`:8088`) is the scan engine. HARMATTAN 4 (`:8040`) is the command center and syncs inventory via `/api/suite/sync-arp`.

---

## Development

```bash
# Install pre-commit hooks
cd ~/harmattan
pip install pre-commit ruff
pre-commit install

# Run linting
ruff check .

# Run tests
python -m pytest tests/ -v

# Update from git
./scripts/harmattan-update.sh
```

---

## Suite

| Repo | Role |
|---|---|
| [harmattan-pt](https://github.com/Life-Is-Nothing/harmattan-pt) | Full pentest platform |
| [harmattan-locate](https://github.com/Life-Is-Nothing/harmattan-locate) | Consent location sharing |
| [harmattan-hub](https://github.com/Life-Is-Nothing/harmattan-hub) | Unified hub & alerts |
| `~/harmattan4` | Command Center (bridge to v3) |

---

## Ethics

**Authorized networks only.** Unauthorized scanning is illegal.
Built for labs, training, and professional engagements with written permission.

---

## Author

**Mohamed Adoungouss Ibrahim** · NACF · Niger
GitHub: [@Life-Is-Nothing](https://github.com/Life-Is-Nothing)

## License

MIT — see [LICENSE]
