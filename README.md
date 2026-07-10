# 🌪️ HARMATTAN — Network Intelligence Suite

[![Python](https://img.shields.io/badge/Python-3.12-blue?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.x-black?logo=flask)](https://flask.palletsprojects.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Ethics](https://img.shields.io/badge/Use-Authorized%20only-orange)](#ethics)

**Professional network reconnaissance & visualization** for authorized audits.  
ARP discovery, nmap integration, attack surface scoring, CVE correlation, live traffic, topology graph, and **HTML / PDF / DOCX** reports.

> Part of the [HARMATTAN Suite](https://github.com/Life-Is-Nothing/harmattan-suite)

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
| **Topology icons** | Icônes par type (Android, Apple, PC, AP, caméra…) |
| **Monitor ARP** | Scan périodique + alerte hub nouveaux hôtes |
| **Export SAHEL / PT** | JSON pour Sahel Shield · scope pour HARMATTAN-PT |
| **Intel pack v3.3** | SNMP · NetBIOS · LLDP/CDP · Wi‑Fi · MITRE · IsolationForest · Suricata · STIX · GraphML |
| **SAHEL bridge** | Push inventaire périodique vers Sahel Shield |
| **L0p4Map parity v3.7** | Range map multi-hop · default-cred · labels · WOL · findings · quick actions |

### Topologie & Intel

- Icônes SVG : Android · Apple · PC · Serveur · Imprimante · Caméra · IoT · TV · AP…
- Vue **Intel** : discovery avancée, anomalies ML, mapping MITRE ATT&CK, Suricata eve.json
- Exports : STIX 2.1, GraphML/GEXF, PNG topologie

---

## Quick start

```bash
git clone https://github.com/Life-Is-Nothing/harmattan.git
cd harmattan
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
sudo apt install nmap   # recommended
chmod +x harmattan.sh
sudo ./harmattan.sh     # root needed for ARP / sniff
```

Open **http://127.0.0.1:8088**

> ARP & packet capture require root (or `CAP_NET_RAW`). Nmap/CVE work without root with reduced features.

---

## Architecture

```text
harmattan/
├── app.py              # Flask API + dashboard
├── core/               # config, jobs, db, validation, alerts
├── modules/            # scanners & analysis
├── templates/ + static/
└── tests/
```

---

## Suite

| Repo | Role |
|---|---|
| [harmattan-pt](https://github.com/Life-Is-Nothing/harmattan-pt) | Full pentest platform |
| [harmattan-locate](https://github.com/Life-Is-Nothing/harmattan-locate) | Consent location sharing |
| [harmattan-hub](https://github.com/Life-Is-Nothing/harmattan-hub) | Unified hub & alerts |

---

## Ethics

**Authorized networks only.** Unauthorized scanning is illegal.  
Built for labs, training, and professional engagements with written permission.

---

## Author

**Mohamed Adoungouss Ibrahim** · NACF · Niger  
GitHub: [@Life-Is-Nothing](https://github.com/Life-Is-Nothing)

## License

MIT — see [LICENSE](LICENSE)
