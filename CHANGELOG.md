# Changelog

## 3.8.0 — Scheduler + HTTP stream + suite compose

### Ops
- **Scheduler ARP** planifié (intervalle + rapport HTML auto dans `reports/`)
- API `/api/scheduler/start|stop|status` · bouton UI **⏱ Scheduler**

### Trafic
- **Reassemblage HTTP** dans Follow stream (request/response pretty)

### Docs
- `openapi.yaml` (aperçu API)
- `~/docker-compose.suite.yml` (Network + Sahel + Cortex)

## 3.7.0 — L0p4Map parity + nouvelles features

### L0p4Map → HARMATTAN
- **Range cartography** : CIDR/plage → ping sweep + parent traceroute
- **Default-cred detection** : iLO, iDRAC, IPMI, Zebra, Hikvision, XPort…
- **Labels custom** nœuds topologie (+ API)
- **Arêtes typées** uplink/backbone/client + **subnet_boxes** meta
- Parents multi-hop sur le graphe (stubs routeur)

### Nouvelles features
- **Wake-on-LAN** (`/api/wol`)
- **Actions rapides** hôte : ping / traceroute / nmap / WOL
- **Findings** notebook par hôte (SQLite)
- UI topologie enrichie (label, cred flags, quick actions)

## 3.6.0 — Export stream + corrélation Sahel

### Trafic
- Export follow-stream **TXT** / **JSON** (téléchargement + copie `reports/`)
- Bouton **⇄ Corréler Sahel** : match IP/ports alertes ↔ paquets
- API `/api/sahel/correlate`, `/api/traffic/follow/<n>/export.txt|json`

## 3.5.0 — Follow TCP stream + stats protocoles

### Trafic Wireshark+
- **Follow stream** (TCP/UDP) : reconstitution conversation + payload
- Stats protocoles (barres DNS/HTTP/TLS/…)
- Bouton **Vider** le buffer
- API `/api/traffic/follow/<no>`, `/api/traffic/clear`, `/api/traffic/proto-stats`

## 3.4.0 — Trafic mode Wireshark

### Trafic
- Dissection paquets : Ethernet · IP · TCP/UDP · DNS · HTTP · TLS · ARP · ICMP · DHCP
- UI 3 panneaux : **Packet List** · **Packet Details** · **Packet Bytes** (hex)
- Filtre display (dns, http, tcp.port == 443, ip.addr == …)
- API `/api/traffic/packets` + `/api/traffic/packet/<no>`
- Colonnes No / Time / Source / Destination / Protocol / Length / Info

## 3.3.0 — Intel pack (discovery · MITRE · ML · STIX)

### Discovery
- SNMP v2c probe (UDP natif + snmpget si dispo) batch / unitaire
- NetBIOS name (UDP 137 + nmblookup) + enrichissement hostname ARP
- LLDP/CDP sniff Scapy (root/CAP_NET_RAW)
- Scan Wi‑Fi (nmcli / iw)

### Detection & scoring
- Mapping **MITRE ATT&CK** (ports, rôles, nouveaux appareils)
- **IsolationForest** (scikit-learn) + fallback heuristique
- Intégration **Suricata** eve.json (lecture seule)
- Bridge live **SAHEL SHIELD** (push périodique)

### Export
- **STIX 2.1** bundle (identity, infrastructure, indicators, attack-pattern)
- **GraphML** + **GEXF** topologie (Gephi)

### UI
- Vue **08 Intel** : discovery, anomalies, MITRE, Suricata, bridge

## 3.2.0 — Topology pro + inventory pack

### Topology
- Icônes SVG par type d’appareil (Android, Apple, server, TV, IoT…)
- Légende cliquable (filtre par rôle)
- Mode présentation plein écran (`P` / Esc)
- Export topologie PNG + CSV
- Override manuel rôle / tags / notes (SQLite `host_overrides`)

### Inventory & integrations
- Historique scans rechargeable (`/api/scans`, load)
- Push inventaire vers SAHEL SHIELD + export JSON fallback
- Export scope PT
- Monitor ARP continu (background)
- Panel santé système (Scapy, Nmap, auth, jobs, overrides)
- Settings persistants (`sahel_url`, theme)

### Fingerprinting
- Android classé avant TV (fix Samsung TV)

## 3.0.0 — Professional release

### Security
- Token API (auto ou `HARMATTAN_TOKEN`) + cookie HttpOnly
- Validation stricte IP/CIDR/hostname/ports/BPF
- Whitelist des arguments nmap (anti-injection)
- XSS escaped côté frontend
- Headers `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`

### Architecture
- Jobs asynchrones avec progression et annulation
- SQLite : historique, scans, cache CVE, known hosts
- État thread-safe, logging rotatif
- Config centralisée (`core/config.py`)

### Features
- Score / grade attack surface + recommandations
- Détection nouveaux appareils (MAC tracking)
- Rôles IoT / caméra / imprimante
- Outils DNS + TLS inspect
- Rapports HTML + JSON + export session
- Live monitoring ARP léger
- Drawer détail hôte, filtres tables, toasts, raccourcis clavier
- Topologie : clients rattachés à l’AP

### Packaging
- Docker + compose (host network)
- pytest suite
- README pro, `.gitignore`, script de lancement amélioré

## 2.0.0 — Initial unified suite
- ARP, nmap, topologie, CVE, trafic, dashboard
