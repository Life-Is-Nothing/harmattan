# Changelog

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
