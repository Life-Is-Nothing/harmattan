# HARMATTAN v3 — Network Intelligence Suite

Outil professionnel d’audit réseau : découverte ARP enrichie, nmap asynchrone,
topologie hiérarchique, surface d’attaque scorée, corrélation CVE (NVD + cache),
capture de trafic, outils diagnostics, rapports HTML/JSON et persistance SQLite.

> ⚠️ **Usage strictement réservé à l’audit de réseaux dont vous avez l’autorisation
> explicite.** L’utilisation contre des réseaux tiers sans consentement est illégale.

**Auteur :** Mohamed Adoungouss Ibrahim / NACF

---

## Fonctionnalités

| Module | Description |
|---|---|
| **Dashboard** | Scan maison 1-clic, score/grade, historique, nouveaux appareils |
| **Découverte ARP** | Broadcast + OUI, hostname, TTL/OS, ports, SNMP, rôles (IoT/cam/print…) |
| **Scan Nmap** | 10 profils, jobs async + progression + annulation, args whitelistés |
| **Topologie** | Graphe hiérarchique (clients → AP → gateway → Internet), live léger |
| **Attack Surface** | Ports sensibles, scoring 0–100, grade A–F, recommandations |
| **Vulnérabilités** | NVD API + cache SQLite, agrégation par sévérité |
| **Trafic** | Capture thread-safe (deque), top flux, ports, BPF, CSV |
| **Outils** | Ping, traceroute, banner, DNS, TLS cert inspect |
| **Rapports** | HTML pro, JSON, export session complète |
| **Sécurité** | Token API, validation stricte, XSS escaped, headers sécurité |

---

## Installation

### Prérequis

```bash
sudo apt install nmap python3-venv python3-pip traceroute iproute2
```

### Lancement rapide

```bash
cd harmattan
chmod +x harmattan.sh
sudo ./harmattan.sh
```

Ouvrez `http://127.0.0.1:8088` — le token API est affiché dans le terminal
et injecté automatiquement en cookie navigateur.

### Variables d’environnement

| Variable | Défaut | Rôle |
|---|---|---|
| `HARMATTAN_HOST` | `127.0.0.1` | Bind address |
| `HARMATTAN_PORT` | `8088` | Port HTTP |
| `HARMATTAN_TOKEN` | (auto) | Token API fixe |
| `HARMATTAN_AUTO_TOKEN` | `1` | Génère un token si absent |
| `NVD_API_KEY` | — | Accélère la corrélation CVE |
| `HARMATTAN_DATA` | `./data` | SQLite + logs |
| `HARMATTAN_SNMP_COMMUNITIES` | `public,private` | Communautés SNMP |

### Docker

```bash
docker compose up --build
# network_mode: host pour découvrir le LAN
```

---

## Utilisation

1. **Scan maison** (Dashboard) — ARP + fingerprint + nmap gateway.
2. **Découverte ARP** — filtre table, détail hôte (drawer).
3. **Nmap** — choisir profil, suivre la barre de progression, annuler si besoin.
4. **Topologie** — clic nœud → fiche hôte ; live monitoring ARP léger.
5. **Attack Surface** — grade + recommandations de durcissement.
6. **CVE** — après un scan `-sV` (profil *service* / *vulners*).
7. **Exports** — HTML, JSON, session, CSV topologie/trafic.

### Raccourcis clavier

| Touche | Action |
|---|---|
| `s` | Scan maison |
| `1`–`4` | Vues dashboard / ARP / nmap / topologie |
| `Esc` | Fermer le panneau hôte |

---

## Architecture

```
harmattan/
├── app.py                 # Flask API + auth + jobs
├── core/
│   ├── config.py          # Configuration / env
│   ├── validation.py      # Validation anti-injection
│   ├── jobs.py            # File d'attente async
│   ├── db.py              # SQLite (scans, CVE cache, hosts)
│   ├── state.py           # État thread-safe
│   └── logging_setup.py
├── modules/               # Scanners & analyse
├── templates/index.html
├── static/{css,js}/
├── tests/
├── Dockerfile
└── docker-compose.yml
```

### API (aperçu)

| Méthode | Endpoint | Description |
|---|---|---|
| GET | `/api/health` | Healthcheck |
| GET | `/api/system-check` | Scapy/nmap/root/réseau |
| POST | `/api/home-scan` | Pipeline maison → `{job_id}` |
| POST | `/api/arp-scan` | Scan ARP async |
| POST | `/api/nmap-scan` | Scan nmap async |
| GET | `/api/jobs/<id>` | Statut + résultat |
| POST | `/api/jobs/<id>/cancel` | Annuler |
| GET | `/api/attack-surface` | Surface d’attaque |
| GET | `/api/topology` | Graphe |
| POST | `/api/vuln-scan` | Corrélation CVE |
| GET | `/api/report.html` | Rapport HTML |
| GET | `/api/report.json` | Rapport JSON |
| GET | `/api/session/export` | Session complète |

Header auth : `X-Harmattan-Token: <token>`

---

## Tests

```bash
./venv/bin/pip install -r requirements-dev.txt
./venv/bin/pytest -q
```

---

## Notes de performance & sécurité

- Jobs async : l’UI ne bloque plus pendant nmap/ARP/CVE.
- Buffer trafic borné (`deque`, 5000 paquets).
- Cache CVE SQLite (24 h).
- Arguments nmap whitelistés (pas d’injection shell).
- Bind local par défaut ; token obligatoire en auto.
- ARP / sniff : `sudo` ou capabilities `CAP_NET_RAW`.

```bash
sudo setcap cap_net_raw,cap_net_admin+eip $(readlink -f ./venv/bin/python)
```

---

## Licence

Projet original pour NACF (Niger Anonymous Cyber Force).  
Libre d’utilisation et de modification dans un cadre d’audit éthique et autorisé.
