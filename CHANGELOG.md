# Changelog

## 3.22.0 — Major Refactoring & Improvements

### Architecture · Frontend
- **app.js split** : le monolithe 3665 lignes est découpé en 18 modules JS séparés (ui, arp, nmap, topology, traffic, ai, tools, intel, drawer, attack, vuln, dashboard, sahel, cleanup, diff, export, jobs, init)
- **Router JS** : navigation par modules avec chargement ordonné
- **Séparation des responsabilités** : chaque feature a son propre fichier

### Sécurité
- **Auth web** : login/password avec sessions Flask (page login cyberpunk)
- **Multi-rôles** : admin (tout), viewer (lecture seule), scanner (scans seulement)
- **Users DB** séparée (users.db) avec mots de passe hashés (werkzeug)
- **Rate limiting frontend** : debounce/throttle sur les appels API

### UX · Interface
- **Dark mode cyberpunk complet** : thème néon cyan/rose/violet avec scanlines, glow, animations
- **Loading skeletons** : placeholders animés pendant le chargement des données
- **Global search Ctrl+K** : fuzzy search sur hosts, scans, outils, navigation
- **Dashboard charts** : visualisations CSS pures (bar chart scans, donut risques, évolution hôtes)
- **Scrollbars custom** neon, toasts avec glow, LED animées

### Santé Système
- **Health check amélioré** : vérification DB, disque, mémoire, uptime, dernier scan
- **/api/health** retourne un JSON structuré avec statut par composant

### Tests & Qualité
- **Nouveaux tests unitaires** : arp_scanner, nmap_scanner, topology, traffic_analyzer, attack_surface, db, auth
- **65+ nouveaux test functions** ajoutées
- **CI/CD GitHub Actions** : lint ruff + pytest avec coverage
- **Pre-commit hooks** : ruff, trailing whitespace, end-of-file

### DevOps
- **Script harmattan-update.sh** : mise à jour pull + deps + restart
- **Script setup-git.sh** : branches main/develop + pre-commit + tags
- **pyproject.toml** : config ruff + pytest
- **.pre-commit-config.yaml** : hooks automatiques
- **Git tags semver** : v3.22.0

## 3.20.1 — Cleanup hôtes / blacklist / scans

### UI · Historique
- **Hôtes connus** : suppression unitaire ou totale
- **Ignorés (blacklist)** : MAC/IP filtrés des prochains scans ARP
- Boutons **Supprimer / Ignorer** dans la table ARP et le tiroir hôte
- Vider scans, session runtime, journal, findings

### API
- `DELETE /api/known-hosts/<mac>` · `POST /api/known-hosts/clear`
- `GET|POST|DELETE /api/ignored-hosts`
- `DELETE /api/scans/<id>` · `POST /api/scans/clear`
- `DELETE /api/session/host` · `POST /api/session/clear`
- `POST /api/history/clear` · `POST /api/findings/clear`

## 3.20.0 — Architecture · auth · observability

### Architecture
- **Flask blueprints** under `api/` (`system`, `scan`, `traffic`, `intel`, `tools`, `topology`, `export`, `ai`) — `app.py` slim factory.
- Frontend helper module `static/js/core.js` (fetch, toast, safe URLs).

### Security
- **Query `?token=` disabled by default** (`HARMATTAN_ALLOW_QUERY_TOKEN=0`) — header `X-Harmattan-Token`, Bearer, or httponly cookie.
- **Rate limiting** (`HARMATTAN_RATE_LIMIT`, default 180/min/IP).
- SSE `/api/stream` uses cookie / same-origin auth (no token in URL).

### Ops
- **Persistent jobs** metadata in SQLite (`jobs` table) + hydrate after restart.
- **`/api/metrics`** — JSON snapshot + Prometheus text (`?format=prometheus`).
- OpenAPI bumped to **3.20.0**.

### Suite
- **HARMATTAN 4 bridge** — richer `sync-arp` (session, attack surface, findings, MITRE).

## 3.9.1 — Critical runtime fix + stability

### Critical
- **Fixed early `if __name__ == "__main__"`** in the middle of `app.py` that started the server before registering most routes (ARP, nmap, traffic, etc. returned 404).
- Routes are now fully registered; single startup block at end of file with SocketIO (`async_mode=threading`).

### Stability
- **Persistent API token** in `data/.api_token` (and `HARMATTAN_TOKEN` env) — no more 401 after every restart.
- **Persistent SECRET_KEY** in `data/.secret_key`.
- Clean **404/405 handlers** (no more 404 logged as Unhandled 500).
- Scapy init more robust; preflight checks CAP_NET_RAW on real python path.
- `PYTHONPYCACHEPREFIX=data/pycache` to avoid root-owned `modules/__pycache__` write failures.
- Alias **`/api/status`** → system-check.
- Frontend `fetch` uses `credentials: "same-origin"`.
- Hub recreated (`~/harmattan-hub`) · suite launcher improved (`restart`, better wait).

## 3.9.0 — OT/ICS + IPv6 + Active Creds

### Discovery & Recon
- **Module IPv6 Discovery** : scan multicast `ff02::1` (ICMPv6) + détection MAC/Vendor.
- **Sondes OT/ICS** : détection de protocoles industriels (Modbus, S7comm, BACnet, EtherNet/IP, Niagara Fox).
- API `/api/ipv6/scan` et `/api/ot/scan`.

### Security
- **Active Creds Verification** : vérification légère de mots de passe par défaut (admin/admin, root/root) sur HTTP/HTTPS.
- Élevation automatique du risque à **CRITIQUE** si les identifiants sont confirmés.
- API `/api/creds/active` (POST).

### UI/Core
- Intégration des résultats OT et IPv6 dans le résumé Intel (`/api/intel/summary`).

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
