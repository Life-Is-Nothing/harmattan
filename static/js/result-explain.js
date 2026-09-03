/**
 * HARMATTAN Result Explain — infos & explications au clic
 * Partagé (même API) sur Network / PT / Cortex / Sahel / Hub
 */
(function (global) {
  "use strict";

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );
  }

  const PORTS = {
    20: { name: "FTP-data", risk: "medium", mean: "Transfert de fichiers FTP (données).", why: "FTP en clair expose identifiants et fichiers.", fix: "Passer en SFTP/FTPS ; restreindre par ACL." },
    21: { name: "FTP", risk: "high", mean: "Contrôle FTP (souvent anonyme ou legacy).", why: "Identifiants en clair ; brute-force fréquent.", fix: "Désactiver ou FTPS/SFTP ; MFA ; fail2ban." },
    22: { name: "SSH", risk: "medium", mean: "Administration distante chiffrée.", why: "Cible #1 de brute-force si exposé Internet.", fix: "Clés only, disable root, fail2ban, VPN, port non standard optionnel." },
    23: { name: "Telnet", risk: "critical", mean: "Shell distant non chiffré.", why: "Tout le trafic (mdp) est interceptable.", fix: "Remplacer immédiatement par SSH." },
    25: { name: "SMTP", risk: "medium", mean: "Serveur mail (envoi).", why: "Open relay = spam ; enumeration users.", fix: "Auth obligatoire, TLS, anti-relay." },
    53: { name: "DNS", risk: "medium", mean: "Résolution de noms.", why: "Recursion ouverte = amplification DDoS.", fix: "Restreindre recursion ; DNSSEC si applicable." },
    80: { name: "HTTP", risk: "medium", mean: "Web non chiffré.", why: "Interception / downgrade ; cookies exposés.", fix: "Rediriger vers HTTPS (443) + HSTS." },
    110: { name: "POP3", risk: "high", mean: "Récupération mail (souvent clair).", why: "Mots de passe mail en clair.", fix: "POP3S (995) ou IMAPS." },
    111: { name: "RPCbind", risk: "high", mean: "Portmapper NFS/RPC.", why: "Surface d’attaque NFS/mountd si exposé.", fix: "Firewall local only ; pas d’exposition WAN." },
    135: { name: "MSRPC", risk: "high", mean: "RPC Windows.", why: "Recon AD / exploitation latérale.", fix: "Bloquer hors LAN de confiance." },
    139: { name: "NetBIOS", risk: "high", mean: "Partages Windows legacy.", why: "Enumération + relais NTLM.", fix: "Désactiver SMBv1/NetBIOS si inutile." },
    143: { name: "IMAP", risk: "medium", mean: "Mail interactif.", why: "Souvent sans TLS.", fix: "IMAPS 993." },
    161: { name: "SNMP", risk: "high", mean: "Supervision équipements.", why: "Community strings faibles = cartographie complète.", fix: "SNMPv3 ; community non-public ; ACL." },
    389: { name: "LDAP", risk: "high", mean: "Annuaire (AD souvent).", why: "Enum users/groups ; LDAP signing.", fix: "LDAPS 636 ; restreindre anonyme." },
    443: { name: "HTTPS", risk: "low", mean: "Web chiffré TLS.", why: "Vulns applicatives + certs expirés.", fix: "TLS 1.2+, headers sécu, patching app." },
    445: { name: "SMB", risk: "critical", mean: "Partages fichiers Windows.", why: "WannaCry/EternalBlue, ransomware, lateral move.", fix: "Jamais exposé Internet ; patch ; segmenter." },
    465: { name: "SMTPS", risk: "low", mean: "SMTP sur TLS.", why: "Surface mail réduite vs 25.", fix: "Auth + monitoring." },
    587: { name: "Submission", risk: "low", mean: "Envoi mail authentifié.", why: "Brute-force comptes.", fix: "TLS + rate-limit." },
    631: { name: "IPP/CUPS", risk: "medium", mean: "Impression réseau.", why: "CVE CUPS récentes ; accès local.", fix: "Bind localhost si possible ; patcher." },
    636: { name: "LDAPS", risk: "medium", mean: "LDAP chiffré.", why: "Toujours sensible (annuaire).", fix: "ACL strictes." },
    993: { name: "IMAPS", risk: "low", mean: "IMAP TLS.", why: "Auth brute-force possible.", fix: "MFA mail si dispo." },
    995: { name: "POP3S", risk: "low", mean: "POP3 TLS.", why: "Idem IMAPS.", fix: "MFA / mots de passe forts." },
    1433: { name: "MSSQL", risk: "critical", mean: "Base SQL Server.", why: "Données métier ; brute-force sa.", fix: "Pas d’exposition ; VPN ; least privilege." },
    1521: { name: "Oracle", risk: "critical", mean: "Base Oracle.", why: "Données critiques.", fix: "Réseau interne uniquement." },
    2049: { name: "NFS", risk: "high", mean: "Partages Unix.", why: "Accès fichiers si mal ACL.", fix: "Exports restreints ; no_root_squash prudent." },
    3306: { name: "MySQL/MariaDB", risk: "critical", mean: "Base de données.", why: "Dump données / RCE via vulns.", fix: "Bind 127.0.0.1 ; user dédiés." },
    3389: { name: "RDP", risk: "critical", mean: "Bureau distant Windows.", why: "Brute-force + ransomware initial access.", fix: "VPN + NLA + MFA ; jamais Internet ouvert." },
    5432: { name: "PostgreSQL", risk: "critical", mean: "Base PostgreSQL.", why: "Données applicatives.", fix: "Réseau privé ; auth forte." },
    5900: { name: "VNC", risk: "critical", mean: "Contrôle écran distant.", why: "Souvent sans auth forte.", fix: "SSH tunnel ; désactiver si inutile." },
    6379: { name: "Redis", risk: "critical", mean: "Cache/clé-valeur.", why: "Souvent sans auth → RCE.", fix: "requirepass ; bind local ; rename COMMANDS." },
    8080: { name: "HTTP-alt", risk: "medium", mean: "Web alternatif / proxy.", why: "Apps admin souvent non durcies.", fix: "Auth + TLS reverse-proxy." },
    8443: { name: "HTTPS-alt", risk: "medium", mean: "HTTPS alternatif.", why: "Consoles admin.", fix: "MFA, IP allowlist." },
    9200: { name: "Elasticsearch", risk: "critical", mean: "Moteur de recherche.", why: "Data leak massif si ouvert.", fix: "Auth X-Pack ; réseau privé." },
    27017: { name: "MongoDB", risk: "critical", mean: "NoSQL.", why: "Historique d’instances sans auth.", fix: "Auth + bind local." },
  };

  const SEV = {
    critical: {
      label: "Critique",
      color: "critical",
      mean: "Impact majeur immédiat (RCE, takeover, data breach probable).",
      action: "Traiter sous 24–48 h : contenir, patcher, invalider secrets.",
    },
    critique: {
      label: "Critique",
      color: "critical",
      mean: "Impact majeur immédiat.",
      action: "Priorité P1 — containment + remédiation urgente.",
    },
    high: {
      label: "Haute",
      color: "high",
      mean: "Exploitation réaliste avec impact fort.",
      action: "Planifier sous la semaine ; compenser (WAF, ACL) si besoin.",
    },
    haute: {
      label: "Haute",
      color: "high",
      mean: "Risque élevé.",
      action: "Remédiation rapide + suivi.",
    },
    élevée: {
      label: "Élevée",
      color: "high",
      mean: "Risque élevé.",
      action: "Remédiation rapide.",
    },
    medium: {
      label: "Moyenne",
      color: "medium",
      mean: "Exposition utile à un attaquant mais prérequis souvent requis.",
      action: "Backlog priorisé ; durcissement.",
    },
    moyenne: {
      label: "Moyenne",
      color: "medium",
      mean: "Risque modéré.",
      action: "Corriger dans le cycle normal.",
    },
    low: {
      label: "Faible",
      color: "low",
      mean: "Hygiène / info limitée.",
      action: "Corriger quand possible ; documenter acceptation du risque.",
    },
    faible: {
      label: "Faible",
      color: "low",
      mean: "Impact limité.",
      action: "Amélioration continue.",
    },
    info: {
      label: "Info",
      color: "info",
      mean: "Observation informative, pas forcément une vulnérabilité.",
      action: "Conserver pour le rapport / contexte.",
    },
  };

  const ROLES = {
    gateway: "Passerelle / routeur — point de sortie Internet. Priorité haute en durcissement.",
    router: "Équipement de routage. SNMP/Telnet ouverts = risque.",
    switch: "Commutateur. Ports de management à isoler.",
    server: "Serveur. Surface de services large → inventaire ports critique.",
    pc: "Poste de travail. RDP/SMB exposés = lateral movement.",
    mobile: "Appareil mobile. Vérifier MDM / isolation guest Wi‑Fi.",
    printer: "Imprimante. Souvent oubliée, firmwares vulnérables.",
    iot: "Objet connecté. Mots de passe par défaut fréquents.",
    ap: "Point d’accès Wi‑Fi. Segmenter guest/corp.",
    camera: "Caméra IP. Souvent default creds.",
    vm: "Machine virtuelle / hyperviseur guest.",
    unknown: "Rôle non déterminé — à investiguer manuellement.",
  };

  const MODULES = {
    nmap: "Scan de ports/services. Montre ce qui écoute sur la cible.",
    nuclei: "Templates de vulnérabilités web/infra connues.",
    full: "Enchaînement multi-modules (profil engagement).",
    recon: "Collecte passive/active d’informations.",
    smb: "Enumération partages / signing SMB.",
    enum: "Énumération services (users, shares, banners).",
    web: "Tests applicatifs web (chemins, headers, techs).",
    ad: "Active Directory (AS-REP, Kerberoast…).",
    cloud: "Recon cloud (buckets, métadonnées…).",
    whatweb: "Fingerprint technologies web.",
    httpx: "Sonde HTTP vivante (status, title, techs).",
    subfinder: "Découverte de sous-domaines.",
    ffuf: "Découverte de chemins/fichiers web.",
    phishing: "Score d’URL/mail suspect (IA/heuristiques).",
    malware: "Analyse de contenu/script suspect.",
    nids: "Classification de flux réseau (démo ML).",
    logs: "Anomalies dans journaux (SSH fails…).",
    beaconing: "Détection de balises C2 périodiques.",
    pipeline: "Triage multi-moteurs combiné.",
    network: "Alerte / événement côté réseau (SOC).",
    log: "Alerte dérivée des logs hôtes.",
    fim: "File Integrity Monitoring — fichier modifié.",
    system: "Événement système / agent.",
  };

  const KEYWORDS = [
    { re: /sql\s*injection|sqli|union select/i, title: "Injection SQL", mean: "Entrée utilisateur concaténée dans une requête SQL.", impact: "Lecture/modif BDD, parfois RCE.", fix: "Requêtes paramétrées, ORM, WAF en appoint." },
    { re: /xss|cross.site|script>|onerror=/i, title: "Cross-Site Scripting (XSS)", mean: "Script injecté exécuté dans le navigateur d’une victime.", impact: "Vol de session, phishing interne.", fix: "Encodage sortie, CSP stricte, HttpOnly cookies." },
    { re: /lfi|local file|path traversal|\.\.\/|etc\/passwd/i, title: "Path traversal / LFI", mean: "Lecture de fichiers hors répertoire prévu.", impact: "Fuite de secrets, parfois RCE via includes.", fix: "Canonicalize paths, allowlist, chroot." },
    { re: /rce|remote code|command injection|os command/i, title: "Exécution de code (RCE)", mean: "L’attaquant exécute du code sur le serveur.", impact: "Prise de contrôle totale.", fix: "Patch, désactiver fonctions dangereuses, sandbox." },
    { re: /takeover|dangling|cname/i, title: "Subdomain takeover", mean: "CNAME pointe vers un service non réclamé.", impact: "Phishing sous ton domaine, cookies scope.", fix: "Supprimer CNAME ou revendiquer la ressource." },
    { re: /\.env|secret|api[_-]?key|password|credential/i, title: "Fuite de secret", mean: "Secret exposé (fichier, repo, header).", impact: "Accès cloud/API/BDD.", fix: "Rotation immédiate + vault + retrait exposition." },
    { re: /open.?relay|spoof|spf|dmarc|dkim/i, title: "Messagerie / usurpation", mean: "Config mail faible permettant spam/spoof.", impact: "Phishing depuis ton domaine.", fix: "SPF/DKIM/DMARC enforce ; fermer relay." },
    { re: /tls|ssl|certificate|expired|weak cipher/i, title: "TLS / certificat", mean: "Chiffrement faible ou cert expiré.", impact: "MITM, perte de confiance.", fix: "Renouveler cert, TLS1.2+, ciphers modernes." },
    { re: /brute|password spray|failed password|hydra/i, title: "Brute-force / spray", mean: "Tentatives massives d’authentification.", impact: "Compte compromis.", fix: "MFA, lockout, rate-limit, alertes SIEM." },
    { re: /default.?cred|admin\/admin|changeme/i, title: "Identifiants par défaut", mean: "Compte usine non changé.", impact: "Accès admin trivial.", fix: "Changer mdp, désactiver comptes défaut." },
    { re: /cve-\d{4}-\d+/i, title: "CVE connue", mean: "Vulnérabilité publiée avec identifiant CVE.", impact: "Dépend du score CVSS et de l’exposition.", fix: "Patch / mitigation vendor ; vérifier PoC public." },
    { re: /smb|eternal|wannacry|445/i, title: "Exposition SMB", mean: "Partages Windows accessibles.", impact: "Ransomware, lateral movement.", fix: "Fermer 445 WAN ; patch ; segmenter." },
    { re: /rdp|3389|nla/i, title: "RDP exposé", mean: "Bureau distant accessible.", impact: "Brute-force / ransomware.", fix: "VPN + MFA + NLA." },
    { re: /phishing|spear/i, title: "Phishing", mean: "Leurre pour voler credentials ou malware.", impact: "Compte utilisateur compromis.", fix: "Formation, MFA, filtrage mail, DMARC." },
    { re: /malware|ransomware|trojan|powershell.*encoded/i, title: "Malware / payload", mean: "Code malveillant ou suspect.", impact: "Chiffrement données, C2.", fix: "Isoler host, EDR, IOC hunt." },
    { re: /port.?scan|nmap|masscan/i, title: "Scan de ports", mean: "Reconnaissance réseau active.", impact: "Préparation d’attaque.", fix: "IDS/IPS, rate-limit, honeypot." },
  ];

  function portInfo(port) {
    const p = Number(port);
    return (
      PORTS[p] || {
        name: "Service",
        risk: "info",
        mean: `Port ${p} ouvert — service à identifier (banner/version).`,
        why: "Tout service exposé élargit la surface d’attaque.",
        fix: "Confirmer le besoin métier ; patcher ; restreindre par firewall.",
      }
    );
  }

  function severityInfo(sev) {
    const k = String(sev || "info").toLowerCase();
    return SEV[k] || SEV.info;
  }

  function roleInfo(role) {
    const k = String(role || "unknown").toLowerCase();
    return ROLES[k] || ROLES.unknown;
  }

  function moduleInfo(mod) {
    const k = String(mod || "").toLowerCase();
    for (const [key, val] of Object.entries(MODULES)) {
      if (k.includes(key)) return val;
    }
    return "Résultat d’un module d’analyse. Clique pour le détail technique.";
  }

  function keywordExplain(text) {
    const t = String(text || "");
    const hits = [];
    for (const k of KEYWORDS) {
      if (k.re.test(t)) hits.push(k);
    }
    return hits;
  }

  function card(title, bodyHtml, extraClass) {
    return `<div class="hmx-card ${extraClass || ""}"><div class="hmx-card-t">${esc(title)}</div><div class="hmx-card-b">${bodyHtml}</div></div>`;
  }

  function portHtml(port, service, product, version) {
    const info = portInfo(port);
    const svc = service || info.name;
    const prod = [product, version].filter(Boolean).join(" ");
    return card(
      `Port ${esc(port)} · ${esc(svc)}`,
      `<p><b>Risque indicatif :</b> <span class="hmx-badge ${esc(info.risk)}">${esc(info.risk)}</span></p>
       <p><b>C’est quoi ?</b> ${esc(info.mean)}</p>
       <p><b>Pourquoi c’est important ?</b> ${esc(info.why)}</p>
       <p><b>Que faire ?</b> ${esc(info.fix)}</p>
       ${prod ? `<p class="hmx-muted">Produit détecté : <code>${esc(prod)}</code></p>` : ""}
       <p class="hmx-muted">Indiciel — valider selon le contexte métier et le ROE.</p>`
    );
  }

  function severityHtml(sev) {
    const s = severityInfo(sev);
    return card(
      `Sévérité : ${esc(s.label)}`,
      `<p>${esc(s.mean)}</p><p><b>Action recommandée :</b> ${esc(s.action)}</p>`
    );
  }

  function findingHtml(f) {
    const title = f.title || f.name || "Finding";
    const desc = f.description || f.detail || f.message || "";
    const sev = f.severity || f.risk || "info";
    const rem = f.remediation || f.recommendation || f.fix || "";
    const target = f.target || f.host || f.ip || "";
    const phase = f.phase || f.module || f.source || "";
    const hits = keywordExplain(`${title} ${desc}`);
    let kw = hits
      .map(
        (h) =>
          `<div class="hmx-kw"><b>${esc(h.title)}</b><br>${esc(h.mean)}<br><span class="hmx-muted">Impact : ${esc(
            h.impact
          )}</span><br><span class="hmx-muted">Remédiation : ${esc(h.fix)}</span></div>`
      )
      .join("");
    if (!kw) {
      kw = `<p class="hmx-muted">Pas de pattern connu — s’appuyer sur la description et la sévérité.</p>`;
    }
    return (
      severityHtml(sev) +
      card(
        esc(title),
        `${target ? `<p><b>Cible :</b> <code>${esc(target)}</code></p>` : ""}
         ${phase ? `<p><b>Phase / source :</b> ${esc(phase)}</p>` : ""}
         <p><b>Description</b></p>
         <pre class="hmx-pre">${esc(desc || "—")}</pre>
         ${rem ? `<p><b>Remédiation enregistrée</b></p><pre class="hmx-pre">${esc(rem)}</pre>` : ""}
         <p><b>Explications automatiques</b></p>${kw}`
      )
    );
  }

  function cveHtml(c) {
    const id = c.id || c.cve || "CVE";
    const score = c.score != null ? c.score : "—";
    const sev = c.severity || "info";
    const desc = c.description || "";
    const url = c.url || (String(id).startsWith("CVE-") ? `https://nvd.nist.gov/vuln/detail/${id}` : "#");
    return (
      severityHtml(sev) +
      card(
        esc(id),
        `<p><b>Score CVSS :</b> ${esc(score)}</p>
         <p>${esc(desc || "Voir la fiche NVD pour le détail.")}</p>
         <p><a class="hmx-link" href="${esc(url)}" target="_blank" rel="noopener">Fiche NVD / source ↗</a></p>
         <p><b>Bonne pratique :</b> vérifier si le produit/version matchent vraiment, si un exploit public existe, et l’exposition réseau avant de paniquer.</p>`
      )
    );
  }

  function hostHtml(h) {
    const ip = h.ip || h.host || "—";
    const role = h.role || "unknown";
    const ports = h.open_ports || h.ports || [];
    let portsBlock = "";
    if (Array.isArray(ports) && ports.length) {
      portsBlock = ports
        .slice(0, 20)
        .map((p) => {
          if (typeof p === "object") return portHtml(p.port, p.service, p.product, p.version);
          return portHtml(p);
        })
        .join("");
    }
    return (
      card(
        `Hôte ${esc(ip)}`,
        `<p><b>Rôle estimé :</b> ${esc(role)}</p>
         <p>${esc(roleInfo(role))}</p>
         <p><b>MAC :</b> ${esc(h.mac || "—")} · <b>Vendor :</b> ${esc(h.vendor || "—")}</p>
         <p><b>Hostname :</b> ${esc(h.hostname || "—")}</p>
         <p><b>OS hint :</b> ${esc(h.os_hint || h.os || "—")}</p>
         <p class="hmx-muted">Clique un port dans les tableaux pour une fiche dédiée.</p>`
      ) + portsBlock
    );
  }

  function resultModuleHtml(mod, payload) {
    const expl = moduleInfo(mod);
    let preview = "";
    try {
      preview = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
    } catch (_) {
      preview = String(payload);
    }
    if (preview.length > 6000) preview = preview.slice(0, 6000) + "\n…";
    const hits = keywordExplain(preview);
    const kw = hits.length
      ? hits
          .map((h) => `<li><b>${esc(h.title)}</b> — ${esc(h.mean)} → ${esc(h.fix)}</li>`)
          .join("")
      : "<li class='hmx-muted'>Aucun motif automatique — lire le JSON technique.</li>";
    return (
      card(`Module « ${esc(mod)} »`, `<p>${esc(expl)}</p><p><b>Indices détectés dans le payload</b></p><ul>${kw}</ul>`) +
      card("Données techniques", `<pre class="hmx-pre">${esc(preview)}</pre>`)
    );
  }

  function alertHtml(a) {
    const sev = a.severity || "info";
    const mod = a.module || a.source || "network";
    const title = a.title || "Alerte";
    const findings = a.findings || [];
    const flow = `${a.src || "—"} → ${a.dst || "—"}${a.dport ? ":" + a.dport : ""}`;
    let fh = findings.length
      ? findings
          .map((f) => {
            if (typeof f === "string") return `<li>${esc(f)}</li>`;
            return `<li><b>${esc(f.title || f.type || "item")}</b> — ${esc(f.detail || f.message || "")}</li>`;
          })
          .join("")
      : "<li class='hmx-muted'>Pas de sous-finding structuré.</li>";
    const hits = keywordExplain(`${title} ${JSON.stringify(findings)}`);
    const kw = hits
      .map((h) => `<div class="hmx-kw"><b>${esc(h.title)}</b> — ${esc(h.mean)} <span class="hmx-muted">(${esc(h.fix)})</span></div>`)
      .join("");
    return (
      severityHtml(sev) +
      card(
        esc(title),
        `<p><b>Module :</b> ${esc(mod)} — ${esc(moduleInfo(mod))}</p>
         <p><b>Flux :</b> <code>${esc(flow)}</code></p>
         <p><b>Statut :</b> ${esc(a.status || "open")}</p>
         <p><b>Findings</b></p><ul>${fh}</ul>
         ${kw ? `<p><b>Explications</b></p>${kw}` : ""}
         <p class="hmx-muted">Playbooks Sahel : acquitter / résoudre / marquer faux positif selon investigation.</p>`
      )
    );
  }

  /* ---------- UI panel ---------- */
  function ensureUi() {
    if (document.getElementById("hmx-root")) return;
    const css = document.createElement("link");
    css.rel = "stylesheet";
    // try local path variants
    const base = document.querySelector("script[src*='result-explain']");
    if (base) {
      const href = base.src.replace(/result-explain\.js.*/, "result-explain.css");
      // css is next to js under static/js — prefer static/css
      const cssHref = base.src.includes("/js/")
        ? base.src.replace("/js/result-explain.js", "/css/result-explain.css")
        : href;
      css.href = cssHref;
      document.head.appendChild(css);
    }
    const root = document.createElement("div");
    root.id = "hmx-root";
    root.innerHTML = `
      <div id="hmx-backdrop" class="hmx-backdrop" hidden></div>
      <aside id="hmx-panel" class="hmx-panel" aria-hidden="true">
        <div class="hmx-head">
          <div>
            <div class="hmx-kicker">Explication du résultat</div>
            <h2 id="hmx-title">Détail</h2>
          </div>
          <button type="button" class="hmx-close" id="hmx-close" aria-label="Fermer">✕</button>
        </div>
        <div class="hmx-body" id="hmx-body"></div>
        <div class="hmx-foot muted">HARMATTAN · aide à la décision — valider en contexte engagé</div>
      </aside>`;
    document.body.appendChild(root);
    const close = () => {
      document.getElementById("hmx-panel").classList.remove("open");
      document.getElementById("hmx-panel").setAttribute("aria-hidden", "true");
      const bd = document.getElementById("hmx-backdrop");
      bd.hidden = true;
      bd.classList.remove("show");
    };
    document.getElementById("hmx-close").addEventListener("click", close);
    document.getElementById("hmx-backdrop").addEventListener("click", close);
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape") close();
    });
  }

  function open(title, html) {
    ensureUi();
    document.getElementById("hmx-title").textContent = title || "Détail";
    document.getElementById("hmx-body").innerHTML = html || "<p>Aucune info.</p>";
    document.getElementById("hmx-panel").classList.add("open");
    document.getElementById("hmx-panel").setAttribute("aria-hidden", "false");
    const bd = document.getElementById("hmx-backdrop");
    bd.hidden = false;
    bd.classList.add("show");
  }

  function close() {
    const p = document.getElementById("hmx-panel");
    if (!p) return;
    p.classList.remove("open");
    p.setAttribute("aria-hidden", "true");
    const bd = document.getElementById("hmx-backdrop");
    if (bd) {
      bd.hidden = true;
      bd.classList.remove("show");
    }
  }

  /** Bind data-hmx-* attributes after render */
  function bind(root) {
    const el = root || document;
    el.querySelectorAll("[data-hmx]").forEach((node) => {
      if (node._hmxBound) return;
      node._hmxBound = true;
      node.classList.add("hmx-clickable");
      node.title = node.title || "Cliquer pour explication";
      node.addEventListener("click", (ev) => {
        // allow nested buttons to work
        if (ev.target.closest("button,a,input,select,textarea,label") && ev.target !== node) return;
        ev.preventDefault();
        ev.stopPropagation();
        const kind = node.getAttribute("data-hmx");
        let data = {};
        try {
          data = JSON.parse(node.getAttribute("data-hmx-json") || "{}");
        } catch (_) {
          data = {};
        }
        if (kind === "port") open(`Port ${data.port || ""}`, portHtml(data.port, data.service, data.product, data.version));
        else if (kind === "severity") open("Sévérité", severityHtml(data.severity || data.sev));
        else if (kind === "finding") open(data.title || "Finding", findingHtml(data));
        else if (kind === "cve") open(data.id || "CVE", cveHtml(data));
        else if (kind === "host") open(data.ip || "Hôte", hostHtml(data));
        else if (kind === "module") open(data.module || "Module", resultModuleHtml(data.module, data.payload));
        else if (kind === "alert") open(data.title || "Alerte", alertHtml(data));
        else if (kind === "role") open("Rôle", card(data.role || "role", `<p>${esc(roleInfo(data.role))}</p>`));
        else if (kind === "html") open(data.title || "Info", data.html || "");
        else open("Info", card("Résultat", `<pre class="hmx-pre">${esc(JSON.stringify(data, null, 2))}</pre>`));
      });
    });
  }

  // Auto-bind dynamically added content
  function observe() {
    ensureUi();
    bind(document);
    if (global._hmxObserver) return;
    global._hmxObserver = new MutationObserver(() => {
      clearTimeout(global._hmxBindTimer);
      global._hmxBindTimer = setTimeout(() => bind(document), 80);
    });
    global._hmxObserver.observe(document.body, { childList: true, subtree: true });
  }


  // Raccourci: touche ? → aide panneau
  document.addEventListener("keydown", function (e) {
    if (e.key !== "?" || e.ctrlKey || e.metaKey || e.altKey) return;
    const tag = (e.target && e.target.tagName) || "";
    if (/INPUT|TEXTAREA|SELECT/.test(tag) || e.target.isContentEditable) return;
    e.preventDefault();
    open(
      "Aide — résultats cliquables",
      card(
        "Comment utiliser",
        "<p>Clique un <b>résultat</b> (hôte, port, finding, CVE, alerte) pour ouvrir ce panneau.</p>" +
          "<p><b>Esc</b> ferme le panneau. Les explications sont indicatives — valide toujours en contexte ROE.</p>" +
          "<p class='hmx-muted'>HARMATTAN Result Explain v" +
          (global.HMExplain && global.HMExplain.VERSION ? global.HMExplain.VERSION : "1") +
          "</p>"
      )
    );
  });

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", observe);
  } else {
    observe();
  }

  global.HMExplain = {
    VERSION: "1.1.0",
    esc,
    portInfo,
    severityInfo,
    roleInfo,
    moduleInfo,
    keywordExplain,
    portHtml,
    severityHtml,
    findingHtml,
    cveHtml,
    hostHtml,
    resultModuleHtml,
    alertHtml,
    card,
    open,
    close,
    bind,
  };
})(typeof window !== "undefined" ? window : globalThis);
