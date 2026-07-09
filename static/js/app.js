// HARMATTAN v3 — Professional frontend controller
const state = {
  arp: null,
  nmap: null,
  vuln: null,
  attack: null,
  network: null,
  trafficTimer: null,
  liveTimer: null,
  liveOn: false,
  hierarchical: true,
  networkGraph: null,
  currentJob: null,
  jobPoll: null,
  arpFilter: "",
  attackFilter: "",
};

const TOKEN = window.HARMATTAN_TOKEN || "";

// ---------- Helpers ----------
function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

function toast(msg, type = "ok") {
  const root = document.getElementById("toast-root");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  root.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

function log(msg) {
  const box = document.getElementById("activity-log");
  const line = document.createElement("div");
  line.className = "log-line";
  const time = new Date().toLocaleTimeString();
  line.innerHTML = `<span class="t">[${esc(time)}]</span>${msg}`;
  box.prepend(line);
  while (box.children.length > 80) box.removeChild(box.lastChild);
}

async function api(path, opts = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(opts.headers || {}),
  };
  if (TOKEN) headers["X-Harmattan-Token"] = TOKEN;
  const res = await fetch(path, { ...opts, headers });
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    const data = await res.json();
    if (res.status === 401) {
      toast("Token API invalide", "err");
    }
    return data;
  }
  return res;
}

function setBadgeStatus(id, ok) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle("ok", !!ok);
  el.classList.toggle("bad", !ok);
}

function roleBadge(role) {
  const r = role || "unknown";
  return `<span class="badge role-${esc(r)}">${esc(r)}</span>`;
}

// ---------- Navigation ----------
function showView(name) {
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("active"));
  document.getElementById("view-" + name).classList.add("active");
  const nav = document.querySelector(`.nav-item[data-view="${name}"]`);
  if (nav) nav.classList.add("active");
  if (name === "topology") renderTopology();
  if (name === "attack") refreshAttack();
  if (name === "dashboard") refreshHistory();
}

document.querySelectorAll(".nav-item").forEach((item) => {
  item.addEventListener("click", () => showView(item.dataset.view));
});

// ---------- Jobs ----------
function showJobBar(kind, msg, pct) {
  const bar = document.getElementById("job-bar");
  bar.classList.remove("hidden");
  document.getElementById("job-kind").textContent = kind;
  document.getElementById("job-msg").textContent = msg || "";
  document.getElementById("job-fill").style.width = `${pct || 0}%`;
}

function hideJobBar() {
  document.getElementById("job-bar").classList.add("hidden");
  document.getElementById("job-fill").style.width = "0%";
  state.currentJob = null;
  if (state.jobPoll) {
    clearInterval(state.jobPoll);
    state.jobPoll = null;
  }
}

async function pollJob(jobId, onDone) {
  state.currentJob = jobId;
  showJobBar("…", "Démarrage", 2);

  const tick = async () => {
    try {
      const j = await api(`/api/jobs/${jobId}`);
      if (!j || j.error === "not_found") {
        hideJobBar();
        toast("Job introuvable", "err");
        return true;
      }
      showJobBar(j.kind, j.message || j.status, j.progress || 0);
      if (j.status === "done") {
        hideJobBar();
        await onDone(j.result);
        return true;
      }
      if (j.status === "error") {
        hideJobBar();
        log(`⚠ ${esc(j.error || "Erreur job")}`);
        toast(j.error || "Erreur", "err");
        return true;
      }
      if (j.status === "cancelled") {
        hideJobBar();
        toast("Job annulé", "warn");
        return true;
      }
    } catch (e) {
      hideJobBar();
      toast("Erreur polling job", "err");
      return true;
    }
    return false;
  };

  if (await tick()) return;
  state.jobPoll = setInterval(async () => {
    if (await tick()) {
      clearInterval(state.jobPoll);
      state.jobPoll = null;
    }
  }, 800);
}

document.getElementById("btn-job-cancel")?.addEventListener("click", async () => {
  if (!state.currentJob) return;
  await api(`/api/jobs/${state.currentJob}/cancel`, { method: "POST" });
  toast("Annulation demandée", "warn");
});

// ---------- Network context ----------
async function loadNetworkInfo() {
  const iface = document.getElementById("iface-select")?.value || "";
  const q = iface ? `?iface=${encodeURIComponent(iface)}` : "";
  const d = await api("/api/network-info" + q);
  state.network = d;

  const sel = document.getElementById("iface-select");
  if (sel && sel.options.length <= 1) {
    (d.interfaces || []).forEach((i) => {
      const o = document.createElement("option");
      o.value = i.name;
      o.textContent = `${i.name} — ${i.ip}${i.virtual ? " (virt)" : ""}`;
      sel.appendChild(o);
    });
  }

  document.getElementById("info-subnet").textContent = d.subnet || "—";
  document.getElementById("info-local-ip").textContent = d.local_ip || "—";
  document.getElementById("info-gateway").textContent = d.gateway || "—";
  document.getElementById("info-ssid").textContent = d.ssid || "—";
  document.getElementById("dash-ssid").textContent = d.ssid || "—";
  document.getElementById("chip-ssid").textContent = d.ssid || "Wi‑Fi";
  document.getElementById("chip-gateway").textContent = d.gateway ? `gw ${d.gateway}` : "gw —";
  document.getElementById("default-subnet-hint").textContent = d.subnet || "";
  const arpInput = document.getElementById("arp-subnet");
  if (arpInput && d.subnet) arpInput.value = d.subnet;
}

document.getElementById("btn-refresh-net")?.addEventListener("click", loadNetworkInfo);
document.getElementById("iface-select")?.addEventListener("change", loadNetworkInfo);

// ---------- System check ----------
async function systemCheck() {
  const d = await api("/api/system-check");
  setBadgeStatus("status-scapy", d.scapy);
  setBadgeStatus("status-nmap", d.nmap);
  setBadgeStatus("status-root", d.running_as_root);
  document.getElementById("default-subnet-hint").textContent = d.local_subnet || "";
  if (d.ssid) document.getElementById("chip-ssid").textContent = d.ssid;
  if (d.gateway) document.getElementById("chip-gateway").textContent = `gw ${d.gateway}`;
  if (!d.running_as_root) {
    log("⚠ Mode non-root : ARP et capture trafic limités");
  }
}

// ---------- Dashboard ----------
document.getElementById("btn-home-scan").addEventListener("click", async () => {
  const btn = document.getElementById("btn-home-scan");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Scan…';
  log("⚡ Pipeline scan maison…");

  const iface = document.getElementById("iface-select").value || null;
  const res = await api("/api/home-scan", {
    method: "POST",
    body: JSON.stringify({ iface, nmap_gateway: true, nmap_profile: "quick", async: true }),
  });

  if (res.job_id) {
    await pollJob(res.job_id, async (result) => {
      btn.disabled = false;
      btn.textContent = "⚡ Scan maison";
      if (!result || result.error) {
        log(`⚠ ${esc(result?.message || result?.error || "échec")}`);
        toast(result?.message || "Échec scan maison", "err");
        return;
      }
      applyHomeResult(result);
    });
    if (!state.currentJob) {
      btn.disabled = false;
      btn.textContent = "⚡ Scan maison";
    } else {
      // pollJob handles hide; re-enable when done via onDone — also safety:
      const reenable = setInterval(() => {
        if (!state.currentJob) {
          btn.disabled = false;
          btn.textContent = "⚡ Scan maison";
          clearInterval(reenable);
        }
      }, 500);
    }
  } else {
    btn.disabled = false;
    btn.textContent = "⚡ Scan maison";
    if (res.error) toast(res.message || res.error, "err");
    else applyHomeResult(res);
  }
});

function applyHomeResult(result) {
  state.arp = result.arp;
  state.nmap = result.nmap;
  state.attack = result.attack;
  state.network = result.network;
  log(`✓ ${result.arp?.count || 0} appareil(s) · gateway scannée`);
  toast(`Scan maison : ${result.arp?.count || 0} appareils`, "ok");
  if (result.arp) {
    renderArpResults(result.arp);
    populateTargetDropdown(result.arp.hosts || []);
  }
  updateDashboard();
  if (result.nmap && !result.nmap.error) renderNmapResults(result.nmap);
  if (result.attack) renderAttack(result.attack);
  renderNewDevices(result.new_devices || result.arp?.new_devices);
  refreshHistory();
}

function tokenUrl(path) {
  if (!TOKEN) return path;
  const sep = path.includes("?") ? "&" : "?";
  return `${path}${sep}token=${encodeURIComponent(TOKEN)}`;
}

document.getElementById("btn-export-report").addEventListener("click", () => {
  window.location = tokenUrl("/api/report.html");
  log("📄 Export rapport HTML pro");
  toast("Rapport HTML généré", "ok");
});
document.getElementById("btn-export-pdf")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/report.pdf");
  log("📄 Export rapport PDF pro");
  toast("Rapport PDF généré", "ok");
});
document.getElementById("btn-export-docx")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/report.docx");
  log("📄 Export rapport Word DOCX");
  toast("Rapport Word généré", "ok");
});
document.getElementById("btn-export-json")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/report.json");
  log("📄 Export rapport JSON");
});
document.getElementById("btn-export-session")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/session/export");
  log("💾 Export session");
});

// Diff ARP + mDNS + PCAP (v3.5)
document.getElementById("btn-diff-arp")?.addEventListener("click", async () => {
  const d = await api("/api/diff/arp");
  if (d.error) return toast(d.message || d.error, "err");
  const s = d.summary || {};
  log(`Δ ARP +${s.appeared || 0} / -${s.disappeared || 0} / ~${s.changed || 0}`);
  toast(`Diff: +${s.appeared} -${s.disappeared} ~${s.changed}`, "ok");
  console.log("ARP diff", d);
  alert(
    `Diff ARP\n+${s.appeared} apparus\n-${s.disappeared} disparus\n~${s.changed} modifiés\n` +
      (d.appeared || []).slice(0, 10).map((h) => `+ ${h.ip} ${h.vendor || ""}`).join("\n")
  );
});
document.getElementById("btn-mdns")?.addEventListener("click", async () => {
  log("mDNS/SSDP…");
  const r = await api("/api/mdns-ssdp", { method: "POST", body: JSON.stringify({ async: true }) });
  if (r.job_id) {
    toast("Discovery mDNS/SSDP lancée", "ok");
    // reuse job poll if present
    if (typeof pollJob === "function") {
      pollJob(r.job_id, (res) => {
        log(`mDNS/SSDP: ${res?.count || 0} annonces`);
        toast(`${res?.count || 0} annonces IoT`, "ok");
      });
    }
  }
});
document.getElementById("btn-traffic-pcap")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/traffic/export.pcap");
  log("📦 Export PCAP");
});

function updateDashboard() {
  const hosts = state.arp?.count || 0;
  document.getElementById("dash-hosts").textContent = hosts;
  const attack = state.attack;
  if (attack) {
    document.getElementById("dash-exposures").textContent = attack.total_exposures || 0;
    document.getElementById("dash-critical").textContent = attack.risk_counts?.critique || 0;
    document.getElementById("dash-grade").textContent =
      attack.grade ? `${attack.grade} (${attack.risk_score ?? 0})` : "—";
  }
  const roles = state.arp?.roles || {};
  const el = document.getElementById("role-breakdown");
  const keys = Object.keys(roles);
  if (!keys.length) {
    el.innerHTML = `<div class="empty-state" style="padding:24px;"><div class="icon">◌</div>Pas encore de classification.</div>`;
    return;
  }
  el.innerHTML = `<div class="role-bars">${keys
    .map(
      (k) => `
    <div class="role-row">
      <span class="role-name">${roleBadge(k)}</span>
      <div class="role-bar-wrap"><div class="role-bar" style="width:${Math.max(8, (roles[k] / Math.max(hosts, 1)) * 100)}%"></div></div>
      <span class="role-n">${roles[k]}</span>
    </div>`
    )
    .join("")}</div>`;
}

function renderNewDevices(list) {
  const panel = document.getElementById("new-devices-panel");
  const box = document.getElementById("new-devices-list");
  if (!list || !list.length) {
    panel.style.display = "none";
    return;
  }
  panel.style.display = "block";
  box.innerHTML = `<table><thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th></tr></thead><tbody>${list
    .map(
      (h) => `<tr class="highlight-new">
      <td><b>${esc(h.ip)}</b></td>
      <td class="mono">${esc(h.mac)}</td>
      <td>${esc(h.vendor)}</td>
      <td>${esc(h.hostname || "—")}</td>
    </tr>`
    )
    .join("")}</tbody></table>`;
  toast(`${list.length} nouvel(aux) appareil(s)`, "warn");
}

async function refreshHistory() {
  const d = await api("/api/history");
  const el = document.getElementById("history-list");
  if (!d.history?.length) {
    el.innerHTML = `<div class="empty-state" style="padding:24px;"><div class="icon">◌</div>Aucune action.</div>`;
    return;
  }
  el.innerHTML = d.history
    .map(
      (h) => `
    <div class="hist-line"><span class="t">${esc((h.time || "").split("T")[1] || h.time)}</span>
    <span class="badge">${esc(h.kind)}</span> ${esc(h.summary)}</div>`
    )
    .join("");
}

// ---------- ARP ----------
document.getElementById("btn-arp-scan").addEventListener("click", async () => {
  const subnet = document.getElementById("arp-subnet").value.trim();
  const enrich = document.getElementById("arp-enrich").checked;
  const iface = document.getElementById("iface-select")?.value || null;
  const btn = document.getElementById("btn-arp-scan");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Scan…';
  log(`Lancement ARP sur <b>${esc(subnet)}</b>`);

  const res = await api("/api/arp-scan", {
    method: "POST",
    body: JSON.stringify({ subnet, enrich, iface, async: true }),
  });

  const finish = () => {
    btn.disabled = false;
    btn.textContent = "Lancer le scan ARP";
  };

  if (res.job_id) {
    await pollJob(res.job_id, async (result) => {
      finish();
      handleArpResult(result);
    });
    const re = setInterval(() => {
      if (!state.currentJob) {
        finish();
        clearInterval(re);
      }
    }, 500);
  } else {
    finish();
    handleArpResult(res);
  }
});

function handleArpResult(result) {
  if (!result || result.error) {
    log(`⚠ Erreur ARP: ${esc(result?.message || result?.error)}`);
    toast(result?.message || "Erreur ARP", "err");
    document.getElementById("arp-results").innerHTML = `<div class="empty-state"><div class="icon">⚠</div>${esc(
      result?.message || "Erreur"
    )}</div>`;
    return;
  }
  state.arp = result;
  log(`✓ ${result.count} hôte(s) · ${result.duration_s}s · gw ${esc(result.gateway || "?")}`);
  toast(`${result.count} hôte(s) découverts`, "ok");
  renderArpResults(result);
  populateTargetDropdown(result.hosts);
  updateDashboard();
  renderNewDevices(result.new_devices);
  refreshAttack();
  refreshHistory();
}

function renderArpResults(result) {
  const el = document.getElementById("arp-results");
  if (!result.hosts?.length) {
    el.innerHTML = `<div class="empty-state"><div class="icon">◌</div>Aucun hôte trouvé.</div>`;
    return;
  }
  const q = (state.arpFilter || "").toLowerCase();
  const hosts = result.hosts.filter((h) => {
    if (!q) return true;
    return [h.ip, h.mac, h.vendor, h.hostname, h.role, h.os_hint]
      .join(" ")
      .toLowerCase()
      .includes(q);
  });

  const rows = hosts
    .map(
      (h) => `
    <tr class="clickable-row" data-ip="${esc(h.ip)}">
      <td><b>${esc(h.ip)}</b></td>
      <td class="mono">${esc(h.mac || "—")}</td>
      <td>${esc(h.vendor || "—")}</td>
      <td>${esc(h.hostname || "—")}</td>
      <td>${roleBadge(h.role)}</td>
      <td>${esc(h.os_hint || "—")}</td>
      <td>${esc((h.open_ports || []).join(", ") || "—")}</td>
      <td>
        <button class="mini" data-act="ping" data-ip="${esc(h.ip)}">ping</button>
        <button class="mini secondary" data-act="tr" data-ip="${esc(h.ip)}">tr</button>
        <button class="mini secondary" data-act="detail" data-ip="${esc(h.ip)}">détail</button>
      </td>
    </tr>`
    )
    .join("");

  el.innerHTML = `
    <table>
      <thead><tr>
        <th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th>
        <th>Rôle</th><th>OS</th><th>Ports</th><th>Actions</th>
      </tr></thead>
      <tbody>${rows || '<tr><td colspan="8">Aucun résultat pour ce filtre</td></tr>'}</tbody>
    </table>`;

  el.querySelectorAll("[data-act]").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      const ip = btn.dataset.ip;
      const act = btn.dataset.act;
      if (act === "detail") openHostDrawer(ip);
      else quickTool(ip, act === "ping" ? "ping" : "tr");
    });
  });
  el.querySelectorAll("tr.clickable-row").forEach((tr) => {
    tr.addEventListener("click", () => openHostDrawer(tr.dataset.ip));
  });
}

document.getElementById("arp-filter")?.addEventListener("input", (e) => {
  state.arpFilter = e.target.value;
  if (state.arp) renderArpResults(state.arp);
});

function populateTargetDropdown(hosts) {
  const sel = document.getElementById("nmap-target");
  sel.innerHTML =
    `<option value="">— Hôte découvert —</option>` +
    hosts
      .map(
        (h) =>
          `<option value="${esc(h.ip)}">${esc(h.ip)} (${esc(h.hostname || h.role || h.vendor || "?")})</option>`
      )
      .join("");
  const tool = document.getElementById("tool-target");
  if (tool && !tool.value && hosts[0]) tool.value = hosts[0].ip;
}

function quickTool(ip, kind) {
  document.getElementById("tool-target").value = ip;
  showView("tools");
  if (kind === "ping") document.getElementById("btn-ping").click();
  else document.getElementById("btn-traceroute").click();
}

// ---------- Host drawer ----------
async function openHostDrawer(ip) {
  const drawer = document.getElementById("host-drawer");
  const backdrop = document.getElementById("drawer-backdrop");
  document.getElementById("drawer-title").textContent = ip;
  document.getElementById("drawer-body").innerHTML = "Chargement…";
  drawer.classList.add("open");
  backdrop.classList.remove("hidden");
  drawer.setAttribute("aria-hidden", "false");

  const d = await api(`/api/host/${encodeURIComponent(ip)}`);
  const a = d.arp || {};
  const n = d.nmap || {};
  const atk = d.attack || {};
  const vul = d.vuln || {};

  let portsHtml = "—";
  if (n.ports?.length) {
    portsHtml = `<table><thead><tr><th>Port</th><th>Svc</th><th>Version</th></tr></thead><tbody>${n.ports
      .filter((p) => p.state === "open")
      .map(
        (p) =>
          `<tr><td>${esc(p.port)}/${esc(p.protocol)}</td><td>${esc(p.service)}</td><td>${esc(
            (p.product || "") + " " + (p.version || "")
          )}</td></tr>`
      )
      .join("")}</tbody></table>`;
  } else if (a.open_ports?.length) {
    portsHtml = esc(a.open_ports.join(", "));
  }

  let cveHtml = "—";
  if (vul.services?.length) {
    cveHtml = vul.services
      .map(
        (s) =>
          `<div><b>${esc(s.product)} ${esc(s.version)}</b><ul>${(s.cves || [])
            .map((c) => `<li><a href="${esc(c.url)}" target="_blank" rel="noopener">${esc(c.id)}</a> ${esc(c.severity)} ${c.score ?? ""}</li>`)
            .join("")}</ul></div>`
      )
      .join("");
  }

  document.getElementById("drawer-body").innerHTML = `
    <h3>Identité</h3>
    <div class="kv"><span>IP</span><b>${esc(ip)}</b></div>
    <div class="kv"><span>MAC</span><b>${esc(a.mac || n.mac || "—")}</b></div>
    <div class="kv"><span>Vendor</span><b>${esc(a.vendor || "—")}</b></div>
    <div class="kv"><span>Hostname</span><b>${esc(a.hostname || (n.hostnames || [])[0] || "—")}</b></div>
    <div class="kv"><span>Rôle</span><b>${roleBadge(a.role || atk.role)}</b></div>
    <div class="kv"><span>OS</span><b>${esc(a.os_hint || (n.os_matches && n.os_matches[0]?.name) || "—")}</b></div>
    <div class="kv"><span>TTL</span><b>${esc(a.ttl ?? "—")}</b></div>
    ${a.snmp_desc ? `<div class="kv"><span>SNMP</span><b>${esc(a.snmp_desc)}</b></div>` : ""}
    <h3>Ports</h3>${portsHtml}
    <h3>Surface d'attaque</h3>
    <div class="kv"><span>Expositions</span><b>${esc(atk.exposure_count ?? 0)}</b></div>
    <div class="kv"><span>Max risk</span><b>${esc(atk.max_risk || "none")}</b></div>
    <h3>CVE</h3>${cveHtml}
    <h3>Actions</h3>
    <div class="controls-row">
      <button class="mini" id="dr-ping">Ping</button>
      <button class="mini secondary" id="dr-tr">Traceroute</button>
      <button class="mini secondary" id="dr-nmap">Nmap quick</button>
    </div>
  `;
  document.getElementById("dr-ping")?.addEventListener("click", () => quickTool(ip, "ping"));
  document.getElementById("dr-tr")?.addEventListener("click", () => quickTool(ip, "tr"));
  document.getElementById("dr-nmap")?.addEventListener("click", () => {
    document.getElementById("nmap-target-manual").value = ip;
    showView("scan");
    document.getElementById("btn-nmap-scan").click();
  });
}

function closeDrawer() {
  document.getElementById("host-drawer").classList.remove("open");
  document.getElementById("drawer-backdrop").classList.add("hidden");
  document.getElementById("host-drawer").setAttribute("aria-hidden", "true");
}
document.getElementById("btn-drawer-close")?.addEventListener("click", closeDrawer);
document.getElementById("drawer-backdrop")?.addEventListener("click", closeDrawer);

// ---------- Nmap ----------
document.getElementById("btn-nmap-scan").addEventListener("click", async () => {
  const dropdown = document.getElementById("nmap-target").value;
  const manual = document.getElementById("nmap-target-manual").value.trim();
  const target = manual || dropdown;
  const profile = document.getElementById("nmap-profile").value;
  const btn = document.getElementById("btn-nmap-scan");

  if (!target) {
    toast("Aucune cible nmap", "warn");
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> nmap…';
  log(`nmap [<b>${esc(profile)}</b>] → <b>${esc(target)}</b>`);

  const res = await api("/api/nmap-scan", {
    method: "POST",
    body: JSON.stringify({ target, profile, async: true }),
  });

  const finish = () => {
    btn.disabled = false;
    btn.textContent = "Lancer nmap";
  };

  if (res.job_id) {
    await pollJob(res.job_id, async (result) => {
      finish();
      handleNmapResult(result);
    });
    const re = setInterval(() => {
      if (!state.currentJob) {
        finish();
        clearInterval(re);
      }
    }, 500);
  } else {
    finish();
    handleNmapResult(res);
  }
});

function handleNmapResult(result) {
  if (!result || result.error) {
    log(`⚠ nmap: ${esc(result?.message || result?.error)}`);
    toast(result?.message || "nmap échoué", "err");
    document.getElementById("nmap-results").innerHTML = `<div class="empty-state"><div class="icon">⚠</div>${esc(
      result?.message || "Erreur"
    )}</div>`;
    return;
  }
  state.nmap = result;
  log(`✓ nmap OK — ${result.count} hôte(s) · ${result.duration_s || "?"}s`);
  toast(`nmap OK — ${result.count} hôte(s)`, "ok");
  renderNmapResults(result);
  refreshAttack();
  refreshHistory();
}

function renderNmapResults(result) {
  const el = document.getElementById("nmap-results");
  if (!result.hosts?.length) {
    el.innerHTML = `<div class="empty-state"><div class="icon">◌</div>Aucune donnée.</div>`;
    return;
  }

  el.innerHTML = result.hosts
    .map((h) => {
      const os = h.os_matches?.length ? h.os_matches[0].name : "Non détecté";
      const ports = (h.ports || []).filter((p) => p.state === "open");
      const portRows = ports
        .map((p) => {
          const scripts = (p.scripts || [])
            .map(
              (s) =>
                `<div class="script-out"><b>${esc(s.id)}</b>: ${esc((s.output || "").slice(0, 200))}</div>`
            )
            .join("");
          return `
      <tr>
        <td>${esc(p.port)}/${esc(p.protocol)}</td>
        <td><span class="badge open">${esc(p.state)}</span></td>
        <td>${esc(p.service || "")}</td>
        <td>${esc(p.product || "")} ${esc(p.version || "")}</td>
        <td>${scripts || "—"}</td>
      </tr>`;
        })
        .join("");

      return `
      <div class="panel" style="margin-bottom:14px;">
        <h2><span class="clickable-row" data-ip="${esc(h.ip)}" style="cursor:pointer">${esc(h.ip)}</span> — ${esc(os)}</h2>
        <table>
          <thead><tr><th>Port</th><th>État</th><th>Service</th><th>Version</th><th>Scripts</th></tr></thead>
          <tbody>${portRows || '<tr><td colspan="5">Aucun port ouvert</td></tr>'}</tbody>
        </table>
      </div>`;
    })
    .join("");

  el.querySelectorAll("[data-ip]").forEach((node) => {
    node.addEventListener("click", () => openHostDrawer(node.dataset.ip));
  });
}

// ---------- Attack surface ----------
async function refreshAttack() {
  const result = await api("/api/attack-surface");
  state.attack = result;
  renderAttack(result);
  updateDashboard();
}

document.getElementById("btn-refresh-attack").addEventListener("click", refreshAttack);

function renderAttack(report) {
  document.getElementById("as-total").textContent = report.total_exposures || 0;
  document.getElementById("as-critique").textContent = report.risk_counts?.critique || 0;
  document.getElementById("as-haute").textContent = report.risk_counts?.haute || 0;
  document.getElementById("as-score").textContent =
    report.grade != null ? `${report.grade} / ${report.risk_score ?? 0}` : "—";

  const recPanel = document.getElementById("as-recs-panel");
  const recList = document.getElementById("as-recs");
  if (report.recommendations?.length) {
    recPanel.style.display = "block";
    recList.innerHTML = report.recommendations.map((r) => `<li>${esc(r)}</li>`).join("");
  } else {
    recPanel.style.display = "none";
  }

  const el = document.getElementById("attack-results");
  if (!report.hosts?.length) {
    el.innerHTML = `<div class="empty-state"><div class="icon">◌</div>Aucune exposition détectée.</div>`;
    return;
  }

  const q = (state.attackFilter || "").toLowerCase();
  const hosts = report.hosts.filter((h) => {
    if (!q) return true;
    return JSON.stringify(h).toLowerCase().includes(q);
  });

  el.innerHTML = hosts
    .map((h) => {
      if (!h.exposures?.length) {
        return `<div class="panel"><h2>${esc(h.ip)} ${roleBadge(h.role)} <span class="badge open">clean</span></h2>
        <p style="color:var(--text-mid);font-size:12px;">Aucun port sensible détecté.</p></div>`;
      }
      const rows = h.exposures
        .map(
          (e) => `
      <tr>
        <td>${esc(e.port)}/${esc(e.protocol)}</td>
        <td>${esc(e.service || "—")}</td>
        <td>${esc(e.product || "")} ${esc(e.version || "")}</td>
        <td><span class="badge ${esc(e.risk)}">${esc(e.risk)}</span></td>
        <td>${esc(e.source)}</td>
        <td style="font-size:11px;color:var(--text-low)">${esc(e.recommendation || "—")}</td>
      </tr>`
        )
        .join("");
      return `
      <div class="panel" style="margin-bottom:14px;">
        <h2><span style="cursor:pointer" data-ip="${esc(h.ip)}">${esc(h.ip)}</span>
          ${h.hostname ? "— " + esc(h.hostname) : ""} ${roleBadge(h.role)}
          <span class="badge ${esc(h.max_risk)}">${esc(h.exposure_count)} expo</span></h2>
        <table>
          <thead><tr><th>Port</th><th>Service</th><th>Produit</th><th>Risque</th><th>Source</th><th>Reco</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
    })
    .join("");

  el.querySelectorAll("[data-ip]").forEach((n) =>
    n.addEventListener("click", () => openHostDrawer(n.dataset.ip))
  );
}

document.getElementById("attack-filter")?.addEventListener("input", (e) => {
  state.attackFilter = e.target.value;
  if (state.attack) renderAttack(state.attack);
});

// ---------- Vuln ----------
document.getElementById("btn-vuln-scan").addEventListener("click", async () => {
  const btn = document.getElementById("btn-vuln-scan");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> CVE…';
  log("Corrélation NVD…");

  const res = await api("/api/vuln-scan", {
    method: "POST",
    body: JSON.stringify({ async: true }),
  });

  const finish = () => {
    btn.disabled = false;
    btn.textContent = "Lancer la corrélation CVE";
  };

  if (res.error && !res.job_id) {
    finish();
    log(`⚠ ${esc(res.message || res.error)}`);
    toast(res.message || res.error, "err");
    document.getElementById("vuln-results").innerHTML = `<div class="empty-state"><div class="icon">⚠</div>${esc(
      res.message || "Pas de données."
    )}</div>`;
    return;
  }

  if (res.job_id) {
    await pollJob(res.job_id, async (result) => {
      finish();
      if (result?.error) {
        toast(result.message || result.error, "err");
        return;
      }
      state.vuln = result;
      log(`✓ ${result.total_findings} CVE`);
      toast(`${result.total_findings} CVE trouvées`, "ok");
      renderVulnResults(result);
      refreshHistory();
    });
    const re = setInterval(() => {
      if (!state.currentJob) {
        finish();
        clearInterval(re);
      }
    }, 500);
  } else {
    finish();
  }
});

function renderVulnResults(report) {
  const el = document.getElementById("vuln-results");
  if (!report.hosts?.length) {
    el.innerHTML = `<div class="empty-state"><div class="icon">✓</div>Aucune CVE trouvée.</div>`;
    return;
  }
  const sev = report.by_severity || {};
  el.innerHTML =
    `<div class="stat-grid" style="margin-bottom:14px;">
      <div class="stat-card"><div class="v">${esc(report.total_findings)}</div><div class="l">Total CVE</div></div>
      <div class="stat-card"><div class="v">${esc(sev.critique || 0)}</div><div class="l">Critiques</div></div>
      <div class="stat-card"><div class="v">${esc(sev.haute || 0)}</div><div class="l">Hautes</div></div>
    </div>` +
    report.hosts
      .map(
        (h) => `
    <div class="panel" style="margin-bottom:14px;">
      <h2 style="cursor:pointer" data-ip="${esc(h.ip)}">${esc(h.ip)}</h2>
      ${h.services
        .map(
          (s) => `
        <p style="color:var(--text-mid); font-size:12px; margin:10px 0 6px;">
          <b style="color:var(--text-hi)">${esc(s.service)} ${esc(s.product)} ${esc(s.version)}</b> — port ${esc(s.port)}
        </p>
        <table>
          <thead><tr><th>CVE</th><th>Score</th><th>Sévérité</th><th>Description</th></tr></thead>
          <tbody>
            ${s.cves
              .map(
                (c) => `
              <tr>
                <td><a href="${esc(c.url)}" target="_blank" rel="noopener" style="color:var(--cyan)">${esc(c.id)}</a></td>
                <td>${c.score ?? "—"}</td>
                <td><span class="badge ${esc(c.severity)}">${esc(c.severity)}</span></td>
                <td>${esc(c.description)}</td>
              </tr>`
              )
              .join("")}
          </tbody>
        </table>`
        )
        .join("")}
    </div>`
      )
      .join("");

  el.querySelectorAll("[data-ip]").forEach((n) =>
    n.addEventListener("click", () => openHostDrawer(n.dataset.ip))
  );
}

// ---------- Traffic ----------
document.getElementById("btn-traffic-start").addEventListener("click", async () => {
  const iface = document.getElementById("traffic-iface").value.trim();
  const filter = document.getElementById("traffic-filter").value.trim();
  const r = await api("/api/traffic/start", {
    method: "POST",
    body: JSON.stringify({ iface, filter }),
  });
  if (r.error) {
    toast(r.message || r.error, "err");
    return;
  }
  log("▶ Capture démarrée");
  toast("Capture démarrée", "ok");
  document.getElementById("btn-traffic-start").disabled = true;
  document.getElementById("btn-traffic-stop").disabled = false;
  state.trafficTimer = setInterval(pollTraffic, 1500);
});

document.getElementById("btn-traffic-stop").addEventListener("click", async () => {
  await api("/api/traffic/stop", { method: "POST" });
  clearInterval(state.trafficTimer);
  log("■ Capture arrêtée");
  document.getElementById("btn-traffic-start").disabled = false;
  document.getElementById("btn-traffic-stop").disabled = true;
});

async function pollTraffic() {
  const snap = await api("/api/traffic/snapshot");
  if (snap.error) log(`⚠ ${esc(snap.error)}`);
  document.getElementById("traffic-total").textContent = snap.total_packets || 0;
  document.getElementById("traffic-bytes").textContent = (
    (snap.bytes_total || 0) / 1024
  ).toFixed(1);
  document.getElementById("traffic-flows").innerHTML =
    (snap.top_flows || [])
      .map(
        (f) => `
    <tr>
      <td>${esc(f.src)}</td><td>${esc(f.dst)}</td>
      <td><span class="proto ${esc(f.protocol)}">${esc(f.protocol)}</span></td>
      <td>${esc(f.dport ?? "—")}</td>
      <td>${esc(f.packets)}</td><td>${((f.bytes || 0) / 1024).toFixed(1)} Ko</td>
    </tr>`
      )
      .join("") || `<tr><td colspan="6">En attente…</td></tr>`;
  document.getElementById("traffic-live").innerHTML = (snap.recent_packets || [])
    .slice(-15)
    .reverse()
    .map(
      (p) => `
    <div class="log-line"><span class="t">${esc(p.time)}</span>
      <span class="proto ${esc(p.protocol)}">${esc(p.protocol)}</span> ${esc(p.src)}:${esc(p.sport ?? "")} → ${esc(
        p.dst
      )}:${esc(p.dport ?? "")} ${esc(p.length)}o
    </div>`
    )
    .join("");
}

document.getElementById("btn-traffic-export").addEventListener("click", () => {
  window.location = tokenUrl("/api/traffic/export.csv");
});

// ---------- Tools ----------
async function runTool(name, body) {
  document.getElementById("tool-output").textContent = `${name}…`;
  const r = await api(`/api/tools/${name}`, { method: "POST", body: JSON.stringify(body) });
  return r;
}

document.getElementById("btn-ping").addEventListener("click", async () => {
  const ip = document.getElementById("tool-target").value.trim();
  if (!ip) return;
  const r = await runTool("ping", { ip });
  document.getElementById("tool-output").textContent = r.output || r.error || JSON.stringify(r, null, 2);
  log(`ping ${esc(ip)} → ${r.ok ? "OK" : "FAIL"}`);
});

document.getElementById("btn-traceroute").addEventListener("click", async () => {
  const ip = document.getElementById("tool-target").value.trim();
  if (!ip) return;
  const r = await runTool("traceroute", { ip });
  document.getElementById("tool-output").textContent =
    r.raw || (r.hops || []).join("\n") || r.message || r.error || "—";
  log(`traceroute ${esc(ip)}`);
});

document.getElementById("btn-banner").addEventListener("click", async () => {
  const ip = document.getElementById("tool-target").value.trim();
  const port = document.getElementById("tool-port").value.trim() || "80";
  if (!ip) return;
  const r = await runTool("banner", { ip, port });
  document.getElementById("tool-output").textContent =
    r.banner || r.error || JSON.stringify(r, null, 2);
  log(`banner ${esc(ip)}:${esc(port)}`);
});

document.getElementById("btn-dns")?.addEventListener("click", async () => {
  const ip = document.getElementById("tool-target").value.trim();
  if (!ip) return;
  const r = await runTool("dns", { query: ip });
  document.getElementById("tool-output").textContent = JSON.stringify(r, null, 2);
  log(`dns ${esc(ip)}`);
});

document.getElementById("btn-tls")?.addEventListener("click", async () => {
  const ip = document.getElementById("tool-target").value.trim();
  const port = document.getElementById("tool-port").value.trim() || "443";
  if (!ip) return;
  const r = await runTool("tls", { host: ip, port });
  document.getElementById("tool-output").textContent = JSON.stringify(r, null, 2);
  log(`tls ${esc(ip)}:${esc(port)}`);
});

// ---------- Topology ----------
async function renderTopology() {
  const data = await api("/api/topology");
  const container = document.getElementById("network-graph");
  if (data.meta) {
    document.getElementById("tp-subnet").textContent = data.meta.subnet || "—";
    document.getElementById("tp-gateway").textContent = data.meta.gateway || "—";
    document.getElementById("tp-devices").textContent = data.meta.devices || 0;
    document.getElementById("tp-intermediates").textContent = data.meta.intermediates || 0;
  }

  if (typeof vis === "undefined") {
    container.innerHTML = `<div class="empty-state">vis-network non chargé (réseau / CDN).</div>`;
    return;
  }

  const nodes = new vis.DataSet(
    (data.nodes || []).map((n) => ({
      ...n,
      color: colorForRole(n.role || n.group),
      font: { color: "#e8ecf1", face: "IBM Plex Mono", size: 11, multi: true },
    }))
  );
  const edges = new vis.DataSet((data.edges || []).map((e) => edgeStyle(e)));

  const options = {
    nodes: { borderWidth: 2, shadow: false },
    edges: { smooth: { type: "cubicBezier", forceDirection: "vertical", roundness: 0.4 } },
    physics: state.hierarchical
      ? false
      : { stabilization: true, barnesHut: { gravitationalConstant: -3500 } },
    layout: state.hierarchical
      ? {
          hierarchical: {
            enabled: true,
            direction: "UD",
            sortMethod: "directed",
            levelSeparation: 100,
            nodeSpacing: 140,
          },
        }
      : { hierarchical: { enabled: false } },
    interaction: { hover: true, tooltipDelay: 120 },
  };

  if (state.networkGraph) state.networkGraph.destroy();
  state.networkGraph = new vis.Network(container, { nodes, edges }, options);
  state.networkGraph.on("click", (params) => {
    if (params.nodes?.length) {
      const id = params.nodes[0];
      if (id && id !== "internet" && id !== "self" && id !== "gateway") {
        openHostDrawer(id);
      }
    }
  });
}

function colorForRole(role) {
  const map = {
    internet: { background: "#0a0d12", border: "#565f6e" },
    gateway: { background: "#0a4d28", border: "#12a150" },
    router: { background: "#0a2a3a", border: "#2fd9d0" },
    ap: { background: "#3a2200", border: "#f77f00" },
    switch: { background: "#0a2030", border: "#3b9eff" },
    pc: { background: "#1a1a2e", border: "#6b7cff" },
    apple: { background: "#1a1a1a", border: "#aaaaaa" },
    mobile: { background: "#2e1a2e", border: "#ff5599" },
    raspberry: { background: "#2e0000", border: "#ef4444" },
    vm: { background: "#1a0033", border: "#9900ff" },
    iot: { background: "#003333", border: "#2fd9d0" },
    camera: { background: "#2a1010", border: "#ef4444" },
    printer: { background: "#2a1a00", border: "#f77f00" },
    self: { background: "#7a4200", border: "#f77f00" },
    host_open_ports: { background: "#1a2230", border: "#12a150" },
    host: { background: "#151b25", border: "#565f6e" },
    unknown: { background: "#151b25", border: "#565f6e" },
  };
  return map[role] || map.unknown;
}

function edgeStyle(e) {
  const t = e.edge_type || "client";
  if (t === "uplink") return { ...e, color: { color: "#565f6e" }, width: 1, dashes: true };
  if (t === "backbone") return { ...e, color: { color: "#2fd9d055" }, width: 2 };
  return { ...e, color: { color: "#232b38" }, width: 1 };
}

document.getElementById("btn-refresh-topology").addEventListener("click", renderTopology);
document.getElementById("btn-export-topo-csv").addEventListener("click", () => {
  window.location = tokenUrl("/api/topology/export.csv");
});

document.getElementById("btn-layout-toggle").addEventListener("click", () => {
  state.hierarchical = !state.hierarchical;
  document.getElementById("btn-layout-toggle").textContent = state.hierarchical
    ? "Hiérarchique"
    : "Force Atlas";
  renderTopology();
});

document.getElementById("btn-live-toggle").addEventListener("click", async () => {
  state.liveOn = !state.liveOn;
  const btn = document.getElementById("btn-live-toggle");
  btn.textContent = state.liveOn ? "Live ON" : "Live OFF";
  btn.classList.toggle("live-on", state.liveOn);
  if (state.liveTimer) clearInterval(state.liveTimer);
  if (state.liveOn) {
    const sec = parseInt(document.getElementById("live-interval").value, 10) || 60;
    log(`Live monitoring (léger) toutes les ${sec}s`);
    toast(`Live ON · ${sec}s`, "ok");
    state.liveTimer = setInterval(async () => {
      const subnet = document.getElementById("arp-subnet").value.trim();
      const res = await api("/api/arp-scan", {
        method: "POST",
        body: JSON.stringify({ subnet, enrich: true, light: true, async: true }),
      });
      if (res.job_id) {
        // lightweight wait
        const wait = async () => {
          for (let i = 0; i < 40; i++) {
            await new Promise((r) => setTimeout(r, 500));
            const j = await api(`/api/jobs/${res.job_id}`);
            if (j.status === "done" && j.result && !j.result.error) {
              state.arp = j.result;
              renderArpResults(j.result);
              populateTargetDropdown(j.result.hosts || []);
              updateDashboard();
              if (document.getElementById("view-topology").classList.contains("active")) {
                renderTopology();
              }
              log(`↻ Live: ${j.result.count} hôte(s)`);
              return;
            }
            if (j.status === "error" || j.status === "cancelled") return;
          }
        };
        wait();
      }
    }, sec * 1000);
  } else {
    log("Live monitoring OFF");
  }
});

// ---------- Keyboard shortcuts ----------
document.addEventListener("keydown", (e) => {
  if (e.target.matches("input, textarea, select")) return;
  if (e.key === "s") document.getElementById("btn-home-scan")?.click();
  if (e.key === "Escape") closeDrawer();
  if (e.key === "1") showView("dashboard");
  if (e.key === "2") showView("discovery");
  if (e.key === "3") showView("scan");
  if (e.key === "4") showView("topology");
});

// ---------- Init ----------
systemCheck();
loadNetworkInfo();
log(`HARMATTAN v${window.HARMATTAN_VERSION || "3"} initialisé — prêt pour l’audit.`);
toast("HARMATTAN prêt", "ok");
