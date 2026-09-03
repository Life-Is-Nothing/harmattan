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
  topoRaw: null,
  topoFilter: { role: "", q: "" },
  currentJob: null,
  jobPoll: null,
  arpFilter: "",
  attackFilter: "",
  presentMode: false,
  detailHost: { ip: "", mac: "", role: "" },
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
  if (!box || box.style.display === "none" || box.getAttribute("aria-hidden") === "true") {
    if (typeof console !== "undefined" && console.debug) console.debug("[HARMATTAN]", msg);
    return;
  }
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
  const res = await fetch(path, {
    credentials: "same-origin",
    ...opts,
    headers,
  });
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    const data = await res.json();
    if (res.status === 401) {
      // Suite SSO: redirect to Identity login
      if (window.HarmattanSSO && window.HarmattanSSO.loginUrl) {
        window.location.href = window.HarmattanSSO.loginUrl();
        return data;
      }
      toast("Session requise — reconnectez-vous (Identity)", "err");
    }
    if (res.status === 404 && data && data.error === "not_found") {
      console.warn("API not found:", path);
    }
    return data;
  }
  if (res.status === 401 && window.HarmattanSSO) {
    window.location.href = window.HarmattanSSO.loginUrl();
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
  if (state.presentMode && name !== "topology") exitPresentMode();
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("active"));
  const view = document.getElementById("view-" + name);
  if (view) view.classList.add("active");
  const nav = document.querySelector(`.nav-item[data-view="${name}"]`);
  if (nav) nav.classList.add("active");
  if (name === "topology") renderTopology();
  if (name === "attack") refreshAttack();
  if (name === "dashboard") {
    refreshHistory();
    refreshHealth();
  }
  if (name === "history") {
    refreshScans();
    refreshOverrides();
    refreshHistoryFull();
    refreshKnownHosts();
    refreshIgnoredHosts();
    refreshFindingsCleanup();
    loadSahelSettings();
  }
  if (name === "intel") {
    refreshIntel();
    refreshBridgeStatus();
  }
}

document.querySelectorAll(".nav-item").forEach((item) => {
  item.addEventListener("click", () => showView(item.dataset.view));
});

// ---------- Jobs ----------
async function refreshJobQueueHint() {
  const el = document.getElementById("job-queue");
  if (!el) return;
  try {
    const d = await api("/api/jobs");
    const active = (d.jobs || []).filter((j) => j.status === "running" || j.status === "pending");
    el.textContent = active.length > 1 ? `+${active.length - 1} en file` : active.length === 1 ? "1 actif" : "";
  } catch (_) {
    /* ignore */
  }
}

function showJobBar(kind, msg, pct) {
  const bar = document.getElementById("job-bar");
  bar.classList.remove("hidden");
  bar.classList.add("active");
  document.getElementById("job-kind").textContent = kind;
  document.getElementById("job-msg").textContent = msg || "";
  const p = Math.max(0, Math.min(100, Number(pct) || 0));
  document.getElementById("job-fill").style.width = `${p}%`;
  const pctEl = document.getElementById("job-pct");
  if (pctEl) pctEl.textContent = `${Math.round(p)}%`;
  refreshJobQueueHint();
}

function hideJobBar() {
  const bar = document.getElementById("job-bar");
  bar.classList.add("hidden");
  bar.classList.remove("active");
  document.getElementById("job-fill").style.width = "0%";
  const pctEl = document.getElementById("job-pct");
  if (pctEl) pctEl.textContent = "0%";
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
  }, 700);
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
  fillTrafficIfaces(d.interfaces, d.capture_iface);
  const banner = document.getElementById("traffic-root-banner");
  if (banner && typeof d.running_as_root === "boolean") {
    banner.classList.toggle("hidden", d.running_as_root);
  }
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
  const banner = document.getElementById("traffic-root-banner");
  if (banner) banner.classList.toggle("hidden", !!d.running_as_root);
  if (!d.running_as_root) {
    log("⚠ Mode non-root : ARP et capture trafic limités — préfère Capture 10 s avec sudo");
  }
}

// ---------- Dashboard ----------
document.getElementById("btn-home-scan").addEventListener("click", async () => {
  const btn = document.getElementById("btn-home-scan");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Full-chain…';
  log("⚡ Full-chain : ARP → nmap → topologie → push Sahel…");

  const iface = document.getElementById("iface-select").value || null;
  const res = await api("/api/home-scan", {
    method: "POST",
    body: JSON.stringify({
      iface,
      nmap_gateway: true,
      nmap_profile: "quick",
      async: true,
      full_chain: true,
    }),
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
  const n = result.arp?.count || 0;
  const chain = result.full_chain ? "full-chain" : "scan";
  log(`✓ ${n} appareil(s) · ${chain}${result.sahel_push ? (result.sahel_push.ok ? " · Sahel OK" : " · Sahel local") : ""}`);
  let toastMsg = `Scan maison : ${n} appareils`;
  if (result.sahel_push) {
    toastMsg += result.sahel_push.ok ? " · poussé Sahel" : " · Sahel offline (export local)";
  }
  toast(toastMsg, result.sahel_push && !result.sahel_push.ok ? "warn" : "ok");
  if (result.arp) {
    renderArpResults(result.arp);
    populateTargetDropdown(result.arp.hosts || []);
  }
  updateDashboard();
  if (result.nmap && !result.nmap.error) renderNmapResults(result.nmap);
  if (result.attack) renderAttack(result.attack);
  if (result.topology && typeof renderTopology === "function") {
    try {
      renderTopology(result.topology);
    } catch (_) {
      /* optional */
    }
  }
  renderNewDevices(result.new_devices || result.arp?.new_devices);
  refreshHistory();
}

function tokenUrl(path) {
  // Cookie httponly + same-origin — never leak token in URL/query
  return (window.HarmattanCore && window.HarmattanCore.safeUrl)
    ? window.HarmattanCore.safeUrl(path)
    : path;
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
function renderDiffArp(d) {
  const panel = document.getElementById("diff-arp-panel");
  if (!panel) return;
  panel.style.display = "block";
  const s = d.summary || {};
  document.getElementById("diff-n-plus").textContent = s.appeared ?? 0;
  document.getElementById("diff-n-minus").textContent = s.disappeared ?? 0;
  document.getElementById("diff-n-chg").textContent = s.changed ?? 0;
  const baseNote = d.has_baseline
    ? `Comparaison prev (${d.prev_count ?? "—"}) → last (${d.last_count ?? "—"})`
    : "Pas de baseline précédente — lance 2 scans ARP pour un vrai delta.";
  document.getElementById("diff-arp-summary").textContent = baseNote;

  const rowHost = (h) =>
    `<tr>
      <td class="mono">${esc(h.ip)}</td>
      <td class="mono">${esc(h.mac || "—")}</td>
      <td>${esc(h.vendor || "—")}</td>
      <td>${roleBadge(h.role)}</td>
    </tr>`;

  document.getElementById("diff-appeared").innerHTML =
    (d.appeared || []).map(rowHost).join("") ||
    `<tr><td colspan="4" class="muted">Aucun nouvel hôte</td></tr>`;
  document.getElementById("diff-disappeared").innerHTML =
    (d.disappeared || []).map(rowHost).join("") ||
    `<tr><td colspan="4" class="muted">Aucun hôte disparu</td></tr>`;
  document.getElementById("diff-changed").innerHTML =
    (d.changed || [])
      .map((c) => {
        const parts = Object.entries(c.changes || {})
          .map(([k, v]) => {
            if (k === "open_ports") {
              return `ports +[${(v.added || []).join(",")}] −[${(v.removed || []).join(",")}]`;
            }
            return `${k}: ${v.from ?? "∅"} → ${v.to ?? "∅"}`;
          })
          .join(" · ");
        return `<tr><td class="mono">${esc(c.ip)}</td><td>${esc(parts)}</td></tr>`;
      })
      .join("") || `<tr><td colspan="2" class="muted">Aucun changement de métadonnées</td></tr>`;

  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

document.getElementById("btn-diff-arp")?.addEventListener("click", async () => {
  const d = await api("/api/diff/arp");
  if (d.error) return toast(d.message || d.error, "err");
  const s = d.summary || {};
  log(`Δ ARP +${s.appeared || 0} / -${s.disappeared || 0} / ~${s.changed || 0}`);
  toast(`Diff: +${s.appeared} −${s.disappeared} ~${s.changed}`, "ok");
  renderDiffArp(d);
});
document.getElementById("btn-diff-close")?.addEventListener("click", () => {
  const panel = document.getElementById("diff-arp-panel");
  if (panel) panel.style.display = "none";
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
async function downloadBlob(url, filename) {
  const headers = {};
  if (TOKEN) headers["X-Harmattan-Token"] = TOKEN;
  const res = await fetch(url, { headers });
  const ct = res.headers.get("content-type") || "";
  if (!res.ok || ct.includes("application/json")) {
    let msg = `HTTP ${res.status}`;
    try {
      const j = await res.json();
      msg = j.message || j.error || msg;
    } catch (_) {}
    throw new Error(msg);
  }
  const blob = await res.blob();
  if (blob.size < 24) throw new Error("Fichier trop petit / vide");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 2000);
}

document.getElementById("btn-traffic-pcap")?.addEventListener("click", async () => {
  try {
    log("📦 Export PCAP…");
    await downloadBlob(tokenUrl("/api/traffic/export.pcap"), "harmattan_traffic.pcap");
    toast("PCAP téléchargé", "ok");
    log("📦 PCAP exporté");
  } catch (e) {
    toast(e.message || "Export PCAP échoué", "err");
    log(`⚠ PCAP: ${esc(e.message)}`);
  }
});

document.getElementById("btn-traffic-import-pcap")?.addEventListener("click", async () => {
  const input = document.getElementById("traffic-pcap-file");
  const file = input?.files?.[0];
  if (!file) {
    toast("Choisis un fichier .pcap d'abord", "err");
    return;
  }
  const fd = new FormData();
  fd.append("pcap", file);
  const headers = {};
  if (TOKEN) headers["X-Harmattan-Token"] = TOKEN;
  try {
    log(`📥 Import PCAP ${esc(file.name)}…`);
    const res = await fetch("/api/traffic/import.pcap", { method: "POST", headers, body: fd });
    const data = await res.json();
    if (data.error) {
      toast(data.message || data.error, "err");
      return;
    }
    toast(`PCAP: ${data.total_packets || 0} paquets`, "ok");
    log(`📥 ${data.total_packets || 0} paquets importés`);
    // refresh UI like snapshot
    document.getElementById("traffic-total").textContent = data.total_packets || 0;
    document.getElementById("traffic-bytes").textContent = (
      (data.bytes_total || 0) / 1024
    ).toFixed(1);
    if (data.top_flows) {
      document.getElementById("traffic-flows").innerHTML =
        (data.top_flows || [])
          .map(
            (f) => `
        <tr>
          <td>${esc(f.src)}</td><td>${esc(f.dst)}</td>
          <td><span class="proto ${esc(f.protocol)}">${esc(f.protocol)}</span></td>
          <td>${esc(f.dport ?? "—")}</td>
          <td>${esc(f.packets)}</td><td>${((f.bytes || 0) / 1024).toFixed(1)} Ko</td>
        </tr>`
          )
          .join("") || `<tr><td colspan="6">—</td></tr>`;
    }
  } catch (e) {
    toast("Import PCAP échoué", "err");
    log(`⚠ import: ${esc(e.message)}`);
  }
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
    <tr class="clickable-row" data-ip="${esc(h.ip)}" title="Clic = fiche hôte + explications">
      <td><b>${esc(h.ip)}</b></td>
      <td class="mono">${esc(h.mac || "—")}</td>
      <td>${esc(h.vendor || "—")}</td>
      <td>${esc(h.hostname || "—")}</td>
      <td data-hmx="role" data-hmx-json="${esc(JSON.stringify({ role: h.role || "unknown" }))}">${roleBadge(h.role)}</td>
      <td>${esc(h.os_hint || "—")}</td>
      <td>${(h.open_ports || [])
        .slice(0, 8)
        .map((p) => {
          const port = typeof p === "object" ? p.port : p;
          return `<span class="badge" style="margin:1px;cursor:pointer" data-hmx="port" data-hmx-json="${esc(
            JSON.stringify({ port })
          )}">${esc(port)}</span>`;
        })
        .join(" ") || "—"}</td>
      <td>
        <button class="mini" data-act="ping" data-ip="${esc(h.ip)}">ping</button>
        <button class="mini secondary" data-act="tr" data-ip="${esc(h.ip)}">tr</button>
        <button class="mini secondary" data-act="detail" data-ip="${esc(h.ip)}">détail</button>
        <button class="mini secondary" data-act="explain" data-ip="${esc(h.ip)}">ⓘ</button>
        <button class="mini secondary" data-act="remove" data-ip="${esc(h.ip)}" data-mac="${esc(h.mac || "")}" title="Retirer de la session">✕</button>
        <button class="mini secondary" data-act="ignore" data-ip="${esc(h.ip)}" data-mac="${esc(h.mac || "")}" title="Ignorer (ne plus réapparaître)">⊘</button>
      </td>
    </tr>`
    )
    .join("");

  el.innerHTML = `
    <p class="hmx-hint">Clique une ligne pour le dossier hôte · ports / ⓘ pour l’explication</p>
    <table>
      <thead><tr>
        <th>IP</th><th>MAC</th><th>Vendor</th><th>Hostname</th>
        <th>Rôle</th><th>OS</th><th>Ports</th><th>Actions</th>
      </tr></thead>
      <tbody>${rows || '<tr><td colspan="8">Aucun résultat pour ce filtre</td></tr>'}</tbody>
    </table>`;

  el.querySelectorAll("[data-act]").forEach((btn) => {
    btn.addEventListener("click", async (ev) => {
      ev.stopPropagation();
      const ip = btn.dataset.ip;
      const mac = btn.dataset.mac || "";
      const act = btn.dataset.act;
      if (act === "detail") openHostDrawer(ip);
      else if (act === "explain") {
        const h = (result.hosts || []).find((x) => x.ip === ip) || { ip };
        if (window.HMExplain) window.HMExplain.open(`Hôte ${ip}`, window.HMExplain.hostHtml(h));
        else openHostDrawer(ip);
      } else if (act === "remove") {
        await removeHostFromSession(ip, mac, false);
      } else if (act === "ignore") {
        if (!confirm(`Ignorer ${ip || mac} ? Il ne réapparaîtra plus dans les scans.`)) return;
        await removeHostFromSession(ip, mac, true);
      } else quickTool(ip, act === "ping" ? "ping" : "tr");
    });
  });
  el.querySelectorAll("tr.clickable-row").forEach((tr) => {
    tr.addEventListener("click", (ev) => {
      if (ev.target.closest("[data-hmx],[data-act]")) return;
      openHostDrawer(tr.dataset.ip);
    });
  });
  window.HMExplain?.bind(el);
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

  const role = a.role || atk.role || "unknown";
  const roleExpl = window.HMExplain ? window.HMExplain.roleInfo(role) : "";
  // enrich ports with clickable explanations
  if (n.ports?.length && window.HMExplain) {
    portsHtml = `<p class="hmx-hint" style="margin:0 0 8px">Clique un port pour l’explication risque / remédiation</p>
      <table><thead><tr><th>Port</th><th>Svc</th><th>Version</th><th></th></tr></thead><tbody>${n.ports
        .filter((p) => p.state === "open")
        .map((p) => {
          const info = window.HMExplain.portInfo(p.port);
          return `<tr class="hmx-clickable" data-hmx="port" data-hmx-json="${esc(
            JSON.stringify({
              port: p.port,
              service: p.service || info.name,
              product: p.product || "",
              version: p.version || "",
            })
          )}">
            <td><b>${esc(p.port)}/${esc(p.protocol)}</b></td>
            <td>${esc(p.service || info.name)}</td>
            <td>${esc((p.product || "") + " " + (p.version || ""))}</td>
            <td><span class="badge ${esc(info.risk)}">${esc(info.risk)}</span></td>
          </tr>`;
        })
        .join("")}</tbody></table>`;
  } else if (a.open_ports?.length && window.HMExplain) {
    portsHtml = a.open_ports
      .map((p) => {
        const port = typeof p === "object" ? p.port : p;
        const info = window.HMExplain.portInfo(port);
        return `<span class="badge ${esc(info.risk)}" style="margin:2px;cursor:pointer" data-hmx="port" data-hmx-json="${esc(
          JSON.stringify({ port, service: info.name })
        )}">${esc(port)} · ${esc(info.name)}</span>`;
      })
      .join(" ");
  }

  if (vul.services?.length && window.HMExplain) {
    cveHtml = vul.services
      .map(
        (s) =>
          `<div><b>${esc(s.product)} ${esc(s.version)}</b><ul>${(s.cves || [])
            .map(
              (c) =>
                `<li data-hmx="cve" data-hmx-json="${esc(JSON.stringify(c))}" class="hmx-clickable"><a href="${esc(
                  c.url || "#"
                )}" target="_blank" rel="noopener" onclick="event.stopPropagation()">${esc(c.id)}</a>
                <span class="badge ${esc(c.severity)}">${esc(c.severity)}</span> ${c.score ?? ""} — ${esc(
                  (c.description || "").slice(0, 80)
                )}…</li>`
            )
            .join("")}</ul></div>`
      )
      .join("");
  }

  document.getElementById("drawer-body").innerHTML = `
    <p class="hmx-hint">Panneau hôte · clique ports / CVE pour plus d’infos</p>
    <h3>Identité</h3>
    <div class="kv"><span>IP</span><b>${esc(ip)}</b></div>
    <div class="kv"><span>MAC</span><b>${esc(a.mac || n.mac || "—")}</b></div>
    <div class="kv"><span>Vendor</span><b>${esc(a.vendor || "—")}</b></div>
    <div class="kv"><span>Hostname</span><b>${esc(a.hostname || (n.hostnames || [])[0] || "—")}</b></div>
    <div class="kv"><span>Rôle</span><b data-hmx="role" data-hmx-json="${esc(
      JSON.stringify({ role })
    )}" class="hmx-clickable">${roleBadge(role)}</b></div>
    ${roleExpl ? `<p style="font-size:12px;color:var(--text-mid);margin:6px 0 10px">${esc(roleExpl)}</p>` : ""}
    <div class="kv"><span>OS</span><b>${esc(a.os_hint || (n.os_matches && n.os_matches[0]?.name) || "—")}</b></div>
    <div class="kv"><span>TTL</span><b>${esc(a.ttl ?? "—")}</b></div>
    ${a.snmp_desc ? `<div class="kv"><span>SNMP</span><b>${esc(a.snmp_desc)}</b></div>` : ""}
    <h3>Ports</h3>${portsHtml}
    <h3>Surface d'attaque</h3>
    <div class="kv"><span>Expositions</span><b>${esc(atk.exposure_count ?? 0)}</b></div>
    <div class="kv" data-hmx="severity" data-hmx-json="${esc(
      JSON.stringify({ severity: atk.max_risk || "info" })
    )}" class="hmx-clickable"><span>Max risk</span><b>${esc(atk.max_risk || "none")}</b></div>
    <h3>CVE <span class="hmx-hint" style="display:inline;margin:0">(clic = explication)</span></h3>${cveHtml}
    <h3>Actions</h3>
    <div class="controls-row">
      <button class="mini" id="dr-ping">Ping</button>
      <button class="mini secondary" id="dr-tr">Traceroute</button>
      <button class="mini secondary" id="dr-nmap">Nmap quick</button>
      <button class="mini secondary" id="dr-explain">Tout expliquer</button>
      <button class="mini secondary" id="dr-remove" title="Retirer de la session + hôtes connus">Supprimer</button>
      <button class="mini secondary" id="dr-ignore" title="Blacklist — ne plus réapparaître">Ignorer</button>
    </div>
  `;
  const mac = a.mac || n.mac || "";
  document.getElementById("dr-ping")?.addEventListener("click", () => quickTool(ip, "ping"));
  document.getElementById("dr-tr")?.addEventListener("click", () => quickTool(ip, "tr"));
  document.getElementById("dr-nmap")?.addEventListener("click", () => {
    document.getElementById("nmap-target-manual").value = ip;
    showView("scan");
    document.getElementById("btn-nmap-scan").click();
  });
  document.getElementById("dr-explain")?.addEventListener("click", () => {
    if (!window.HMExplain) return;
    window.HMExplain.open(
      `Hôte ${ip}`,
      window.HMExplain.hostHtml({
        ip,
        mac: a.mac || n.mac,
        vendor: a.vendor,
        hostname: a.hostname,
        role,
        os_hint: a.os_hint,
        ports: (n.ports || []).filter((p) => p.state === "open"),
        open_ports: a.open_ports,
      })
    );
  });
  document.getElementById("dr-remove")?.addEventListener("click", async () => {
    if (!confirm(`Supprimer ${ip} de la session et des hôtes connus ?`)) return;
    await removeHostFromSession(ip, mac, false);
    closeDrawer();
  });
  document.getElementById("dr-ignore")?.addEventListener("click", async () => {
    if (!confirm(`Ignorer ${ip} définitivement (blacklist) ?`)) return;
    await removeHostFromSession(ip, mac, true);
    closeDrawer();
  });
  window.HMExplain?.bind(document.getElementById("drawer-body"));
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
          const risk = window.HMExplain?.portInfo(p.port)?.risk || "info";
          return `
      <tr class="hmx-clickable" title="Clic = explication du port" data-hmx="port" data-hmx-json="${esc(
        JSON.stringify({
          port: p.port,
          service: p.service,
          product: p.product,
          version: p.version,
        })
      )}">
        <td>${esc(p.port)}/${esc(p.protocol)}</td>
        <td><span class="badge open">${esc(p.state)}</span></td>
        <td>${esc(p.service || "")}</td>
        <td>${esc(p.product || "")} ${esc(p.version || "")}</td>
        <td><span class="badge ${esc(risk)}">${esc(risk)}</span> ${scripts || ""}</td>
      </tr>`;
        })
        .join("");

      return `
      <div class="panel" style="margin-bottom:14px;">
        <p class="hmx-hint">Clique un port pour l’explication · IP pour le dossier hôte</p>
        <h2><span class="clickable-row" data-ip="${esc(h.ip)}" style="cursor:pointer">${esc(h.ip)}</span> — ${esc(os)}</h2>
        <table>
          <thead><tr><th>Port</th><th>État</th><th>Service</th><th>Version</th><th>Risque / Scripts</th></tr></thead>
          <tbody>${portRows || '<tr><td colspan="5">Aucun port ouvert</td></tr>'}</tbody>
        </table>
      </div>`;
    })
    .join("");

  el.querySelectorAll("[data-ip]").forEach((node) => {
    node.addEventListener("click", (ev) => {
      ev.stopPropagation();
      openHostDrawer(node.dataset.ip);
    });
  });
  window.HMExplain?.bind(el);
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

  const l0p4Btns = (ip, mac) => `
    <div class="as-host-actions controls-row" style="margin:8px 0 10px;gap:4px;">
      <button type="button" class="mini secondary as-pick" data-ip="${esc(ip)}" data-mac="${esc(mac || "")}">◎ Cible</button>
      <button type="button" class="mini secondary as-act" data-act="ping" data-ip="${esc(ip)}">Ping</button>
      <button type="button" class="mini secondary as-act" data-act="traceroute" data-ip="${esc(ip)}">Trace</button>
      <button type="button" class="mini secondary as-act" data-act="banner" data-ip="${esc(ip)}">Banner</button>
      <button type="button" class="mini secondary as-act" data-act="port-scan" data-ip="${esc(ip)}">Ports</button>
      <button type="button" class="mini secondary as-act" data-act="nmap-light" data-ip="${esc(ip)}">Nmap</button>
      <button type="button" class="mini secondary as-act" data-act="nmap-vuln" data-ip="${esc(ip)}">Nmap+CVE</button>
      <button type="button" class="mini secondary as-act" data-act="http" data-ip="${esc(ip)}">HTTP</button>
      <button type="button" class="mini secondary as-act" data-act="tls" data-ip="${esc(ip)}">TLS</button>
      <button type="button" class="mini secondary as-act" data-act="ssh-keyscan" data-ip="${esc(ip)}">SSH</button>
      <button type="button" class="mini secondary as-act" data-act="dns" data-ip="${esc(ip)}">DNS</button>
      <button type="button" class="mini secondary as-act" data-act="whois" data-ip="${esc(ip)}">WHOIS</button>
      <button type="button" class="mini secondary as-act" data-act="wol" data-ip="${esc(ip)}" data-mac="${esc(mac || "")}">WOL</button>
      <button type="button" class="mini secondary as-act" data-act="ai-host" data-ip="${esc(ip)}">AI</button>
      <button type="button" class="mini secondary as-drawer" data-ip="${esc(ip)}">Détail</button>
    </div>`;

  el.innerHTML = hosts
    .map((h) => {
      const mac = h.mac || "";
      if (!h.exposures?.length) {
        return `<div class="panel">
        <h2><span style="cursor:pointer" data-ip="${esc(h.ip)}">${esc(h.ip)}</span>
          ${h.hostname ? "— " + esc(h.hostname) : ""} ${roleBadge(h.role)}
          <span class="badge open">clean</span></h2>
        ${l0p4Btns(h.ip, mac)}
        <p style="color:var(--text-mid);font-size:12px;">Aucun port sensible détecté — commandes L0p4 disponibles.</p></div>`;
      }
      const rows = h.exposures
        .map(
          (e) => `
      <tr class="hmx-clickable" data-hmx="port" data-hmx-json="${esc(
        JSON.stringify({
          port: e.port,
          service: e.service,
          product: e.product,
          version: e.version,
        })
      )}" title="Clic = pourquoi ce risque">
        <td>${esc(e.port)}/${esc(e.protocol || "tcp")}</td>
        <td>${esc(e.service || "—")}</td>
        <td>${esc(e.product || "")} ${esc(e.version || "")}</td>
        <td data-hmx="severity" data-hmx-json="${esc(JSON.stringify({ severity: e.risk }))}"><span class="badge ${esc(
          e.risk
        )}">${esc(e.risk)}</span></td>
        <td>${esc(e.source || "—")}</td>
        <td style="font-size:11px;color:var(--text-low)">${esc(e.recommendation || "—")}</td>
      </tr>`
        )
        .join("");
      return `
      <div class="panel" style="margin-bottom:14px;">
        <h2><span style="cursor:pointer" data-ip="${esc(h.ip)}">${esc(h.ip)}</span>
          ${h.hostname ? "— " + esc(h.hostname) : ""} ${roleBadge(h.role)}
          <span class="badge ${esc(h.max_risk)}">${esc(h.exposure_count || h.exposures.length)} expo</span></h2>
        ${l0p4Btns(h.ip, mac)}
        <p class="hmx-hint muted small">Clique une exposition pour l’explication · boutons = commandes L0p4Map</p>
        <table>
          <thead><tr><th>Port</th><th>Service</th><th>Produit</th><th>Risque</th><th>Source</th><th>Reco</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
      </div>`;
    })
    .join("");

  el.querySelectorAll("[data-ip]").forEach((n) => {
    if (n.classList.contains("as-act") || n.classList.contains("as-pick") || n.classList.contains("as-drawer")) return;
    n.addEventListener("click", () => {
      const ip = n.dataset.ip;
      const tgt = document.getElementById("as-target");
      if (tgt) tgt.value = ip;
      openHostDrawer(ip);
    });
  });
  el.querySelectorAll(".as-pick").forEach((b) =>
    b.addEventListener("click", () => {
      document.getElementById("as-target").value = b.dataset.ip || "";
      if (b.dataset.mac) document.getElementById("as-mac").value = b.dataset.mac;
      toast(`Cible → ${b.dataset.ip}`, "ok");
    })
  );
  el.querySelectorAll(".as-drawer").forEach((b) =>
    b.addEventListener("click", () => openHostDrawer(b.dataset.ip))
  );
  el.querySelectorAll(".as-act").forEach((b) =>
    b.addEventListener("click", () => {
      runAsAction(b.dataset.act, b.dataset.ip, b.dataset.mac);
    })
  );
  window.HMExplain?.bind(el);
}

async function runAsAction(action, ip, mac) {
  const target = ip || document.getElementById("as-target")?.value?.trim();
  const port = document.getElementById("as-port")?.value?.trim() || "80";
  const macV = mac || document.getElementById("as-mac")?.value?.trim() || "";
  const out = document.getElementById("as-cmd-out");
  if (!target && action !== "wol") {
    toast("IP cible manquante", "warn");
    return;
  }
  if (out) out.textContent = `${action} ${target || macV}…`;
  if (action === "ai-host") {
    const d = await api(`/api/ai-host/${encodeURIComponent(target)}`);
    if (out) out.textContent = JSON.stringify(d, null, 2);
    toast(d?.error ? d.error : `AI ${target}: ${d?.severity || "ok"}`, d?.error ? "err" : "ok");
    return;
  }
  const body = { action, ip: target, target, port, mac: macV, async: true };
  const r = await api("/api/host/quick", { method: "POST", body: JSON.stringify(body) });
  if (r.job_id) {
    toast(`${action} job…`, "ok");
    await pollJob(r.job_id, (result) => {
      if (out) out.textContent = JSON.stringify(result, null, 2);
      toast(`${action} terminé`, "ok");
      // refresh attack after nmap
      if (String(action).startsWith("nmap")) refreshAttack();
    });
    return;
  }
  if (out) out.textContent = r.output || r.raw || r.banner || JSON.stringify(r, null, 2);
  toast(r.ok === false || r.error ? r.error || "fail" : `${action} OK`, r.ok === false || r.error ? "err" : "ok");
}

// Global L0p4 command bar on Attack Surface
document.getElementById("as-cmds-global")?.addEventListener("click", (e) => {
  const btn = e.target.closest("[data-as-act]");
  if (!btn) return;
  runAsAction(btn.getAttribute("data-as-act"));
});
document.getElementById("btn-as-ai")?.addEventListener("click", () => {
  runNetworkAiAnalyze();
  try {
    showView("dashboard");
  } catch (_) {}
});
document.getElementById("btn-as-vuln")?.addEventListener("click", () => {
  document.getElementById("btn-vuln-scan")?.click();
  try {
    showView("vuln");
  } catch (_) {}
});

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
    `<p class="hmx-hint">Clique une CVE pour score, impact et bonnes pratiques</p>
    <div class="stat-grid" style="margin-bottom:14px;">
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
              <tr class="hmx-clickable" data-hmx="cve" data-hmx-json="${esc(
                JSON.stringify(c)
              )}" title="Clic = explication CVE">
                <td><a href="${esc(c.url)}" target="_blank" rel="noopener" style="color:var(--cyan)" onclick="event.stopPropagation()">${esc(
                  c.id
                )}</a></td>
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
  window.HMExplain?.bind(el);
}

// ---------- Traffic ----------
function fillTrafficIfaces(interfaces, preferred) {
  const sel = document.getElementById("traffic-iface");
  if (!sel || sel.dataset.filled === "1") return;
  (interfaces || []).forEach((i) => {
    const o = document.createElement("option");
    o.value = i.name;
    o.textContent = `${i.name} — ${i.ip || "?"}${i.virtual ? " (virt)" : ""}`;
    if (preferred && i.name === preferred) o.selected = true;
    sel.appendChild(o);
  });
  sel.dataset.filled = "1";
}

state.wsSelected = null;
state.wsFilter = "";

function renderTrafficSnap(snap) {
  if (!snap) return;
  document.getElementById("traffic-bytes").textContent = (
    (snap.bytes_total || 0) / 1024
  ).toFixed(1);
  if (document.getElementById("traffic-buffer")) {
    document.getElementById("traffic-buffer").textContent = snap.buffer_size || snap.total_packets || 0;
  }
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
  // refresh packet list from dedicated API
  refreshPacketList();
}

function renderPacketList(data) {
  const body = document.getElementById("ws-packet-body");
  if (!body) return;
  const pkts = data.packets || [];
  document.getElementById("traffic-total").textContent = data.total ?? pkts.length;
  if (document.getElementById("traffic-buffer")) {
    document.getElementById("traffic-buffer").textContent = data.buffer_total ?? data.packets_total ?? "—";
  }
  if (data.bytes_total != null) {
    document.getElementById("traffic-bytes").textContent = ((data.bytes_total || 0) / 1024).toFixed(1);
  }
  const meta = document.getElementById("ws-list-meta");
  if (meta) {
    meta.textContent = `${data.total || 0} affiché(s) · buffer ${data.buffer_total || 0}${
      data.filter ? " · filter: " + data.filter : ""
    }`;
  }
  if (!pkts.length) {
    body.innerHTML = `<tr><td colspan="7" class="muted">Aucun paquet${
      data.filter ? " (filtre trop strict ?)" : " — capture / import PCAP"
    }</td></tr>`;
    return;
  }
  body.innerHTML = pkts
    .map((p) => {
      const proto = p.protocol || "OTHER";
      const selected = state.wsSelected === p.no ? "selected" : "";
      const src =
        p.sport != null && p.sport !== "" ? `${p.src}:${p.sport}` : p.src;
      const dst =
        p.dport != null && p.dport !== "" ? `${p.dst}:${p.dport}` : p.dst;
      return `<tr class="proto-${esc(proto)} ${selected}" data-no="${p.no}">
        <td class="col-no">${p.no}</td>
        <td class="col-time">${esc(p.time)}</td>
        <td class="col-src">${esc(src)}</td>
        <td class="col-dst">${esc(dst)}</td>
        <td class="col-proto"><span class="proto-chip ${esc(proto)}">${esc(proto)}</span></td>
        <td class="col-len">${esc(p.length)}</td>
        <td class="col-info" title="${esc(p.info || "")}">${esc(p.info || "")}</td>
      </tr>`;
    })
    .join("");
}

async function refreshPacketList() {
  const filt = state.wsFilter || document.getElementById("display-filter")?.value || "";
  const q = new URLSearchParams({
    limit: "400",
    offset: "0",
    filter: filt,
  });
  try {
    const data = await api("/api/traffic/packets?" + q.toString());
    renderPacketList(data);
    refreshProtoStats();
  } catch (e) {
    /* ignore */
  }
}

async function selectPacket(no) {
  state.wsSelected = no;
  document.getElementById("traffic-selected").textContent = "#" + no;
  const followBtn = document.getElementById("btn-follow-stream");
  if (followBtn) followBtn.disabled = false;
  document.querySelectorAll("#ws-packet-body tr").forEach((tr) => {
    tr.classList.toggle("selected", String(tr.dataset.no) === String(no));
  });
  try {
    const p = await api(`/api/traffic/packet/${no}`);
    if (p.error) {
      document.getElementById("ws-layers").textContent = p.message || p.error;
      return;
    }
    renderPacketDetail(p);
  } catch (e) {
    document.getElementById("ws-layers").textContent = String(e.message || e);
  }
}

async function refreshProtoStats() {
  try {
    const d = await api("/api/traffic/proto-stats");
    const el = document.getElementById("proto-stats-bars");
    if (!el) return;
    const items = d.protocols || [];
    if (!items.length) {
      el.innerHTML = "—";
      return;
    }
    const max = Math.max(...items.map((x) => x.packets), 1);
    el.innerHTML = items
      .slice(0, 12)
      .map(
        (x) => `<span class="proto-stat">
        <span class="proto-chip ${esc(x.protocol)}">${esc(x.protocol)}</span>
        <span class="bar"><i style="width:${Math.max(6, (x.packets / max) * 100)}%"></i></span>
        <b>${x.packets}</b>
      </span>`
      )
      .join("");
  } catch (_) {}
}

document.getElementById("btn-refresh-proto")?.addEventListener("click", refreshProtoStats);
document.getElementById("btn-traffic-clear")?.addEventListener("click", async () => {
  await api("/api/traffic/clear", { method: "POST", body: "{}" });
  state.wsSelected = null;
  document.getElementById("ws-layers").textContent = "Buffer vidé.";
  document.getElementById("ws-hex").textContent = "—";
  document.getElementById("btn-follow-stream").disabled = true;
  refreshPacketList();
  refreshProtoStats();
  toast("Buffer trafic vidé", "ok");
});

document.getElementById("btn-follow-stream")?.addEventListener("click", async () => {
  if (!state.wsSelected) return;
  const r = await api(`/api/traffic/follow/${state.wsSelected}`);
  if (!r.ok) {
    toast(r.message || r.error || "Follow stream impossible", "err");
    return;
  }
  state.wsStreamNo = state.wsSelected;
  const st = r.stream || {};
  document.getElementById("stream-title").textContent =
    `Stream ${st.client || ""} ↔ ${st.server || ""}` + (st.http ? " · HTTP" : "");
  document.getElementById("stream-meta").textContent =
    `${st.packets || 0} paquets · ${st.payload_bytes || 0} o payload · #${(r.member_nos || []).join(",")}` +
    (r.http?.method ? ` · ${r.http.method} ${r.http.path || ""} → ${r.http.status || ""}` : "");
  // Prefer HTTP pretty reassembly when available
  document.getElementById("stream-body").textContent =
    (r.http && r.http.pretty) || r.assembled || "(vide)";
  document.getElementById("stream-modal")?.classList.remove("hidden");
});

// Scheduled ARP + report
let _schedOn = false;
document.getElementById("btn-sched-toggle")?.addEventListener("click", async () => {
  const btn = document.getElementById("btn-sched-toggle");
  if (!_schedOn) {
    const r = await api("/api/scheduler/start", {
      method: "POST",
      body: JSON.stringify({ interval: 300, with_report: true }),
    });
    _schedOn = true;
    if (btn) btn.textContent = "⏱ Scheduler ON";
    toast(r.message || "Scheduler ON (5 min + rapport)", "ok");
    log("Scheduler ARP planifié démarré");
  } else {
    const r = await api("/api/scheduler/stop", { method: "POST", body: "{}" });
    _schedOn = false;
    if (btn) btn.textContent = "⏱ Scheduler";
    toast(r.message || "Scheduler OFF", "warn");
  }
});
document.getElementById("btn-stream-close")?.addEventListener("click", () => {
  document.getElementById("stream-modal")?.classList.add("hidden");
});
document.getElementById("stream-modal")?.addEventListener("click", (e) => {
  if (e.target.id === "stream-modal") e.target.classList.add("hidden");
});
document.getElementById("btn-stream-export-txt")?.addEventListener("click", () => {
  const no = state.wsStreamNo || state.wsSelected;
  if (!no) return;
  window.location = tokenUrl(`/api/traffic/follow/${no}/export.txt`);
  toast("Export stream TXT…", "ok");
});
document.getElementById("btn-stream-export-json")?.addEventListener("click", () => {
  const no = state.wsStreamNo || state.wsSelected;
  if (!no) return;
  window.location = tokenUrl(`/api/traffic/follow/${no}/export.json`);
  toast("Export stream JSON…", "ok");
});

document.getElementById("btn-sahel-correlate")?.addEventListener("click", async () => {
  toast("Corrélation Sahel…", "ok");
  log("Corrélation paquets ↔ alertes Sahel…");
  const url = document.getElementById("sahel-url")?.value?.trim() || "";
  const r = await api("/api/sahel/correlate", {
    method: "POST",
    body: JSON.stringify(url ? { url } : {}),
  });
  const panel = document.getElementById("corr-panel");
  const sum = document.getElementById("corr-summary");
  const res = document.getElementById("corr-results");
  if (panel) panel.style.display = "block";
  const loc = r.local || {};
  const rem = r.remote || {};
  if (sum) {
    sum.textContent = `Paquets: ${r.packets || 0} · Alertes: ${r.alerts_used || 0} · ` +
      `Match local: ${loc.matched || 0} · Remote: ${rem.ok ? "OK" : "offline"} (${rem.message || rem.via || ""})`;
  }
  const matches = loc.matches || rem.matches || [];
  if (res) {
    if (!matches.length) {
      res.innerHTML = `<span class="muted">Aucun match IP (lance des alertes Sahel + capture avec les mêmes IP).</span>`;
    } else {
      res.innerHTML = matches
        .slice(0, 25)
        .map(
          (m) => `<div class="hist-line">
          <span class="t">${esc(m.severity || "")}</span>
          <span class="k">${esc(m.alert_id || "")}</span>
          <span><b>${esc(m.src || "")}</b>→<b>${esc(m.dst || "")}</b>
            · pkts #${esc((m.top_packet_nos || []).join(","))}
            · ${esc(m.title || "")}</span>
        </div>`
        )
        .join("");
    }
  }
  toast(
    `Corrélation: ${loc.matched || 0} match(s)` +
      (rem.matched != null ? ` · Sahel ${rem.matched}` : ""),
    "ok"
  );
  log(`Corrélation Sahel: local=${loc.matched || 0}`);
});

function renderPacketDetail(p) {
  const layers = p.layers || [];
  const el = document.getElementById("ws-layers");
  if (!layers.length) {
    el.innerHTML = `<div class="muted">Pas de couches pour #${p.no}</div>
      <div>${esc(p.info || "")}</div>`;
  } else {
    el.innerHTML = layers
      .map((L, i) => {
        const fields = (L.fields || [])
          .map(
            (f) =>
              `<div class="ws-field"><span class="k">${esc(f.k)}</span><span class="v">${esc(
                f.v
              )}</span></div>`
          )
          .join("");
        return `<details class="ws-layer" ${i < 3 ? "open" : ""}>
          <summary>${esc(L.name)}${L.summary ? " · " + esc(L.summary) : ""}</summary>
          <div class="ws-fields">${fields || '<span class="muted">—</span>'}</div>
        </details>`;
      })
      .join("");
  }
  const hexEl = document.getElementById("ws-hex");
  const lines = p.hex || [];
  if (!lines.length) {
    hexEl.textContent = "—";
    return;
  }
  hexEl.innerHTML = lines
    .map(
      (ln) =>
        `<span class="off">${esc(ln.offset)}</span> ${esc(ln.hex)} <span class="asc">${esc(
          ln.ascii
        )}</span>`
    )
    .join("\n");
}

document.getElementById("ws-packet-body")?.addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-no]");
  if (!tr) return;
  selectPacket(parseInt(tr.dataset.no, 10));
});

document.getElementById("btn-display-filter")?.addEventListener("click", () => {
  state.wsFilter = document.getElementById("display-filter")?.value?.trim() || "";
  refreshPacketList();
  toast(state.wsFilter ? "Filtre: " + state.wsFilter : "Filtre effacé", "ok");
});
document.getElementById("btn-df-clear")?.addEventListener("click", () => {
  const el = document.getElementById("display-filter");
  if (el) el.value = "";
  state.wsFilter = "";
  refreshPacketList();
});
document.getElementById("display-filter")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    state.wsFilter = e.target.value.trim();
    refreshPacketList();
  }
});

document.getElementById("btn-traffic-oneshot")?.addEventListener("click", async () => {
  const iface = document.getElementById("traffic-iface").value.trim();
  const filter = document.getElementById("traffic-filter").value.trim();
  const btn = document.getElementById("btn-traffic-oneshot");
  btn.disabled = true;
  btn.textContent = "Capture…";
  log("⚡ Capture oneshot 10 s…");
  toast("Capture 10 s en cours…", "ok");
  try {
    const r = await api("/api/traffic/oneshot", {
      method: "POST",
      body: JSON.stringify({ iface, filter, seconds: 10 }),
    });
    if (r.error) {
      toast(r.message || r.error, "err");
      log(`⚠ ${esc(r.message || r.error)}`);
    } else {
      toast(r.message || "Capture terminée", r.warning ? "warn" : "ok");
      log(
        `⚡ ${r.total_packets || 0} paquets · iface ${esc(r.iface || "auto")} · ${esc(
          r.running_as_root ? "root" : "user"
        )}`
      );
      renderTrafficSnap(r);
    }
  } finally {
    btn.disabled = false;
    btn.textContent = "⚡ Capture 10 s";
  }
});

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
  if (r.error && typeof r.error === "string") {
    toast(r.error, "err");
  }
  log(`▶ Capture live · ${esc(r.iface || "auto")}`);
  toast(r.message || "Capture démarrée", r.running_as_root === false ? "warn" : "ok");
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
  renderTrafficSnap(snap);
}

// ensure traffic view refreshes list when opened
const _showViewOrig = showView;
showView = function (name) {
  _showViewOrig(name);
  if (name === "traffic") {
    refreshPacketList();
    api("/api/traffic/snapshot").then(renderTrafficSnap).catch(() => {});
  }
};

document.getElementById("btn-traffic-export").addEventListener("click", () => {
  window.location = tokenUrl("/api/traffic/export.csv");
});

// ---------- Tools ----------
async function runTool(name, body) {
  document.getElementById("tool-output").textContent = `${name}…`;
  const r = await api(`/api/tools/${name}`, { method: "POST", body: JSON.stringify(body) });
  return r;
}

function toolTarget() {
  return (document.getElementById("tool-target")?.value || "").trim();
}
function toolPort(def = "80") {
  return (document.getElementById("tool-port")?.value || "").trim() || def;
}
function toolExtra() {
  return (document.getElementById("tool-extra")?.value || "").trim();
}
function showTool(name, r, summary) {
  const out = document.getElementById("tool-output");
  const meta = document.getElementById("tool-meta");
  if (meta) meta.textContent = summary || name;
  if (!out) return;
  if (typeof r === "string") out.textContent = r;
  else if (r?.output) out.textContent = r.output;
  else if (r?.raw) out.textContent = r.raw;
  else if (r?.banner) out.textContent = r.banner;
  else out.textContent = JSON.stringify(r, null, 2);
}

document.getElementById("btn-tool-clear")?.addEventListener("click", () => {
  const out = document.getElementById("tool-output");
  const meta = document.getElementById("tool-meta");
  if (out) out.textContent = "Sélectionne une action…";
  if (meta) meta.textContent = "Prêt";
});

document.getElementById("btn-ping")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const r = await runTool("ping", { ip });
  showTool("ping", r.output || r.error || r, `ping ${ip} → ${r.ok ? "OK" : "FAIL"}`);
  log(`ping ${esc(ip)} → ${r.ok ? "OK" : "FAIL"}`);
});

document.getElementById("btn-traceroute")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const r = await runTool("traceroute", { ip });
  showTool("traceroute", r.raw || (r.hops || []).join("\n") || r.message || r.error || r, `traceroute ${ip}`);
  log(`traceroute ${esc(ip)}`);
});

document.getElementById("btn-banner")?.addEventListener("click", async () => {
  const ip = toolTarget();
  const port = toolPort("80");
  if (!ip) return;
  const r = await runTool("banner", { ip, port });
  showTool("banner", r.banner || r.error || r, `banner ${ip}:${port}`);
  log(`banner ${esc(ip)}:${esc(port)}`);
});

document.getElementById("btn-dns")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const r = await runTool("dns", { query: ip });
  showTool("dns", r, `dns ${ip}`);
  log(`dns ${esc(ip)}`);
});

document.getElementById("btn-tls")?.addEventListener("click", async () => {
  const ip = toolTarget();
  const port = toolPort("443");
  if (!ip) return;
  const r = await runTool("tls", { host: ip, port });
  showTool("tls", r, `tls ${ip}:${port}`);
  log(`tls ${esc(ip)}:${esc(port)}`);
});

document.getElementById("btn-port-check")?.addEventListener("click", async () => {
  const ip = toolTarget();
  const port = toolPort("80");
  if (!ip) return;
  const r = await runTool("port-check", { ip, port });
  showTool("port-check", r, `port ${ip}:${port} → ${r.open ? "OPEN" : "CLOSED"}`);
  log(`port-check ${esc(ip)}:${esc(port)}`);
});

document.getElementById("btn-port-scan")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const ports = toolExtra() || "21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080";
  const r = await runTool("port-scan", { ip, ports });
  showTool("port-scan", r, `scan ${ip} · open: ${(r.open || []).join(", ") || "—"}`);
  log(`port-scan ${esc(ip)}`);
});

document.getElementById("btn-http")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const port = parseInt(toolPort("80"), 10) || 80;
  const path = toolExtra() || "/";
  const https = port === 443 || port === 8443;
  const r = await runTool("http", { target: ip, port, path, https });
  showTool("http", r, `http ${ip} → ${r.status || r.error || "?"}`);
  log(`http ${esc(ip)}`);
});

document.getElementById("btn-dig")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const r = await runTool("dig", { query: ip });
  showTool("dig", r.raw || r, `dig ${ip}`);
  log(`dig ${esc(ip)}`);
});

document.getElementById("btn-whois")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const r = await runTool("whois", { query: ip });
  showTool("whois", r.output || r, `whois ${ip}`);
  log(`whois ${esc(ip)}`);
});

document.getElementById("btn-neighbors")?.addEventListener("click", async () => {
  const r = await runTool("neighbors", {});
  showTool("neighbors", r.raw || (r.entries || []).join("\n") || r, `neighbors · ${r.count || 0}`);
  log("neighbors");
});

document.getElementById("btn-routes")?.addEventListener("click", async () => {
  const r = await runTool("routes", {});
  showTool("routes", r.raw || (r.routes || []).join("\n") || r, "routes");
  log("routes");
});

document.getElementById("btn-listening")?.addEventListener("click", async () => {
  const r = await runTool("listening", {});
  showTool("listening", r.raw || (r.lines || []).join("\n") || r, `listeners · ${r.count || 0}`);
  log("listening");
});

document.getElementById("btn-subnet")?.addEventListener("click", async () => {
  const cidr = toolTarget();
  if (!cidr) return;
  const r = await runTool("subnet", { cidr });
  showTool("subnet", r, `subnet ${cidr}`);
  log(`subnet ${esc(cidr)}`);
});

document.getElementById("btn-mac")?.addEventListener("click", async () => {
  const mac = toolTarget();
  if (!mac) return;
  const r = await runTool("mac", { mac });
  showTool("mac", r, `mac ${mac} → ${r.vendor || "?"}`);
  log(`mac ${esc(mac)}`);
});

document.getElementById("btn-ssh-keyscan")?.addEventListener("click", async () => {
  const ip = toolTarget();
  const port = toolPort("22");
  if (!ip) return;
  const r = await runTool("ssh-keyscan", { ip, port });
  showTool("ssh-keyscan", r.raw || (r.keys || []).join("\n") || r, `ssh-keyscan ${ip}:${port}`);
  log(`ssh-keyscan ${esc(ip)}`);
});

document.getElementById("btn-mtu")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const size = parseInt(toolExtra() || "1400", 10) || 1400;
  const r = await runTool("mtu", { ip, size });
  showTool("mtu", r.output || r, `mtu ${ip} size=${size} → ${r.ok ? "OK" : "FAIL"}`);
  log(`mtu ${esc(ip)}`);
});

// ---------- Topology ----------
function filterTopoNodes(nodeList) {
  const role = (state.topoFilter.role || "").toLowerCase();
  const q = (state.topoFilter.q || "").toLowerCase().trim();
  const always = new Set(["internet", "gateway", "self"]);
  return (nodeList || []).filter((n) => {
    const id = String(n.id || "");
    const r = (n.role || n.group || "").toLowerCase();
    if (always.has(id) || r === "internet" || r === "gateway") return true;
    if (role) {
      if (role === "ap" && !(r === "ap" || r === "router")) return false;
      else if (role !== "ap" && r !== role && !(role === "self" && r === "self")) return false;
    }
    if (q) {
      const hay = `${id} ${n.label || ""} ${n.hostname || ""} ${n.vendor || ""}`.toLowerCase();
      if (!hay.includes(q) && !always.has(id)) return false;
    }
    return true;
  });
}

async function showTopoDetail(ip) {
  const empty = document.getElementById("topo-detail-empty");
  const body = document.getElementById("topo-detail-body");
  if (!ip || ip === "internet") {
    empty?.classList.remove("hidden");
    body?.classList.add("hidden");
    return;
  }
  // resolve gateway label id
  let target = ip;
  if (ip === "self") target = state.network?.local_ip || ip;
  if (ip === "gateway") target = state.network?.gateway || ip;

  empty?.classList.add("hidden");
  body?.classList.remove("hidden");
  document.getElementById("td-ip").textContent = target;

  let d = {};
  try {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(target)) {
      d = await api(`/api/host/${encodeURIComponent(target)}`);
    }
  } catch (_) {}

  const arp = d.arp || {};
  // try role from topology raw node
  let role = arp.role || d.nmap?.role || "unknown";
  try {
    const n = (state.topoRaw?.nodes || []).find((x) => x.id === ip || x.id === target);
    if (n?.role) role = n.role;
  } catch (_) {}
  const iconEl = document.getElementById("td-icon");
  if (iconEl) {
    const iconRole = role === "host_open_ports" ? "host" : role;
    iconEl.src = `/static/img/devices/${iconRole}.svg`;
    iconEl.onerror = () => {
      iconEl.src = "/static/img/devices/unknown.svg";
    };
  }
  document.getElementById("td-host").textContent = arp.hostname || arp.custom_label || "—";
  document.getElementById("td-mac").textContent = arp.mac || "—";
  document.getElementById("td-vendor").textContent = arp.vendor || "—";
  document.getElementById("td-role").textContent =
    (role || "—") + (arp.role_override ? " ★" : "");
  document.getElementById("td-os").textContent =
    arp.os_hint ||
    (d.nmap?.os_matches && d.nmap.os_matches[0]?.name) ||
    "—";

  state.detailHost = {
    ip: target,
    mac: arp.mac || "",
    role: role || "",
  };
  const roleSel = document.getElementById("td-role-select");
  if (roleSel) {
    const r = (role || "").toLowerCase();
    roleSel.value = [...roleSel.options].some((o) => o.value === r) ? r : "";
  }
  const labEl = document.getElementById("td-custom-label");
  if (labEl) labEl.value = arp.custom_label || "";
  const tagsEl = document.getElementById("td-tags");
  if (tagsEl) tagsEl.value = Array.isArray(arp.tags) ? arp.tags.join(", ") : arp.tags || "";
  const notesEl = document.getElementById("td-notes");
  if (notesEl) notesEl.value = arp.notes || "";
  const credEl = document.getElementById("td-default-cred");
  if (credEl) {
    const flags = arp.default_cred_flags || d.arp?.default_cred_flags || [];
    credEl.innerHTML = flags.length
      ? flags
          .map(
            (f) =>
              `<div class="risk-line"><span class="badge ${esc(f.risk)}">${esc(f.risk)}</span> ${esc(
                f.name
              )} — ${esc(f.hint || "")}</div>`
          )
          .join("")
      : "";
  }

  const ports = d.ports || [];
  document.getElementById("td-ports").innerHTML = ports.length
    ? ports
        .map(
          (p) =>
            `<span class="pill-port">${esc(p.port)}${p.service ? "/" + esc(p.service) : ""}</span>`
        )
        .join("")
    : "Aucun port listé (lance nmap pour enrichir)";

  const exps = d.exposures || [];
  document.getElementById("td-exposures").innerHTML = exps.length
    ? exps
        .map(
          (e) =>
            `<div class="risk-line"><span class="badge ${esc(e.risk || "")}">${esc(
              e.risk || "?"
            )}</span> :${esc(e.port)} ${esc(e.service || "")} — ${esc(
              (e.recommendation || "").slice(0, 80)
            )}</div>`
        )
        .join("")
    : "—";

  const cves = d.cves || [];
  document.getElementById("td-cves").innerHTML = cves.length
    ? cves
        .slice(0, 12)
        .map(
          (c) =>
            `<div class="risk-line"><b>${esc(c.id || "CVE")}</b> · ${esc(
              c.severity || ""
            )} · ${esc((c.description || "").slice(0, 90))}</div>`
        )
        .join("")
    : "—";
}

async function renderTopology() {
  const data = await api("/api/topology");
  state.topoRaw = data;
  const container = document.getElementById("network-graph");
  const emptyEl = document.getElementById("topo-empty");
  if (data.meta) {
    document.getElementById("tp-subnet").textContent = data.meta.subnet || "—";
    document.getElementById("tp-gateway").textContent = data.meta.gateway || "—";
    document.getElementById("tp-devices").textContent = data.meta.devices || 0;
    document.getElementById("tp-intermediates").textContent = data.meta.intermediates || 0;
    const boxes = data.meta.subnet_boxes || [];
    const tb = document.getElementById("tp-subnets");
    if (tb) tb.textContent = boxes.length ? boxes.slice(0, 4).join(", ") : data.meta.subnet || "—";
  }

  if (typeof vis === "undefined") {
    container.innerHTML = `<div class="empty-state">vis-network non chargé (réseau / CDN).</div>`;
    return;
  }

  const rawNodes = data.nodes || [];
  const nodeList = filterTopoNodes(rawNodes);
  const keepIds = new Set(nodeList.map((n) => n.id));
  // keep edges whose ends are both visible
  const edgeList = (data.edges || []).filter((e) => keepIds.has(e.from) && keepIds.has(e.to));

  const onlySkeleton =
    rawNodes.length <= 3 &&
    rawNodes.every((n) => ["internet", "gateway", "self"].includes(n.id) || n.role === "gateway");
  if (emptyEl) {
    emptyEl.classList.toggle("hidden", !(data.meta?.empty || onlySkeleton));
  }

  const nodes = new vis.DataSet(
    nodeList.map((n) => {
      const role = n.role || n.group || "unknown";
      const colors = colorForRole(role);
      const icon =
        n.image ||
        n.icon ||
        `/static/img/devices/${role === "host_open_ports" ? "host" : role}.svg`;
      // Size hierarchy: gateway/self larger, leaves smaller
      let size = n.size || 30;
      if (role === "gateway" || role === "router") size = Math.max(size, 40);
      else if (role === "self") size = Math.max(size, 36);
      else if (role === "ap") size = Math.max(size, 34);
      else if (role === "internet") size = Math.max(size, 28);
      // Cleaner labels (short)
      let label = n.label || String(n.id || "");
      if (label.includes("\n")) {
        /* keep multi-line server labels */
      } else if (label.length > 22) {
        label = label.slice(0, 20) + "…";
      }
      return {
        ...n,
        label,
        shape: "image",
        image: icon,
        brokenImage: "/static/img/devices/unknown.svg",
        size,
        // No rectangular border around image icons (avoids ugly squares)
        color: {
          border: "transparent",
          background: "transparent",
          highlight: { border: colors.border, background: "transparent" },
          hover: { border: colors.border, background: "transparent" },
        },
        borderWidth: 0,
        borderWidthSelected: 0,
        font: {
          color: "#e8eef9",
          face: "IBM Plex Mono, ui-monospace, monospace",
          size: role === "gateway" || role === "self" ? 12 : 11,
          multi: true,
          align: "center",
          strokeWidth: 4,
          strokeColor: "rgba(10,13,18,0.92)",
          vadjust: 4,
        },
        shadow: {
          enabled: true,
          color: colors.glow || "rgba(0,0,0,0.45)",
          size: 16,
          x: 0,
          y: 2,
        },
        margin: { top: 10, right: 10, bottom: 10, left: 10 },
      };
    })
  );
  // edges déjà stylées côté serveur ; edgeStyle en secours
  const edges = new vis.DataSet(edgeList.map((e) => edgeStyle(e)));

  const options = {
    autoResize: true,
    height: "100%",
    width: "100%",
    nodes: {
      borderWidth: 0,
      // useBorderWithImage:false → no square frame around device icons
      shapeProperties: { borderRadius: 0, useBorderWithImage: false },
      scaling: { min: 18, max: 52 },
      chosen: true,
    },
    edges: {
      selectionWidth: 2.5,
      hoverWidth: 2,
      smooth: {
        type: state.hierarchical ? "cubicBezier" : "continuous",
        forceDirection: state.hierarchical ? "vertical" : "none",
        roundness: state.hierarchical ? 0.45 : 0.28,
      },
      color: { inherit: false },
      font: { size: 9, color: "#6b7688", strokeWidth: 0 },
    },
    physics: state.hierarchical
      ? false
      : {
          enabled: true,
          stabilization: { iterations: 160, fit: true, updateInterval: 25 },
          barnesHut: {
            gravitationalConstant: -5200,
            centralGravity: 0.12,
            springLength: 140,
            springConstant: 0.035,
            damping: 0.48,
            avoidOverlap: 0.55,
          },
        },
    layout: state.hierarchical
      ? {
          hierarchical: {
            enabled: true,
            direction: "UD",
            sortMethod: "directed",
            shakeTowards: "roots",
            levelSeparation: 130,
            nodeSpacing: 170,
            treeSpacing: 200,
            blockShifting: true,
            edgeMinimization: true,
            parentCentralization: true,
          },
        }
      : { hierarchical: { enabled: false }, improvedLayout: true, randomSeed: 42 },
    interaction: {
      hover: true,
      tooltipDelay: 60,
      hideEdgesOnDrag: true,
      hideEdgesOnZoom: false,
      navigationButtons: true,
      keyboard: false,
      zoomView: true,
      dragView: true,
      multiselect: false,
    },
  };

  if (state.networkGraph) {
    try {
      state.networkGraph.destroy();
    } catch (_) {}
  }
  // clear previous empty message in container
  if (container.querySelector(".empty-state")) container.innerHTML = "";

  state.networkGraph = new vis.Network(container, { nodes, edges }, options);
  state.networkGraph.once("stabilizationIterationsDone", () => {
    try {
      state.networkGraph.setOptions({ physics: false });
      state.networkGraph.fit({ animation: { duration: 400, easingFunction: "easeInOutQuad" } });
    } catch (_) {}
  });
  // hierarchical: fit after short delay
  if (state.hierarchical) {
    setTimeout(() => {
      try {
        state.networkGraph.fit({
          animation: { duration: 350, easingFunction: "easeInOutQuad" },
          padding: 36,
        });
      } catch (_) {}
    }, 80);
  }

  state.networkGraph.on("click", (params) => {
    if (params.nodes?.length) {
      const id = params.nodes[0];
      showTopoDetail(id);
      if (id && /^\d+\.\d+\.\d+\.\d+$/.test(String(id))) {
        // optional drawer if exists
        try {
          openHostDrawer(id);
        } catch (_) {}
      }
    }
  });
}

function colorForRole(role) {
  const map = {
    internet: {
      background: "#121820",
      border: "#6b7688",
      highlight: "#1c2430",
      glow: "rgba(107,118,136,0.35)",
    },
    gateway: {
      background: "#0d3d28",
      border: "#22c55e",
      highlight: "#145c38",
      glow: "rgba(34,197,94,0.45)",
    },
    android: {
      background: "#052e16",
      border: "#3DDC84",
      highlight: "#14532d",
      glow: "rgba(61,220,132,0.5)",
    },
    apple: {
      background: "#1c1917",
      border: "#f5f5f7",
      highlight: "#292524",
      glow: "rgba(245,245,247,0.35)",
    },
    server: {
      background: "#0c4a6e",
      border: "#38bdf8",
      highlight: "#075985",
      glow: "rgba(56,189,248,0.4)",
    },
    tv: {
      background: "#2e1065",
      border: "#a78bfa",
      highlight: "#4c1d95",
      glow: "rgba(167,139,250,0.4)",
    },
    router: {
      background: "#0c2f3d",
      border: "#2fd9d0",
      highlight: "#124a5c",
      glow: "rgba(47,217,208,0.4)",
    },
    ap: {
      background: "#3d2208",
      border: "#f77f00",
      highlight: "#5a320c",
      glow: "rgba(247,127,0,0.4)",
    },
    switch: {
      background: "#0c2440",
      border: "#3b9eff",
      highlight: "#143560",
      glow: "rgba(59,158,255,0.35)",
    },
    pc: {
      background: "#1a2040",
      border: "#7b8cff",
      highlight: "#2a3070",
      glow: "rgba(123,140,255,0.35)",
    },
    apple: {
      background: "#1c1c1c",
      border: "#c0c0c0",
      highlight: "#2a2a2a",
      glow: "rgba(192,192,192,0.25)",
    },
    mobile: {
      background: "#2e1530",
      border: "#ff5ca8",
      highlight: "#4a2050",
      glow: "rgba(255,92,168,0.35)",
    },
    raspberry: {
      background: "#3a0a0a",
      border: "#ef4444",
      highlight: "#5a1212",
      glow: "rgba(239,68,68,0.35)",
    },
    vm: {
      background: "#1e0a38",
      border: "#a855f7",
      highlight: "#301050",
      glow: "rgba(168,85,247,0.35)",
    },
    iot: {
      background: "#063333",
      border: "#2fd9d0",
      highlight: "#0a4a4a",
      glow: "rgba(47,217,208,0.3)",
    },
    camera: {
      background: "#2a1010",
      border: "#f87171",
      highlight: "#401818",
      glow: "rgba(248,113,113,0.3)",
    },
    printer: {
      background: "#2a1a00",
      border: "#fbbf24",
      highlight: "#3d2800",
      glow: "rgba(251,191,36,0.3)",
    },
    self: {
      background: "#7a3a00",
      border: "#ff9f1a",
      highlight: "#9a4c00",
      glow: "rgba(255,159,26,0.45)",
    },
    host_open_ports: {
      background: "#12281c",
      border: "#34d399",
      highlight: "#1a3d2a",
      glow: "rgba(52,211,153,0.3)",
    },
    host: {
      background: "#151b25",
      border: "#64748b",
      highlight: "#1e2633",
      glow: "rgba(100,116,139,0.25)",
    },
    unknown: {
      background: "#151b25",
      border: "#64748b",
      highlight: "#1e2633",
      glow: "rgba(100,116,139,0.25)",
    },
  };
  return map[role] || map.unknown;
}

function edgeStyle(e) {
  const t = e.edge_type || "client";
  const base = { ...e };
  if (!base.color || typeof base.color === "string") {
    if (t === "uplink") {
      base.color = { color: "rgba(107,118,136,0.75)", highlight: "#a8b4c8", hover: "#a8b4c8" };
    } else if (t === "backbone") {
      base.color = { color: "rgba(47,217,208,0.85)", highlight: "#7aefe8", hover: "#7aefe8" };
    } else {
      base.color = { color: "rgba(70,82,104,0.7)", highlight: "#f77f00", hover: "#f77f00" };
    }
  }
  if (base.width == null) {
    base.width = t === "backbone" ? 2.8 : t === "uplink" ? 1.8 : 1.35;
  }
  if (base.smooth == null) {
    base.smooth = { type: "continuous", roundness: 0.3 };
  }
  return base;
}

document.getElementById("btn-refresh-topology")?.addEventListener("click", renderTopology);
document.getElementById("btn-export-topo-csv")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/topology/export.csv");
});
document.getElementById("btn-topo-fit")?.addEventListener("click", () => {
  if (state.networkGraph) {
    state.networkGraph.fit({
      animation: { duration: 350, easingFunction: "easeInOutQuad" },
      padding: 40,
    });
  }
});

document.getElementById("btn-layout-toggle")?.addEventListener("click", () => {
  state.hierarchical = !state.hierarchical;
  document.getElementById("btn-layout-toggle").textContent = state.hierarchical
    ? "Hiérarchique"
    : "Force Atlas";
  renderTopology();
});

let _topoFilterTimer = null;
document.getElementById("topo-search")?.addEventListener("input", (e) => {
  state.topoFilter.q = e.target.value || "";
  clearTimeout(_topoFilterTimer);
  _topoFilterTimer = setTimeout(() => renderTopology(), 200);
});
document.getElementById("topo-filter-role")?.addEventListener("change", (e) => {
  state.topoFilter.role = e.target.value || "";
  syncLegendActive();
  const tf = document.getElementById("tp-filter");
  if (tf) tf.textContent = state.topoFilter.role || "tous";
  renderTopology();
});

function syncLegendActive() {
  document.querySelectorAll("#topo-legend .leg-item").forEach((el) => {
    const r = el.dataset.role || "";
    el.classList.toggle("active", r === (state.topoFilter.role || ""));
  });
}

document.getElementById("topo-legend")?.addEventListener("click", (e) => {
  const item = e.target.closest(".leg-item");
  if (!item) return;
  const role = item.dataset.role || "";
  // toggle if same role
  state.topoFilter.role =
    state.topoFilter.role === role && role !== "" ? "" : role;
  const sel = document.getElementById("topo-filter-role");
  if (sel) sel.value = state.topoFilter.role;
  const tf = document.getElementById("tp-filter");
  if (tf) tf.textContent = state.topoFilter.role || "tous";
  syncLegendActive();
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

// ---------- Export SAHEL / PT + monitor ----------
document.getElementById("btn-export-sahel")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/export/sahel");
  toast("Export SAHEL SHIELD…", "ok");
});
document.getElementById("btn-export-pt")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/export/pt-scope");
  toast("Export scope PT…", "ok");
});

async function pushToSahel() {
  const urlEl = document.getElementById("sahel-url");
  const url = urlEl?.value?.trim() || "";
  try {
    const r = await api("/api/export/sahel/push", {
      method: "POST",
      body: JSON.stringify(url ? { url } : {}),
    });
    const msg = r.message || "Push SAHEL";
    toast(msg, r.ok === false ? "err" : "ok");
    log(
      `SAHEL push: ${msg}` +
        (r.data?.file ? ` → ${r.data.file}` : "") +
        (r.data?.hosts != null ? ` (${r.data.hosts} hôtes)` : "")
    );
  } catch (e) {
    toast(String(e.message || e), "err");
  }
}
document.getElementById("btn-push-sahel")?.addEventListener("click", pushToSahel);
document.getElementById("btn-push-sahel-2")?.addEventListener("click", pushToSahel);
document.getElementById("btn-save-sahel-url")?.addEventListener("click", async () => {
  const url = document.getElementById("sahel-url")?.value?.trim() || "";
  const r = await api("/api/settings", {
    method: "POST",
    body: JSON.stringify({ sahel_url: url }),
  });
  toast(r.message || "URL sauvée", "ok");
});

async function loadSahelSettings() {
  try {
    const s = await api("/api/settings");
    const el = document.getElementById("sahel-url");
    if (el && s.sahel_url) el.value = s.sahel_url;
  } catch (_) {}
}

let _monitorOn = false;
document.getElementById("btn-monitor-toggle")?.addEventListener("click", async () => {
  const btn = document.getElementById("btn-monitor-toggle");
  try {
    if (!_monitorOn) {
      const r = await api("/api/monitor/start", {
        method: "POST",
        body: JSON.stringify({ interval: 60 }),
      });
      _monitorOn = true;
      if (btn) btn.textContent = "Monitor ON";
      toast(r.message || "Monitor ON", "ok");
      log("Monitoring ARP continu démarré");
    } else {
      const r = await api("/api/monitor/stop", { method: "POST", body: "{}" });
      _monitorOn = false;
      if (btn) btn.textContent = "Monitor ARP";
      toast(r.message || "Monitor OFF", "warn");
    }
    refreshHealth();
  } catch (e) {
    toast(String(e.message || e), "err");
  }
});

// ---------- Role override ----------
document.getElementById("btn-save-override")?.addEventListener("click", async () => {
  const key = state.detailHost.mac || state.detailHost.ip;
  if (!key) {
    toast("Sélectionne un hôte", "warn");
    return;
  }
  const role = document.getElementById("td-role-select")?.value || null;
  const tagsRaw = document.getElementById("td-tags")?.value || "";
  const notes = document.getElementById("td-notes")?.value || "";
  const label = document.getElementById("td-custom-label")?.value || "";
  const tags = tagsRaw
    .split(/[,;]/)
    .map((t) => t.trim())
    .filter(Boolean);
  try {
    const r = await api("/api/host/override", {
      method: "POST",
      body: JSON.stringify({ key, role: role || undefined, tags, notes, label }),
    });
    toast(`Override ${r.role || r.label || "ok"} pour ${key}`, "ok");
    log(`Override: ${key} → role=${r.role || "—"} label=${r.label || "—"}`);
    renderTopology();
    if (state.detailHost.ip) showTopoDetail(state.detailHost.ip);
  } catch (e) {
    toast(String(e.message || e), "err");
  }
});

async function quickAction(action) {
  const ip = state.detailHost?.ip;
  if (!ip || !/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
    toast("Sélectionne un hôte IP", "warn");
    return;
  }
  if (action === "wol") {
    const mac = state.detailHost.mac;
    if (!mac) {
      toast("MAC manquante pour WOL", "warn");
      return;
    }
    const r = await api("/api/wol", { method: "POST", body: JSON.stringify({ mac }) });
    toast(r.ok ? `WOL envoyé → ${mac}` : r.error || "WOL fail", r.ok ? "ok" : "err");
    return;
  }
  toast(`${action} ${ip}…`, "ok");
  const r = await api("/api/host/quick", {
    method: "POST",
    body: JSON.stringify({ action, ip, async: true }),
  });
  if (r.job_id) {
    await pollJob(r.job_id, (result) => {
      toast(`${action} terminé`, "ok");
      log(`${action} ${ip}: ${JSON.stringify(result).slice(0, 120)}`);
    });
    return;
  }
  log(`${action} ${ip}: ${JSON.stringify(r).slice(0, 200)}`);
  toast(r.ok === false ? r.error || "fail" : `${action} OK`, r.ok === false ? "err" : "ok");
}
document.getElementById("btn-quick-ping")?.addEventListener("click", () => quickAction("ping"));
document.getElementById("btn-quick-trace")?.addEventListener("click", () => quickAction("traceroute"));
document.getElementById("btn-quick-banner")?.addEventListener("click", () => quickAction("banner"));
document.getElementById("btn-quick-nmap")?.addEventListener("click", () => quickAction("nmap-light"));
document.getElementById("btn-quick-nmap-vuln")?.addEventListener("click", () => quickAction("nmap-vuln"));
document.getElementById("btn-quick-ports")?.addEventListener("click", () => quickAction("port-scan"));
document.getElementById("btn-quick-http")?.addEventListener("click", () => quickAction("http"));
document.getElementById("btn-quick-tls")?.addEventListener("click", () => quickAction("tls"));
document.getElementById("btn-quick-ssh")?.addEventListener("click", () => quickAction("ssh-keyscan"));
document.getElementById("btn-quick-dns")?.addEventListener("click", () => quickAction("dns"));
document.getElementById("btn-quick-whois")?.addEventListener("click", () => quickAction("whois"));
document.getElementById("btn-quick-wol")?.addEventListener("click", () => quickAction("wol"));
document.getElementById("btn-quick-ai")?.addEventListener("click", async () => {
  const ip = state.detailHost?.ip;
  if (!ip) return toast("Sélectionne un hôte", "warn");
  const d = await api(`/api/ai-host/${encodeURIComponent(ip)}`);
  toast(d?.error ? d.error : `AI ${ip}: ${d?.severity}`, d?.error ? "err" : "ok");
  log(d?.narrative || JSON.stringify(d).slice(0, 200));
});
document.getElementById("btn-add-finding")?.addEventListener("click", async () => {
  const key = state.detailHost.mac || state.detailHost.ip;
  const title = document.getElementById("td-notes")?.value?.trim() || "Finding";
  if (!key) return;
  const r = await api("/api/findings", {
    method: "POST",
    body: JSON.stringify({ host_key: key, title, severity: "info" }),
  });
  toast(`Finding #${r.id} sauvé`, "ok");
});

async function runRangeMap() {
  let target =
    document.getElementById("range-target")?.value?.trim() ||
    prompt("Cible CIDR / plage (ex: 192.168.1.0/24)") ||
    "";
  if (!target) return;
  const out = document.getElementById("range-out");
  if (out) out.textContent = `Range map ${target}…`;
  toast(`Range map ${target}`, "ok");
  const res = await api("/api/range-map", {
    method: "POST",
    body: JSON.stringify({ target, enrich: true, async: true }),
  });
  if (res.job_id) {
    await pollJob(res.job_id, (result) => {
      if (out) out.textContent = JSON.stringify(result, null, 2);
      toast(`Range: ${result.alive || 0} hôtes up`, "ok");
      log(`Range map ${target}: ${result.alive} up / ${result.probed} probed`);
      if (result.hosts) {
        state.arp = { hosts: result.hosts, count: result.alive };
        updateDashboard();
      }
      showView("topology");
    });
  }
}
document.getElementById("btn-range-map")?.addEventListener("click", runRangeMap);
document.getElementById("btn-range-map-2")?.addEventListener("click", runRangeMap);

async function runDefaultCreds() {
  toast("Scan default-cred…", "ok");
  const res = await api("/api/default-creds", {
    method: "POST",
    body: JSON.stringify({ async: true }),
  });
  if (res.job_id) {
    await pollJob(res.job_id, (result) => {
      toast(`${result.flagged || 0} appareils signalés`, result.flagged ? "warn" : "ok");
      log(`Default-cred: ${result.flagged} flagged`);
      const el = document.getElementById("intel-discovery-out");
      if (el) el.textContent = JSON.stringify(result, null, 2);
      showView("intel");
    });
  }
}
document.getElementById("btn-default-creds")?.addEventListener("click", runDefaultCreds);
document.getElementById("btn-default-creds-2")?.addEventListener("click", runDefaultCreds);

document.getElementById("btn-clear-override")?.addEventListener("click", async () => {
  const key = state.detailHost.mac || state.detailHost.ip;
  if (!key) return;
  try {
    await api("/api/host/override", {
      method: "DELETE",
      body: JSON.stringify({ key }),
    });
    toast("Override supprimé", "ok");
    document.getElementById("td-role-select").value = "";
    document.getElementById("td-tags").value = "";
    document.getElementById("td-notes").value = "";
    renderTopology();
  } catch (e) {
    toast(String(e.message || e), "err");
  }
});

// ---------- Present mode + PNG export ----------
function enterPresentMode() {
  state.presentMode = true;
  document.body.classList.add("present-mode");
  showView("topology");
  let hint = document.getElementById("present-hint");
  if (!hint) {
    hint = document.createElement("div");
    hint.id = "present-hint";
    hint.className = "present-exit-hint";
    hint.innerHTML = `Mode présentation · <kbd>Esc</kbd> pour quitter · <kbd>F</kbd> fit`;
    document.body.appendChild(hint);
  }
  setTimeout(() => {
    try {
      state.networkGraph?.fit({ animation: true });
    } catch (_) {}
  }, 200);
  toast("Mode présentation", "ok");
}

function exitPresentMode() {
  state.presentMode = false;
  document.body.classList.remove("present-mode");
  document.getElementById("present-hint")?.remove();
  setTimeout(() => {
    try {
      state.networkGraph?.fit({ animation: true });
    } catch (_) {}
  }, 100);
}

document.getElementById("btn-present-mode")?.addEventListener("click", () => {
  if (state.presentMode) exitPresentMode();
  else enterPresentMode();
});

document.getElementById("btn-export-topo-png")?.addEventListener("click", () => {
  try {
    if (!state.networkGraph) {
      toast("Aucune topologie affichée", "warn");
      return;
    }
    const canvas = document.querySelector("#network-graph canvas");
    if (!canvas) {
      toast("Canvas topologie introuvable", "err");
      return;
    }
    const a = document.createElement("a");
    a.download = `harmattan-topo-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.png`;
    a.href = canvas.toDataURL("image/png");
    a.click();
    toast("PNG topologie exporté", "ok");
    log("Export topologie PNG");
  } catch (e) {
    toast("Export PNG échoué: " + (e.message || e), "err");
  }
});

// ---------- Health panel ----------
async function refreshHealth() {
  try {
    const h = await api("/api/health");
    const set = (id, text, cls) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.textContent = text;
      el.classList.remove("ok", "bad", "warn");
      if (cls) el.classList.add(cls);
    };
    set("h-version", h.version || "—");
    set("h-scapy", h.scapy ? "OK" : "OFF", h.scapy ? "ok" : "bad");
    set("h-nmap", h.nmap ? "OK" : "OFF", h.nmap ? "ok" : "bad");
    set("h-auth", h.auth_enabled ? "Token" : "Open", h.auth_enabled ? "ok" : "warn");
    const mon = h.monitor?.running ? "ON" : "OFF";
    set("h-monitor", mon, h.monitor?.running ? "ok" : "");
    set("h-known", String(h.known_hosts ?? "—"));
    set("h-overrides", String(h.overrides ?? "—"));
    set("h-jobs", String(h.jobs_running ?? 0), h.jobs_running ? "warn" : "ok");
    if (h.monitor?.running) _monitorOn = true;
  } catch (_) {}
}
document.getElementById("btn-refresh-health")?.addEventListener("click", refreshHealth);

// ---------- Cleanup: hosts / ignores / scans / session ----------
async function removeHostFromSession(ip, mac, ignore) {
  const body = {
    ip: ip || "",
    mac: mac || "",
    forget_known: true,
    ignore: !!ignore,
    reason: ignore ? "ui" : "",
  };
  const r = await api("/api/session/host", { method: "DELETE", body: JSON.stringify(body) });
  if (r.ok === false && r.error) {
    toast(r.message || r.error, "err");
    return;
  }
  // Update local ARP state
  if (state.arp?.hosts) {
    state.arp = {
      ...state.arp,
      hosts: state.arp.hosts.filter(
        (h) => h.ip !== ip && (!mac || (h.mac || "").toUpperCase() !== mac.toUpperCase())
      ),
    };
    state.arp.count = state.arp.hosts.length;
    renderArpResults(state.arp);
    populateTargetDropdown(state.arp.hosts);
  }
  updateDashboard();
  toast(ignore ? `${ip || mac} ignoré` : `${ip || mac} supprimé`, "ok");
  refreshKnownHosts();
  refreshIgnoredHosts();
}

async function refreshKnownHosts() {
  const tb = document.getElementById("known-hosts-tbody");
  if (!tb) return;
  try {
    const d = await api("/api/known-hosts");
    const hosts = d.hosts || [];
    if (!hosts.length) {
      tb.innerHTML = `<tr><td colspan="5" class="muted">Aucun hôte connu.</td></tr>`;
      return;
    }
    tb.innerHTML = hosts
      .map(
        (h) => `<tr>
        <td class="mono">${esc(h.ip || "—")}</td>
        <td class="mono">${esc(h.mac || "—")}</td>
        <td>${esc(h.vendor || h.hostname || "—")}</td>
        <td class="muted small">${esc(h.last_seen || "")}</td>
        <td>
          <button class="mini secondary" data-del-known="${esc(h.mac)}" type="button">✕</button>
          <button class="mini secondary" data-ignore-known="${esc(h.mac)}" data-ip="${esc(h.ip || "")}" type="button" title="Ignorer">⊘</button>
        </td>
      </tr>`
      )
      .join("");
  } catch (e) {
    tb.innerHTML = `<tr><td colspan="5" class="muted">${esc(String(e.message || e))}</td></tr>`;
  }
}

async function refreshIgnoredHosts() {
  const el = document.getElementById("ignored-hosts-list");
  if (!el) return;
  try {
    const d = await api("/api/ignored-hosts");
    const list = d.ignored || [];
    if (!list.length) {
      el.innerHTML = `<span class="muted">Aucun.</span>`;
      return;
    }
    el.innerHTML = list
      .map(
        (o) => `<div class="ov-row">
        <span class="ov-key mono">${esc(o.key)}</span>
        <span class="muted small">${esc(o.reason || "")}</span>
        <button class="mini secondary" data-unignore="${esc(o.key)}" type="button">✕</button>
      </div>`
      )
      .join("");
  } catch (_) {
    el.innerHTML = `<span class="muted">Erreur.</span>`;
  }
}

async function refreshFindingsCleanup() {
  const el = document.getElementById("findings-cleanup-list");
  if (!el) return;
  try {
    const d = await api("/api/findings?limit=40");
    const list = d.findings || [];
    if (!list.length) {
      el.innerHTML = `<span class="muted">Aucun finding.</span>`;
      return;
    }
    el.innerHTML = list
      .map(
        (f) => `<div class="ov-row">
        <span class="badge">${esc(f.severity || "info")}</span>
        <span class="ov-key">${esc(f.host_key || "")}</span>
        <span>${esc(f.title || "")}</span>
        <button class="mini secondary" data-del-finding="${f.id}" type="button">✕</button>
      </div>`
      )
      .join("");
  } catch (_) {
    el.innerHTML = `<span class="muted">Erreur.</span>`;
  }
}

// ---------- Scan history ----------
async function refreshScans() {
  const kind = document.getElementById("hist-kind-filter")?.value || "";
  const q = kind ? `?kind=${encodeURIComponent(kind)}` : "";
  try {
    const d = await api("/api/scans" + q);
    const tb = document.getElementById("scans-tbody");
    if (!tb) return;
    const scans = d.scans || [];
    if (!scans.length) {
      tb.innerHTML = `<tr><td colspan="5" class="muted">Aucun scan enregistré.</td></tr>`;
      return;
    }
    tb.innerHTML = scans
      .map(
        (s) => `<tr>
        <td class="mono">${s.id}</td>
        <td><span class="badge">${esc(s.kind)}</span></td>
        <td>${esc(s.created || "")}</td>
        <td>${s.size != null ? Math.round(s.size / 1024) + " Ko" : "—"}</td>
        <td>
          <button class="mini" data-load-scan="${s.id}" type="button">Charger</button>
          <button class="mini secondary" data-del-scan="${s.id}" type="button">✕</button>
        </td>
      </tr>`
      )
      .join("");
  } catch (e) {
    toast(String(e.message || e), "err");
  }
}

document.getElementById("btn-refresh-scans")?.addEventListener("click", () => {
  refreshScans();
  refreshKnownHosts();
  refreshIgnoredHosts();
  refreshFindingsCleanup();
  refreshOverrides();
  refreshHistoryFull();
});
document.getElementById("hist-kind-filter")?.addEventListener("change", refreshScans);

document.getElementById("scans-tbody")?.addEventListener("click", async (e) => {
  const del = e.target.closest("[data-del-scan]");
  if (del) {
    if (!confirm(`Supprimer le scan #${del.dataset.delScan} ?`)) return;
    await api(`/api/scans/${del.dataset.delScan}`, { method: "DELETE" });
    toast("Scan supprimé", "ok");
    refreshScans();
    return;
  }
  const btn = e.target.closest("[data-load-scan]");
  if (!btn) return;
  const id = btn.dataset.loadScan;
  try {
    const r = await api(`/api/scans/${id}/load`, { method: "POST", body: "{}" });
    toast(r.message || `Scan ${id} chargé`, "ok");
    log(r.message || `Scan ${id} chargé`);
    if (r.data?.kind === "arp" || r.kind === "arp") {
      try {
        const sess = await api("/api/session/export");
        if (sess.last_arp) {
          state.arp = sess.last_arp;
          renderArpResults(sess.last_arp);
          populateTargetDropdown(sess.last_arp.hosts || []);
        }
      } catch (_) {}
      updateDashboard();
    }
    showView("topology");
  } catch (err) {
    toast(String(err.message || err), "err");
  }
});

document.getElementById("btn-clear-scans")?.addEventListener("click", async () => {
  const kind = document.getElementById("hist-kind-filter")?.value || "";
  if (!confirm(kind ? `Vider tous les scans « ${kind} » ?` : "Vider TOUS les scans enregistrés ?")) return;
  await api("/api/scans/clear", { method: "POST", body: JSON.stringify({ kind: kind || null }) });
  toast("Scans vidés", "ok");
  refreshScans();
});

document.getElementById("btn-clear-session")?.addEventListener("click", async () => {
  if (!confirm("Vider la session runtime (ARP / nmap / attack en mémoire) ?")) return;
  await api("/api/session/clear", { method: "POST", body: "{}" });
  state.arp = null;
  state.nmap = null;
  state.attack = null;
  state.vuln = null;
  const arpEl = document.getElementById("arp-results");
  if (arpEl) arpEl.innerHTML = `<div class="empty-state"><div class="icon">◌</div>Session vidée.</div>`;
  updateDashboard();
  toast("Session vidée", "ok");
});

document.getElementById("btn-clear-known")?.addEventListener("click", async () => {
  if (!confirm("Supprimer TOUS les hôtes connus de la base ?")) return;
  await api("/api/known-hosts/clear", { method: "POST", body: "{}" });
  toast("Hôtes connus vidés", "ok");
  refreshKnownHosts();
});

document.getElementById("known-hosts-tbody")?.addEventListener("click", async (e) => {
  const del = e.target.closest("[data-del-known]");
  if (del) {
    await api(`/api/known-hosts/${encodeURIComponent(del.dataset.delKnown)}`, { method: "DELETE" });
    toast("Hôte connu supprimé", "ok");
    refreshKnownHosts();
    return;
  }
  const ign = e.target.closest("[data-ignore-known]");
  if (ign) {
    await api("/api/ignored-hosts", {
      method: "POST",
      body: JSON.stringify({ mac: ign.dataset.ignoreKnown, ip: ign.dataset.ip || "", reason: "from-known" }),
    });
    toast("Hôte ignoré", "ok");
    refreshKnownHosts();
    refreshIgnoredHosts();
  }
});

document.getElementById("btn-add-ignore")?.addEventListener("click", async () => {
  const key = document.getElementById("ignore-key-input")?.value?.trim();
  if (!key) return toast("MAC ou IP requis", "err");
  await api("/api/ignored-hosts", { method: "POST", body: JSON.stringify({ key, reason: "manual" }) });
  document.getElementById("ignore-key-input").value = "";
  toast(`${key} ignoré`, "ok");
  refreshIgnoredHosts();
  if (state.arp) {
    state.arp.hosts = (state.arp.hosts || []).filter(
      (h) => h.ip !== key && (h.mac || "").toUpperCase() !== key.toUpperCase()
    );
    state.arp.count = state.arp.hosts.length;
    renderArpResults(state.arp);
  }
});

document.getElementById("ignored-hosts-list")?.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-unignore]");
  if (!btn) return;
  await api(`/api/ignored-hosts/${encodeURIComponent(btn.dataset.unignore)}`, { method: "DELETE" });
  toast("Retiré des ignorés", "ok");
  refreshIgnoredHosts();
});

document.getElementById("btn-clear-ignored")?.addEventListener("click", async () => {
  if (!confirm("Vider toute la blacklist ?")) return;
  await api("/api/ignored-hosts/clear", { method: "POST", body: "{}" });
  toast("Ignorés vidés", "ok");
  refreshIgnoredHosts();
});

document.getElementById("btn-clear-history")?.addEventListener("click", async () => {
  if (!confirm("Vider le journal ?")) return;
  await api("/api/history/clear", { method: "POST", body: "{}" });
  toast("Journal vidé", "ok");
  refreshHistoryFull();
  refreshHistory();
});

document.getElementById("btn-clear-findings")?.addEventListener("click", async () => {
  if (!confirm("Supprimer tous les findings ?")) return;
  await api("/api/findings/clear", { method: "POST", body: "{}" });
  toast("Findings vidés", "ok");
  refreshFindingsCleanup();
});

document.getElementById("findings-cleanup-list")?.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-del-finding]");
  if (!btn) return;
  await api(`/api/findings/${btn.dataset.delFinding}`, { method: "DELETE" });
  toast("Finding supprimé", "ok");
  refreshFindingsCleanup();
});

async function refreshOverrides() {
  try {
    const d = await api("/api/overrides");
    const el = document.getElementById("overrides-list");
    if (!el) return;
    const list = d.overrides || [];
    if (!list.length) {
      el.innerHTML = `<span class="muted">Aucun override.</span>`;
      return;
    }
    el.innerHTML = list
      .map(
        (o) => `<div class="ov-row">
        <span class="ov-key">${esc(o.key)}</span>
        <span>${roleBadge(o.role)}</span>
        <button class="mini secondary" data-del-ov="${esc(o.key)}" type="button">✕</button>
      </div>`
      )
      .join("");
  } catch (_) {}
}

document.getElementById("overrides-list")?.addEventListener("click", async (e) => {
  const btn = e.target.closest("[data-del-ov]");
  if (!btn) return;
  await api("/api/host/override", {
    method: "DELETE",
    body: JSON.stringify({ key: btn.dataset.delOv }),
  });
  toast("Override supprimé", "ok");
  refreshOverrides();
});

async function refreshHistoryFull() {
  const d = await api("/api/history");
  const el = document.getElementById("history-list-full");
  if (!el) return;
  if (!d.history?.length) {
    el.innerHTML = `<div class="empty-state" style="padding:24px;"><div class="icon">◌</div>Aucune action.</div>`;
    return;
  }
  el.className = "";
  el.innerHTML = d.history
    .map(
      (h) =>
        `<div class="hist-line"><span class="t">${esc(h.time || "")}</span><span class="k">${esc(
          h.kind || ""
        )}</span><span>${esc(h.summary || "")}</span></div>`
    )
    .join("");
}

// ---------- Keyboard shortcuts ----------
document.addEventListener("keydown", (e) => {
  if (e.target.matches("input, textarea, select")) return;
  if (e.key === "Escape") {
    if (state.presentMode) {
      exitPresentMode();
      return;
    }
    closeDrawer();
  }
  if (e.key === "s") document.getElementById("btn-home-scan")?.click();
  if (e.key === "f" && state.presentMode) {
    try {
      state.networkGraph?.fit({ animation: true });
    } catch (_) {}
  }
  if (e.key === "1") showView("dashboard");
  if (e.key === "2") showView("discovery");
  if (e.key === "3") showView("scan");
  if (e.key === "4") showView("topology");
  if (e.key === "8") showView("intel");
  if (e.key === "9") showView("history");
  if (e.key === "p" && !e.ctrlKey && !e.metaKey) {
    if (document.getElementById("view-topology")?.classList.contains("active")) {
      if (state.presentMode) exitPresentMode();
      else enterPresentMode();
    }
  }
});

// ---------- Intel pack (SNMP / NetBIOS / LLDP / Wi‑Fi / MITRE / ML / Suricata) ----------
function pretty(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch (_) {
    return String(obj);
  }
}

async function runIntelJob(path, body, label) {
  const out = document.getElementById("intel-discovery-out");
  if (out) out.textContent = `${label}…`;
  log(label + "…");
  const res = await api(path, { method: "POST", body: JSON.stringify(body || {}) });
  if (res.job_id) {
    await pollJob(res.job_id, (result) => {
      if (out) out.textContent = pretty(result);
      log(`✓ ${label} terminé`);
      toast(label + " OK", "ok");
    });
    return;
  }
  if (out) out.textContent = pretty(res);
  if (res.error) toast(res.message || res.error, "err");
  else toast(label + " OK", "ok");
}

document.getElementById("btn-snmp-batch")?.addEventListener("click", () =>
  runIntelJob("/api/snmp/probe", { async: true }, "SNMP batch")
);
document.getElementById("btn-snmp-one")?.addEventListener("click", async () => {
  const ip = document.getElementById("snmp-target")?.value?.trim();
  if (!ip) {
    toast("IP SNMP requise", "warn");
    return;
  }
  runIntelJob("/api/snmp/probe", { target: ip }, "SNMP " + ip);
});
document.getElementById("btn-netbios-batch")?.addEventListener("click", () =>
  runIntelJob("/api/netbios/probe", { async: true }, "NetBIOS")
);
document.getElementById("btn-lldp")?.addEventListener("click", () =>
  runIntelJob("/api/lldp-cdp", { async: true, timeout: 8 }, "LLDP/CDP")
);
document.getElementById("btn-wifi-scan")?.addEventListener("click", () =>
  runIntelJob("/api/wifi/scan", { async: true }, "Scan Wi‑Fi")
);

function renderAnomalies(scores) {
  const el = document.getElementById("intel-anomalies");
  if (!el) return;
  const list = scores?.anomalies || scores?.hosts?.filter((h) => h.label === "anomaly") || [];
  if (!list.length) {
    el.innerHTML = `<span class="muted">Aucune anomalie (ou scan ARP manquant).</span>`;
    return;
  }
  el.innerHTML = list
    .slice(0, 20)
    .map(
      (h) => `<div class="hist-line">
      <span class="t">${esc(String(h.anomaly_score))}</span>
      <span class="k">${esc(h.label)}</span>
      <span><b>${esc(h.ip)}</b> ${roleBadge(h.role)} ${esc((h.reasons || []).join("; "))}</span>
    </div>`
    )
    .join("");
}

function renderMitre(mitre) {
  const el = document.getElementById("intel-mitre-list");
  if (!el) return;
  const techs = mitre?.techniques || [];
  if (!techs.length) {
    el.innerHTML = `<span class="muted">Aucune technique mappée — lance ARP + nmap.</span>`;
    return;
  }
  el.innerHTML = techs
    .slice(0, 25)
    .map(
      (t) => `<div class="hist-line">
      <span class="t">${esc(t.technique_id)}</span>
      <span class="k">${esc(t.tactic || "")}</span>
      <span>${esc(t.technique)} · <b>${t.host_count || 0}</b> hôte(s)</span>
    </div>`
    )
    .join("");
}

function renderSuricata(suri) {
  const el = document.getElementById("intel-suricata");
  if (!el) return;
  if (!suri?.available) {
    el.innerHTML = `<span class="muted">${esc(suri?.message || "Suricata non détecté")}. Option: SURICATA_EVE=/chemin/eve.json</span>`;
    return;
  }
  const alerts = suri.alerts || [];
  el.innerHTML =
    `<div class="muted small" style="margin-bottom:8px;">${esc(suri.path)} · ${alerts.length} événements</div>` +
    (alerts.length
      ? alerts
          .slice(-20)
          .map(
            (a) => `<div class="hist-line">
        <span class="t">${esc((a.timestamp || "").slice(11, 19))}</span>
        <span class="k">${esc(a.severity || a.event_type || "")}</span>
        <span>${esc(a.src_ip || "")}→${esc(a.dest_ip || "")} ${esc(a.signature || "")}</span>
      </div>`
          )
          .join("")
      : `<span class="muted">Fichier trouvé, aucune alerte récente.</span>`);
}

async function refreshIntel() {
  try {
    const d = await api("/api/intel/summary");
    document.getElementById("intel-hosts").textContent = d.hosts ?? 0;
    document.getElementById("intel-anom").textContent = d.scores?.anomaly_count ?? 0;
    document.getElementById("intel-mitre").textContent = d.mitre?.technique_count ?? 0;
    document.getElementById("intel-method").textContent = d.scores?.method || "—";
    const suri = d.suricata || {};
    document.getElementById("intel-suri").textContent = suri.available
      ? String(suri.count ?? 0)
      : "OFF";
    renderAnomalies(d.scores);
    renderMitre(d.mitre);
    renderSuricata(suri);
    const urlEl = document.getElementById("bridge-sahel-url");
    const sahel = document.getElementById("sahel-url");
    if (urlEl && sahel?.value) urlEl.value = sahel.value;
  } catch (e) {
    toast(String(e.message || e), "err");
  }
}

document.getElementById("btn-intel-refresh")?.addEventListener("click", refreshIntel);
document.getElementById("btn-score-hosts")?.addEventListener("click", async () => {
  const d = await api("/api/score/hosts", { method: "POST", body: "{}" });
  renderAnomalies(d);
  document.getElementById("intel-anom").textContent = d.anomaly_count ?? 0;
  document.getElementById("intel-method").textContent = d.method || "—";
  toast(`${d.anomaly_count || 0} anomalies (${d.method})`, "ok");
  log(`Score ML: ${d.anomaly_count} anomalies via ${d.method}`);
});
document.getElementById("btn-mitre-map")?.addEventListener("click", async () => {
  const d = await api("/api/mitre");
  renderMitre(d);
  document.getElementById("intel-mitre").textContent = d.technique_count ?? 0;
  toast(`${d.technique_count || 0} techniques MITRE`, "ok");
});

document.getElementById("btn-export-stix")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/export/stix");
  toast("Export STIX 2.1…", "ok");
});
document.getElementById("btn-export-stix-2")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/export/stix");
  toast("Export STIX 2.1…", "ok");
});
document.getElementById("btn-export-graphml")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/export/graphml");
  toast("Export GraphML…", "ok");
});
document.getElementById("btn-export-gexf")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/export/gexf");
  toast("Export GEXF…", "ok");
});

async function refreshBridgeStatus() {
  try {
    const s = await api("/api/sahel/bridge/status");
    const el = document.getElementById("bridge-status");
    if (!el) return;
    el.textContent = s.running
      ? `ON · ${s.pushes || 0} push · ${s.last_ok ? "OK" : s.last_error || "…"}`
      : "OFF";
    if (s.url) {
      const u = document.getElementById("bridge-sahel-url");
      if (u && !u.value) u.value = s.url;
    }
  } catch (_) {}
}

document.getElementById("btn-bridge-start")?.addEventListener("click", async () => {
  const url = document.getElementById("bridge-sahel-url")?.value?.trim() || "";
  const interval = parseInt(document.getElementById("bridge-interval")?.value || "120", 10);
  const r = await api("/api/sahel/bridge/start", {
    method: "POST",
    body: JSON.stringify({ url, interval }),
  });
  toast(r.message || "Bridge", r.ok === false ? "err" : "ok");
  refreshBridgeStatus();
});
document.getElementById("btn-bridge-stop")?.addEventListener("click", async () => {
  const r = await api("/api/sahel/bridge/stop", { method: "POST", body: "{}" });
  toast(r.message || "Stop", "warn");
  refreshBridgeStatus();
});

// ---------- Init ----------
systemCheck();
loadNetworkInfo();
refreshHealth();
syncLegendActive();
log(`HARMATTAN v${window.HARMATTAN_VERSION || "3.3"} initialisé — prêt pour l’audit.`);
toast("HARMATTAN prêt", "ok");

/* hmx-boot-hint */
(function bootExplainHint() {
  try {
    if (sessionStorage.getItem("hmx_hint_shown")) return;
    sessionStorage.setItem("hmx_hint_shown", "1");
    setTimeout(() => {
      if (typeof toast === "function")
        toast("Astuce: clique un résultat (port/hôte/CVE) · touche ? pour l'aide", "ok");
    }, 1200);
  } catch (_) {}
})();


// ---------- AI Analyst Network v3 ----------
function renderAiAnalysis(data) {
  if (!data || data.error) {
    toast((data && (data.message || data.error)) || "Erreur AI", "err");
    return;
  }
  const sev = data.severity || "info";
  const grade = data.grade || "—";
  const score = data.risk_score ?? "—";
  document.getElementById("ai-summary").textContent = data.summary || "—";
  document.getElementById("ai-meta").innerHTML =
    `<span class="badge">sévérité <b>${esc(sev)}</b></span> ` +
    `<span class="badge">grade <b>${esc(grade)}</b></span> ` +
    `<span class="badge">score <b>${esc(score)}</b>/100</span> ` +
    `<span class="badge">${esc(data.engine || "ai")}</span> ` +
    `<span class="badge">${esc(data.total_hosts ?? 0)} hôtes</span>`;

  const pri = data.priority_actions || [];
  document.getElementById("ai-priorities").innerHTML = pri.length
    ? pri.map((p) => `<li>${esc(p)}</li>`).join("")
    : "<li class='muted'>Aucune priorité</li>";

  const qw = data.quick_wins || [];
  const qwEl = document.getElementById("ai-quickwins");
  if (qwEl) {
    qwEl.innerHTML = qw.length
      ? qw.map((p) => `<li>${esc(p)}</li>`).join("")
      : "<li class='muted'>—</li>";
  }

  document.getElementById("ai-advice").textContent = data.advice || "";

  const mitre = data.mitre || [];
  document.getElementById("ai-mitre").innerHTML = mitre.length
    ? mitre.map((m) => `<span class="badge role-gateway" style="margin:2px;">${esc(m)}</span>`).join(" ")
    : "—";

  const posture = data.posture || {};
  const checks = posture.checks || [];
  document.getElementById("ai-posture").innerHTML = checks.length
    ? `<div>Score posture: <b>${esc(posture.score ?? "—")}%</b></div>` +
      checks
        .map(
          (c) =>
            `<div>${c.ok ? "✓" : "✗"} ${esc(c.label || c.id)}</div>`
        )
        .join("")
    : "";

  const hot = data.hot_hosts || [];
  document.getElementById("ai-hot-hosts").innerHTML = hot.length
    ? `<table class="mini-table"><thead><tr><th>IP</th><th>Host</th><th>Risque</th><th>Ports</th><th></th></tr></thead><tbody>` +
      hot
        .map((h) => {
          const ports = (h.top_ports || []).join(", ") || "—";
          return `<tr>
            <td>${esc(h.ip)}</td>
            <td>${esc(h.hostname || h.vendor || "—")}</td>
            <td>${esc(h.max_risk || "—")}</td>
            <td>${esc(ports)}</td>
            <td><button type="button" class="mini secondary btn-ai-host" data-ip="${esc(h.ip)}">AI hôte</button>
            <a class="mini" href="/api/remediation/script/${encodeURIComponent(h.ip)}" target="_blank">Fix</a></td>
          </tr>`;
        })
        .join("") +
      `</tbody></table>`
    : "<span class='muted'>Aucun hôte prioritaire</span>";

  const insc = data.insecure_services || [];
  document.getElementById("ai-insecure").innerHTML = insc.length
    ? `<table class="mini-table"><thead><tr><th>IP</th><th>Port</th><th>Service</th><th>Risque</th><th>Reco</th></tr></thead><tbody>` +
      insc
        .slice(0, 20)
        .map(
          (i) => `<tr>
          <td>${esc(i.ip)}</td><td>${esc(i.port)}</td><td>${esc(i.service)}</td>
          <td>${esc(i.risk)}</td><td class="muted">${esc(i.recommendation || "")}</td></tr>`
        )
        .join("") +
      `</tbody></table>`
    : "<span class='muted'>Aucun service critique/haute listé</span>";

  // Remediation shortcuts
  const crit = hot.filter((h) => h.max_risk === "critique" || h.max_risk === "haute");
  if (crit.length) {
    document.getElementById("ai-remediation-links").innerHTML =
      "<strong>Scripts de remédiation :</strong><br>" +
      crit
        .slice(0, 8)
        .map(
          (h) =>
            `<a href="/api/remediation/script/${encodeURIComponent(h.ip)}" class="badge role-gateway" style="text-decoration:none;margin:2px;" target="_blank">Fix ${esc(h.ip)}</a>`
        )
        .join("");
  } else {
    document.getElementById("ai-remediation-links").innerHTML = "";
  }

  // AI v4 extras
  const exec = document.getElementById("ai-executive");
  if (exec) exec.textContent = data.executive_brief || "";

  const pathsEl = document.getElementById("ai-paths");
  if (pathsEl) {
    const paths = data.attack_paths || [];
    pathsEl.innerHTML = paths.length
      ? paths
          .map(
            (p) =>
              `<div style="margin-bottom:8px;padding:8px;border:1px solid var(--border);border-radius:8px;">
                <b style="color:var(--orange)">${esc(p.id || "")} ${esc(p.name || "")}</b>
                <span class="badge ${esc(p.severity || "info")}">${esc(p.severity || "")}</span>
                <div class="muted small">${esc((p.steps || []).join(" → "))}</div>
                <div class="muted small">MITRE: ${esc((p.mitre || []).join(", ") || "—")}</div>
              </div>`
          )
          .join("")
      : "—";
  }

  const blastEl = document.getElementById("ai-blast");
  if (blastEl && data.blast_radius) {
    const b = data.blast_radius;
    blastEl.innerHTML = `<strong>Blast radius:</strong> impact ${esc(b.estimated_impact)} ·
      hôtes HR ${esc(b.hosts_high_risk)} · admin ${esc(b.admin_exposures)} · data ${esc(b.data_exposures)}`;
  }

  const segEl = document.getElementById("ai-segmentation");
  if (segEl) {
    const segs = data.segmentation || [];
    segEl.innerHTML = segs.length
      ? "<strong>Segmentation:</strong><ul class='rec-list'>" +
        segs.map((s) => `<li>${esc(s)}</li>`).join("") +
        "</ul>"
      : "";
  }

  const slaEl = document.getElementById("ai-sla");
  if (slaEl) {
    const sla = data.remediation_sla || [];
    slaEl.innerHTML = sla.length
      ? "<strong>SLA remédiation:</strong><br>" +
        sla
          .map(
            (s) =>
              `<span class="badge ${esc(s.severity)}">${esc(s.severity)}</span> ${esc(s.deadline)} — ${esc(s.action)}<br>`
          )
          .join("")
      : "";
  }

  const narEl = document.getElementById("ai-narratives");
  if (narEl) {
    const nars = data.host_narratives || [];
    narEl.innerHTML = nars.length
      ? nars.map((n) => `<div style="margin-bottom:6px;">• ${esc(n.text || "")}</div>`).join("")
      : "—";
  }

  // bind host AI buttons
  document.querySelectorAll(".btn-ai-host").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const ip = btn.getAttribute("data-ip");
      const d = await api(`/api/ai-host/${encodeURIComponent(ip)}`);
      if (d && !d.error) {
        toast(`AI hôte ${ip}: ${d.severity || "—"}`, "ok");
        log(`AI host ${ip}: ${(d.findings || []).slice(0, 3).join(" · ")}`);
        if (d.narrative) log(d.narrative);
      } else {
        toast((d && (d.message || d.error)) || "Erreur AI hôte", "err");
      }
    });
  });
}

async function runNetworkAiAnalyze() {
  const panel = document.getElementById("ai-analysis-panel");
  if (!panel) return;
  panel.classList.remove("hidden");
  document.getElementById("ai-summary").textContent = "Analyse cognitive v4 en cours…";
  document.getElementById("ai-priorities").innerHTML = "";
  document.getElementById("ai-advice").textContent = "";
  document.getElementById("ai-remediation-links").innerHTML = "";
  const meta = document.getElementById("ai-meta");
  if (meta) meta.textContent = "";
  const exec = document.getElementById("ai-executive");
  if (exec) exec.textContent = "";
  log("Lancement AI Analyst Network v4…");
  const data = await api("/api/ai-analyze");
  if (data && (data.error || data.ok === false)) {
    toast(data.message || data.error || "Erreur AI", "err");
    document.getElementById("ai-summary").textContent =
      data.message || data.error || "Échec analyse — lancez ARP/nmap d'abord.";
    return;
  }
  renderAiAnalysis(data);
  // enrich meta line
  if (meta) {
    const conf = data.confidence || {};
    meta.textContent = `engine ${data.engine || "v4"} · confiance ${conf.score ?? "—"}% (${conf.level || "—"}) · grade ${data.grade || "—"} · score ${data.risk_score ?? "—"}`;
  }
  log(`AI Network v4 — ${data.severity || "?"} grade ${data.grade || "—"}`);
  panel.scrollIntoView({ behavior: "smooth" });
}

document.getElementById("btn-ai-analyze")?.addEventListener("click", runNetworkAiAnalyze);
document.getElementById("btn-ai-refresh")?.addEventListener("click", runNetworkAiAnalyze);
document.getElementById("btn-ai-close")?.addEventListener("click", () => {
  document.getElementById("ai-analysis-panel")?.classList.add("hidden");
});

// ---------- Dark Mode (New) ----------
function toggleDarkMode() {
  const isDark = document.body.classList.toggle("dark-mode");
  localStorage.setItem("harmattan_dark_mode", isDark ? "1" : "0");
  document.getElementById("btn-toggle-dark").textContent = isDark ? "☀️ Light" : "🌓 Dark";
}

document.getElementById("btn-toggle-dark")?.addEventListener("click", toggleDarkMode);

if (localStorage.getItem("harmattan_dark_mode") === "1") {
  document.body.classList.add("dark-mode");
  const btn = document.getElementById("btn-toggle-dark");
  if (btn) btn.textContent = "☀️ Light";
}
