/**
 * HARMATTAN v3.22 — Module: dashboard
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

// ---------- Network context ----------
window.loadNetworkInfo = function loadNetworkInfo() {
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
window.systemCheck = function systemCheck() {
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

window.applyHomeResult = function applyHomeResult(result) {
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
window.renderDiffArp = function renderDiffArp(d) {
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
window.downloadBlob = function downloadBlob(url, filename) {
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

window.updateDashboard = function updateDashboard() {
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

window.renderNewDevices = function renderNewDevices(list) {
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

window.refreshHistory = function refreshHistory() {
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

