/**
 * HARMATTAN v3.22 — Module: sahel
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

// ---------- Export SAHEL / PT + monitor ----------
document.getElementById("btn-export-sahel")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/export/sahel");
  toast("Export SAHEL SHIELD…", "ok");
});
document.getElementById("btn-export-pt")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/export/pt-scope");
  toast("Export scope PT…", "ok");
});

window.pushToSahel = function pushToSahel() {
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

window.loadSahelSettings = function loadSahelSettings() {
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

window.quickAction = function quickAction(action) {
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

window.runRangeMap = function runRangeMap() {
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

window.runDefaultCreds = function runDefaultCreds() {
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

