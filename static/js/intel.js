/**
 * HARMATTAN v3.22 — Module: intel
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

// ---------- Intel pack (SNMP / NetBIOS / LLDP / Wi‑Fi / MITRE / ML / Suricata) ----------
window.pretty = function pretty(obj) {
  try {
    return JSON.stringify(obj, null, 2);
  } catch (_) {
    return String(obj);
  }
}

window.runIntelJob = function runIntelJob(path, body, label) {
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

window.renderAnomalies = function renderAnomalies(scores) {
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

window.renderMitre = function renderMitre(mitre) {
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

window.renderSuricata = function renderSuricata(suri) {
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

window.refreshIntel = function refreshIntel() {
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

window.refreshBridgeStatus = function refreshBridgeStatus() {
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

