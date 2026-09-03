/**
 * HARMATTAN v3.22 — Module: cleanup
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

// ---------- Cleanup: hosts / ignores / scans / session ----------
window.removeHostFromSession = function removeHostFromSession(ip, mac, ignore) {
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

window.refreshKnownHosts = function refreshKnownHosts() {
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

window.refreshIgnoredHosts = function refreshIgnoredHosts() {
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

window.refreshFindingsCleanup = function refreshFindingsCleanup() {
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
window.refreshScans = function refreshScans() {
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

window.refreshOverrides = function refreshOverrides() {
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

window.refreshHistoryFull = function refreshHistoryFull() {
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

