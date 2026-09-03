/**
 * HARMATTAN v3.22 — Module: attack
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

// ---------- Attack surface ----------
window.refreshAttack = function refreshAttack() {
  const result = await api("/api/attack-surface");
  state.attack = result;
  renderAttack(result);
  updateDashboard();
}

document.getElementById("btn-refresh-attack").addEventListener("click", refreshAttack);

window.renderAttack = function renderAttack(report) {
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

window.runAsAction = function runAsAction(action, ip, mac) {
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

