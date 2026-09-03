/**
 * HARMATTAN v3.22 — Module: ai
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

// ---------- AI Analyst Network v3 ----------
window.renderAiAnalysis = function renderAiAnalysis(data) {
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

window.runNetworkAiAnalyze = function runNetworkAiAnalyze() {
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

