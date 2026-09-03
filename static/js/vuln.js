/**
 * HARMATTAN v3.22 — Module: vuln
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

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

window.renderVulnResults = function renderVulnResults(report) {
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

