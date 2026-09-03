/**
 * HARMATTAN v3.22 — Module: nmap
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

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

window.handleNmapResult = function handleNmapResult(result) {
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

window.renderNmapResults = function renderNmapResults(result) {
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

