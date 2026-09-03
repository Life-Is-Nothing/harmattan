/**
 * HARMATTAN v3.22 — Module: arp
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

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

window.handleArpResult = function handleArpResult(result) {
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

window.renderArpResults = function renderArpResults(result) {
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

window.populateTargetDropdown = function populateTargetDropdown(hosts) {
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

window.quickTool = function quickTool(ip, kind) {
  document.getElementById("tool-target").value = ip;
  showView("tools");
  if (kind === "ping") document.getElementById("btn-ping").click();
  else document.getElementById("btn-traceroute").click();
}

