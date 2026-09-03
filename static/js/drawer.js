/**
 * HARMATTAN v3.22 — Module: drawer
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

// ---------- Host drawer ----------
window.openHostDrawer = function openHostDrawer(ip) {
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

window.closeDrawer = function closeDrawer() {
  document.getElementById("host-drawer").classList.remove("open");
  document.getElementById("drawer-backdrop").classList.add("hidden");
  document.getElementById("host-drawer").setAttribute("aria-hidden", "true");
}
document.getElementById("btn-drawer-close")?.addEventListener("click", closeDrawer);
document.getElementById("drawer-backdrop")?.addEventListener("click", closeDrawer);

