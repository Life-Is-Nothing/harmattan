/**
 * HARMATTAN v3.22 — Module: tools
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

// ---------- Tools ----------
window.runTool = function runTool(name, body) {
  document.getElementById("tool-output").textContent = `${name}…`;
  const r = await api(`/api/tools/${name}`, { method: "POST", body: JSON.stringify(body) });
  return r;
}

window.toolTarget = function toolTarget() {
  return (document.getElementById("tool-target")?.value || "").trim();
}
window.toolPort = function toolPort(def = "80") {
  return (document.getElementById("tool-port")?.value || "").trim() || def;
}
window.toolExtra = function toolExtra() {
  return (document.getElementById("tool-extra")?.value || "").trim();
}
window.showTool = function showTool(name, r, summary) {
  const out = document.getElementById("tool-output");
  const meta = document.getElementById("tool-meta");
  if (meta) meta.textContent = summary || name;
  if (!out) return;
  if (typeof r === "string") out.textContent = r;
  else if (r?.output) out.textContent = r.output;
  else if (r?.raw) out.textContent = r.raw;
  else if (r?.banner) out.textContent = r.banner;
  else out.textContent = JSON.stringify(r, null, 2);
}

document.getElementById("btn-tool-clear")?.addEventListener("click", () => {
  const out = document.getElementById("tool-output");
  const meta = document.getElementById("tool-meta");
  if (out) out.textContent = "Sélectionne une action…";
  if (meta) meta.textContent = "Prêt";
});

document.getElementById("btn-ping")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const r = await runTool("ping", { ip });
  showTool("ping", r.output || r.error || r, `ping ${ip} → ${r.ok ? "OK" : "FAIL"}`);
  log(`ping ${esc(ip)} → ${r.ok ? "OK" : "FAIL"}`);
});

document.getElementById("btn-traceroute")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const r = await runTool("traceroute", { ip });
  showTool("traceroute", r.raw || (r.hops || []).join("\n") || r.message || r.error || r, `traceroute ${ip}`);
  log(`traceroute ${esc(ip)}`);
});

document.getElementById("btn-banner")?.addEventListener("click", async () => {
  const ip = toolTarget();
  const port = toolPort("80");
  if (!ip) return;
  const r = await runTool("banner", { ip, port });
  showTool("banner", r.banner || r.error || r, `banner ${ip}:${port}`);
  log(`banner ${esc(ip)}:${esc(port)}`);
});

document.getElementById("btn-dns")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const r = await runTool("dns", { query: ip });
  showTool("dns", r, `dns ${ip}`);
  log(`dns ${esc(ip)}`);
});

document.getElementById("btn-tls")?.addEventListener("click", async () => {
  const ip = toolTarget();
  const port = toolPort("443");
  if (!ip) return;
  const r = await runTool("tls", { host: ip, port });
  showTool("tls", r, `tls ${ip}:${port}`);
  log(`tls ${esc(ip)}:${esc(port)}`);
});

document.getElementById("btn-port-check")?.addEventListener("click", async () => {
  const ip = toolTarget();
  const port = toolPort("80");
  if (!ip) return;
  const r = await runTool("port-check", { ip, port });
  showTool("port-check", r, `port ${ip}:${port} → ${r.open ? "OPEN" : "CLOSED"}`);
  log(`port-check ${esc(ip)}:${esc(port)}`);
});

document.getElementById("btn-port-scan")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const ports = toolExtra() || "21,22,23,25,53,80,110,139,143,443,445,3306,3389,8080";
  const r = await runTool("port-scan", { ip, ports });
  showTool("port-scan", r, `scan ${ip} · open: ${(r.open || []).join(", ") || "—"}`);
  log(`port-scan ${esc(ip)}`);
});

document.getElementById("btn-http")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const port = parseInt(toolPort("80"), 10) || 80;
  const path = toolExtra() || "/";
  const https = port === 443 || port === 8443;
  const r = await runTool("http", { target: ip, port, path, https });
  showTool("http", r, `http ${ip} → ${r.status || r.error || "?"}`);
  log(`http ${esc(ip)}`);
});

document.getElementById("btn-dig")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const r = await runTool("dig", { query: ip });
  showTool("dig", r.raw || r, `dig ${ip}`);
  log(`dig ${esc(ip)}`);
});

document.getElementById("btn-whois")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const r = await runTool("whois", { query: ip });
  showTool("whois", r.output || r, `whois ${ip}`);
  log(`whois ${esc(ip)}`);
});

document.getElementById("btn-neighbors")?.addEventListener("click", async () => {
  const r = await runTool("neighbors", {});
  showTool("neighbors", r.raw || (r.entries || []).join("\n") || r, `neighbors · ${r.count || 0}`);
  log("neighbors");
});

document.getElementById("btn-routes")?.addEventListener("click", async () => {
  const r = await runTool("routes", {});
  showTool("routes", r.raw || (r.routes || []).join("\n") || r, "routes");
  log("routes");
});

document.getElementById("btn-listening")?.addEventListener("click", async () => {
  const r = await runTool("listening", {});
  showTool("listening", r.raw || (r.lines || []).join("\n") || r, `listeners · ${r.count || 0}`);
  log("listening");
});

document.getElementById("btn-subnet")?.addEventListener("click", async () => {
  const cidr = toolTarget();
  if (!cidr) return;
  const r = await runTool("subnet", { cidr });
  showTool("subnet", r, `subnet ${cidr}`);
  log(`subnet ${esc(cidr)}`);
});

document.getElementById("btn-mac")?.addEventListener("click", async () => {
  const mac = toolTarget();
  if (!mac) return;
  const r = await runTool("mac", { mac });
  showTool("mac", r, `mac ${mac} → ${r.vendor || "?"}`);
  log(`mac ${esc(mac)}`);
});

document.getElementById("btn-ssh-keyscan")?.addEventListener("click", async () => {
  const ip = toolTarget();
  const port = toolPort("22");
  if (!ip) return;
  const r = await runTool("ssh-keyscan", { ip, port });
  showTool("ssh-keyscan", r.raw || (r.keys || []).join("\n") || r, `ssh-keyscan ${ip}:${port}`);
  log(`ssh-keyscan ${esc(ip)}`);
});

document.getElementById("btn-mtu")?.addEventListener("click", async () => {
  const ip = toolTarget();
  if (!ip) return;
  const size = parseInt(toolExtra() || "1400", 10) || 1400;
  const r = await runTool("mtu", { ip, size });
  showTool("mtu", r.output || r, `mtu ${ip} size=${size} → ${r.ok ? "OK" : "FAIL"}`);
  log(`mtu ${esc(ip)}`);
});

