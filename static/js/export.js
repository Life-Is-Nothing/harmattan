/**
 * HARMATTAN v3.22 — Module: export
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

// HARMATTAN v3 — Professional frontend controller
const state = {
  arp: null,
  nmap: null,
  vuln: null,
  attack: null,
  network: null,
  trafficTimer: null,
  liveTimer: null,
  liveOn: false,
  hierarchical: true,
  networkGraph: null,
  topoRaw: null,
  topoFilter: { role: "", q: "" },
  currentJob: null,
  jobPoll: null,
  arpFilter: "",
  attackFilter: "",
  presentMode: false,
  detailHost: { ip: "", mac: "", role: "" },
};

const TOKEN = window.HARMATTAN_TOKEN || "";

document.getElementById("btn-export-report").addEventListener("click", () => {
  window.location = tokenUrl("/api/report.html");
  log("📄 Export rapport HTML pro");
  toast("Rapport HTML généré", "ok");
});
document.getElementById("btn-export-pdf")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/report.pdf");
  log("📄 Export rapport PDF pro");
  toast("Rapport PDF généré", "ok");
});
document.getElementById("btn-export-docx")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/report.docx");
  log("📄 Export rapport Word DOCX");
  toast("Rapport Word généré", "ok");
});
document.getElementById("btn-export-json")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/report.json");
  log("📄 Export rapport JSON");
});
document.getElementById("btn-export-session")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/session/export");
  log("💾 Export session");
});

// Diff ARP + mDNS + PCAP (v3.5)
