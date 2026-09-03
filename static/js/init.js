/**
 * HARMATTAN v3.22 — Module: init
 * Initializes global state and bootstraps all modules
 */
'use strict';

// Global state object
window.state = window.state || {
  arp: null, nmap: null, vuln: null, attack: null, network: null,
  trafficTimer: null, liveTimer: null, liveOn: false,
  hierarchical: true, networkGraph: null, topoRaw: null,
  topoFilter: { role: "", q: "" },
  currentJob: null, jobPoll: null,
  arpFilter: "", attackFilter: "",
  presentMode: false,
  detailHost: { ip: "", mac: "", role: "" },
};

const state = window.state;
window.HARMATTAN_TOKEN = window.HARMATTAN_TOKEN || '';
const TOKEN = window.HARMATTAN_TOKEN;

// ---------- Init ----------
systemCheck();
loadNetworkInfo();
refreshHealth();
syncLegendActive();
log(`HARMATTAN v${window.HARMATTAN_VERSION || "3.3"} initialisé — prêt pour l’audit.`);
toast("HARMATTAN prêt", "ok");

/* hmx-boot-hint */
(function bootExplainHint() {
  try {
    if (sessionStorage.getItem("hmx_hint_shown")) return;
    sessionStorage.setItem("hmx_hint_shown", "1");
    setTimeout(() => {
      if (typeof toast === "function")
        toast("Astuce: clique un résultat (port/hôte/CVE) · touche ? pour l'aide", "ok");
    }, 1200);
  } catch (_) {}
})();


