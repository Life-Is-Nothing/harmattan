/**
 * HARMATTAN v3.22 — Module: ui
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

// ---------- Helpers ----------
window.esc = function esc(s) {
  return String(s ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

window.toast = function toast(msg, type = "ok") {
  const root = document.getElementById("toast-root");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.textContent = msg;
  root.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

window.log = function log(msg) {
  const box = document.getElementById("activity-log");
  if (!box || box.style.display === "none" || box.getAttribute("aria-hidden") === "true") {
    if (typeof console !== "undefined" && console.debug) console.debug("[HARMATTAN]", msg);
    return;
  }
  const line = document.createElement("div");
  line.className = "log-line";
  const time = new Date().toLocaleTimeString();
  line.innerHTML = `<span class="t">[${esc(time)}]</span>${msg}`;
  box.prepend(line);
  while (box.children.length > 80) box.removeChild(box.lastChild);
}

window.api = function api(path, opts = {}) {
  const headers = {
    "Content-Type": "application/json",
    ...(opts.headers || {}),
  };
  if (TOKEN) headers["X-Harmattan-Token"] = TOKEN;
  const res = await fetch(path, {
    credentials: "same-origin",
    ...opts,
    headers,
  });
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("application/json")) {
    const data = await res.json();
    if (res.status === 401) {
      // Suite SSO: redirect to Identity login
      if (window.HarmattanSSO && window.HarmattanSSO.loginUrl) {
        window.location.href = window.HarmattanSSO.loginUrl();
        return data;
      }
      toast("Session requise — reconnectez-vous (Identity)", "err");
    }
    if (res.status === 404 && data && data.error === "not_found") {
      console.warn("API not found:", path);
    }
    return data;
  }
  if (res.status === 401 && window.HarmattanSSO) {
    window.location.href = window.HarmattanSSO.loginUrl();
  }
  return res;
}

window.setBadgeStatus = function setBadgeStatus(id, ok) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.toggle("ok", !!ok);
  el.classList.toggle("bad", !ok);
}

window.roleBadge = function roleBadge(role) {
  const r = role || "unknown";
  return `<span class="badge role-${esc(r)}">${esc(r)}</span>`;
}

// ---------- Navigation ----------
window.showView = function showView(name) {
  if (state.presentMode && name !== "topology") exitPresentMode();
  document.querySelectorAll(".view").forEach((v) => v.classList.remove("active"));
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.remove("active"));
  const view = document.getElementById("view-" + name);
  if (view) view.classList.add("active");
  const nav = document.querySelector(`.nav-item[data-view="${name}"]`);
  if (nav) nav.classList.add("active");
  if (name === "topology") renderTopology();
  if (name === "attack") refreshAttack();
  if (name === "dashboard") {
    refreshHistory();
    refreshHealth();
  }
  if (name === "history") {
    refreshScans();
    refreshOverrides();
    refreshHistoryFull();
    refreshKnownHosts();
    refreshIgnoredHosts();
    refreshFindingsCleanup();
    loadSahelSettings();
  }
  if (name === "intel") {
    refreshIntel();
    refreshBridgeStatus();
  }
}

document.querySelectorAll(".nav-item").forEach((item) => {
  item.addEventListener("click", () => showView(item.dataset.view));
});

// ---------- Keyboard shortcuts ----------
document.addEventListener("keydown", (e) => {
  if (e.target.matches("input, textarea, select")) return;
  if (e.key === "Escape") {
    if (state.presentMode) {
      exitPresentMode();
      return;
    }
    closeDrawer();
  }
  if (e.key === "s") document.getElementById("btn-home-scan")?.click();
  if (e.key === "f" && state.presentMode) {
    try {
      state.networkGraph?.fit({ animation: true });
    } catch (_) {}
  }
  if (e.key === "1") showView("dashboard");
  if (e.key === "2") showView("discovery");
  if (e.key === "3") showView("scan");
  if (e.key === "4") showView("topology");
  if (e.key === "8") showView("intel");
  if (e.key === "9") showView("history");
  if (e.key === "p" && !e.ctrlKey && !e.metaKey) {
    if (document.getElementById("view-topology")?.classList.contains("active")) {
      if (state.presentMode) exitPresentMode();
      else enterPresentMode();
    }
  }
});

// ---------- Dark Mode (New) ----------
function toggleDarkMode() {
  const isDark = document.body.classList.toggle("dark-mode");
  localStorage.setItem("harmattan_dark_mode", isDark ? "1" : "0");
  document.getElementById("btn-toggle-dark").textContent = isDark ? "☀️ Light" : "🌓 Dark";
}

document.getElementById("btn-toggle-dark")?.addEventListener("click", toggleDarkMode);

if (localStorage.getItem("harmattan_dark_mode") === "1") {
  document.body.classList.add("dark-mode");
  const btn = document.getElementById("btn-toggle-dark");
  if (btn) btn.textContent = "☀️ Light";
}
