/**
 * HARMATTAN v3.22 — Module: topology
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

// ---------- Topology ----------
window.filterTopoNodes = function filterTopoNodes(nodeList) {
  const role = (state.topoFilter.role || "").toLowerCase();
  const q = (state.topoFilter.q || "").toLowerCase().trim();
  const always = new Set(["internet", "gateway", "self"]);
  return (nodeList || []).filter((n) => {
    const id = String(n.id || "");
    const r = (n.role || n.group || "").toLowerCase();
    if (always.has(id) || r === "internet" || r === "gateway") return true;
    if (role) {
      if (role === "ap" && !(r === "ap" || r === "router")) return false;
      else if (role !== "ap" && r !== role && !(role === "self" && r === "self")) return false;
    }
    if (q) {
      const hay = `${id} ${n.label || ""} ${n.hostname || ""} ${n.vendor || ""}`.toLowerCase();
      if (!hay.includes(q) && !always.has(id)) return false;
    }
    return true;
  });
}

window.showTopoDetail = function showTopoDetail(ip) {
  const empty = document.getElementById("topo-detail-empty");
  const body = document.getElementById("topo-detail-body");
  if (!ip || ip === "internet") {
    empty?.classList.remove("hidden");
    body?.classList.add("hidden");
    return;
  }
  // resolve gateway label id
  let target = ip;
  if (ip === "self") target = state.network?.local_ip || ip;
  if (ip === "gateway") target = state.network?.gateway || ip;

  empty?.classList.add("hidden");
  body?.classList.remove("hidden");
  document.getElementById("td-ip").textContent = target;

  let d = {};
  try {
    if (/^\d+\.\d+\.\d+\.\d+$/.test(target)) {
      d = await api(`/api/host/${encodeURIComponent(target)}`);
    }
  } catch (_) {}

  const arp = d.arp || {};
  // try role from topology raw node
  let role = arp.role || d.nmap?.role || "unknown";
  try {
    const n = (state.topoRaw?.nodes || []).find((x) => x.id === ip || x.id === target);
    if (n?.role) role = n.role;
  } catch (_) {}
  const iconEl = document.getElementById("td-icon");
  if (iconEl) {
    const iconRole = role === "host_open_ports" ? "host" : role;
    iconEl.src = `/static/img/devices/${iconRole}.svg`;
    iconEl.onerror = () => {
      iconEl.src = "/static/img/devices/unknown.svg";
    };
  }
  document.getElementById("td-host").textContent = arp.hostname || arp.custom_label || "—";
  document.getElementById("td-mac").textContent = arp.mac || "—";
  document.getElementById("td-vendor").textContent = arp.vendor || "—";
  document.getElementById("td-role").textContent =
    (role || "—") + (arp.role_override ? " ★" : "");
  document.getElementById("td-os").textContent =
    arp.os_hint ||
    (d.nmap?.os_matches && d.nmap.os_matches[0]?.name) ||
    "—";

  state.detailHost = {
    ip: target,
    mac: arp.mac || "",
    role: role || "",
  };
  const roleSel = document.getElementById("td-role-select");
  if (roleSel) {
    const r = (role || "").toLowerCase();
    roleSel.value = [...roleSel.options].some((o) => o.value === r) ? r : "";
  }
  const labEl = document.getElementById("td-custom-label");
  if (labEl) labEl.value = arp.custom_label || "";
  const tagsEl = document.getElementById("td-tags");
  if (tagsEl) tagsEl.value = Array.isArray(arp.tags) ? arp.tags.join(", ") : arp.tags || "";
  const notesEl = document.getElementById("td-notes");
  if (notesEl) notesEl.value = arp.notes || "";
  const credEl = document.getElementById("td-default-cred");
  if (credEl) {
    const flags = arp.default_cred_flags || d.arp?.default_cred_flags || [];
    credEl.innerHTML = flags.length
      ? flags
          .map(
            (f) =>
              `<div class="risk-line"><span class="badge ${esc(f.risk)}">${esc(f.risk)}</span> ${esc(
                f.name
              )} — ${esc(f.hint || "")}</div>`
          )
          .join("")
      : "";
  }

  const ports = d.ports || [];
  document.getElementById("td-ports").innerHTML = ports.length
    ? ports
        .map(
          (p) =>
            `<span class="pill-port">${esc(p.port)}${p.service ? "/" + esc(p.service) : ""}</span>`
        )
        .join("")
    : "Aucun port listé (lance nmap pour enrichir)";

  const exps = d.exposures || [];
  document.getElementById("td-exposures").innerHTML = exps.length
    ? exps
        .map(
          (e) =>
            `<div class="risk-line"><span class="badge ${esc(e.risk || "")}">${esc(
              e.risk || "?"
            )}</span> :${esc(e.port)} ${esc(e.service || "")} — ${esc(
              (e.recommendation || "").slice(0, 80)
            )}</div>`
        )
        .join("")
    : "—";

  const cves = d.cves || [];
  document.getElementById("td-cves").innerHTML = cves.length
    ? cves
        .slice(0, 12)
        .map(
          (c) =>
            `<div class="risk-line"><b>${esc(c.id || "CVE")}</b> · ${esc(
              c.severity || ""
            )} · ${esc((c.description || "").slice(0, 90))}</div>`
        )
        .join("")
    : "—";
}

window.renderTopology = function renderTopology() {
  const data = await api("/api/topology");
  state.topoRaw = data;
  const container = document.getElementById("network-graph");
  const emptyEl = document.getElementById("topo-empty");
  if (data.meta) {
    document.getElementById("tp-subnet").textContent = data.meta.subnet || "—";
    document.getElementById("tp-gateway").textContent = data.meta.gateway || "—";
    document.getElementById("tp-devices").textContent = data.meta.devices || 0;
    document.getElementById("tp-intermediates").textContent = data.meta.intermediates || 0;
    const boxes = data.meta.subnet_boxes || [];
    const tb = document.getElementById("tp-subnets");
    if (tb) tb.textContent = boxes.length ? boxes.slice(0, 4).join(", ") : data.meta.subnet || "—";
  }

  if (typeof vis === "undefined") {
    container.innerHTML = `<div class="empty-state">vis-network non chargé (réseau / CDN).</div>`;
    return;
  }

  const rawNodes = data.nodes || [];
  const nodeList = filterTopoNodes(rawNodes);
  const keepIds = new Set(nodeList.map((n) => n.id));
  // keep edges whose ends are both visible
  const edgeList = (data.edges || []).filter((e) => keepIds.has(e.from) && keepIds.has(e.to));

  const onlySkeleton =
    rawNodes.length <= 3 &&
    rawNodes.every((n) => ["internet", "gateway", "self"].includes(n.id) || n.role === "gateway");
  if (emptyEl) {
    emptyEl.classList.toggle("hidden", !(data.meta?.empty || onlySkeleton));
  }

  const nodes = new vis.DataSet(
    nodeList.map((n) => {
      const role = n.role || n.group || "unknown";
      const colors = colorForRole(role);
      const icon =
        n.image ||
        n.icon ||
        `/static/img/devices/${role === "host_open_ports" ? "host" : role}.svg`;
      // Size hierarchy: gateway/self larger, leaves smaller
      let size = n.size || 30;
      if (role === "gateway" || role === "router") size = Math.max(size, 40);
      else if (role === "self") size = Math.max(size, 36);
      else if (role === "ap") size = Math.max(size, 34);
      else if (role === "internet") size = Math.max(size, 28);
      // Cleaner labels (short)
      let label = n.label || String(n.id || "");
      if (label.includes("\n")) {
        /* keep multi-line server labels */
      } else if (label.length > 22) {
        label = label.slice(0, 20) + "…";
      }
      return {
        ...n,
        label,
        shape: "image",
        image: icon,
        brokenImage: "/static/img/devices/unknown.svg",
        size,
        // No rectangular border around image icons (avoids ugly squares)
        color: {
          border: "transparent",
          background: "transparent",
          highlight: { border: colors.border, background: "transparent" },
          hover: { border: colors.border, background: "transparent" },
        },
        borderWidth: 0,
        borderWidthSelected: 0,
        font: {
          color: "#e8eef9",
          face: "IBM Plex Mono, ui-monospace, monospace",
          size: role === "gateway" || role === "self" ? 12 : 11,
          multi: true,
          align: "center",
          strokeWidth: 4,
          strokeColor: "rgba(10,13,18,0.92)",
          vadjust: 4,
        },
        shadow: {
          enabled: true,
          color: colors.glow || "rgba(0,0,0,0.45)",
          size: 16,
          x: 0,
          y: 2,
        },
        margin: { top: 10, right: 10, bottom: 10, left: 10 },
      };
    })
  );
  // edges déjà stylées côté serveur ; edgeStyle en secours
  const edges = new vis.DataSet(edgeList.map((e) => edgeStyle(e)));

  const options = {
    autoResize: true,
    height: "100%",
    width: "100%",
    nodes: {
      borderWidth: 0,
      // useBorderWithImage:false → no square frame around device icons
      shapeProperties: { borderRadius: 0, useBorderWithImage: false },
      scaling: { min: 18, max: 52 },
      chosen: true,
    },
    edges: {
      selectionWidth: 2.5,
      hoverWidth: 2,
      smooth: {
        type: state.hierarchical ? "cubicBezier" : "continuous",
        forceDirection: state.hierarchical ? "vertical" : "none",
        roundness: state.hierarchical ? 0.45 : 0.28,
      },
      color: { inherit: false },
      font: { size: 9, color: "#6b7688", strokeWidth: 0 },
    },
    physics: state.hierarchical
      ? false
      : {
          enabled: true,
          stabilization: { iterations: 160, fit: true, updateInterval: 25 },
          barnesHut: {
            gravitationalConstant: -5200,
            centralGravity: 0.12,
            springLength: 140,
            springConstant: 0.035,
            damping: 0.48,
            avoidOverlap: 0.55,
          },
        },
    layout: state.hierarchical
      ? {
          hierarchical: {
            enabled: true,
            direction: "UD",
            sortMethod: "directed",
            shakeTowards: "roots",
            levelSeparation: 130,
            nodeSpacing: 170,
            treeSpacing: 200,
            blockShifting: true,
            edgeMinimization: true,
            parentCentralization: true,
          },
        }
      : { hierarchical: { enabled: false }, improvedLayout: true, randomSeed: 42 },
    interaction: {
      hover: true,
      tooltipDelay: 60,
      hideEdgesOnDrag: true,
      hideEdgesOnZoom: false,
      navigationButtons: true,
      keyboard: false,
      zoomView: true,
      dragView: true,
      multiselect: false,
    },
  };

  if (state.networkGraph) {
    try {
      state.networkGraph.destroy();
    } catch (_) {}
  }
  // clear previous empty message in container
  if (container.querySelector(".empty-state")) container.innerHTML = "";

  state.networkGraph = new vis.Network(container, { nodes, edges }, options);
  state.networkGraph.once("stabilizationIterationsDone", () => {
    try {
      state.networkGraph.setOptions({ physics: false });
      state.networkGraph.fit({ animation: { duration: 400, easingFunction: "easeInOutQuad" } });
    } catch (_) {}
  });
  // hierarchical: fit after short delay
  if (state.hierarchical) {
    setTimeout(() => {
      try {
        state.networkGraph.fit({
          animation: { duration: 350, easingFunction: "easeInOutQuad" },
          padding: 36,
        });
      } catch (_) {}
    }, 80);
  }

  state.networkGraph.on("click", (params) => {
    if (params.nodes?.length) {
      const id = params.nodes[0];
      showTopoDetail(id);
      if (id && /^\d+\.\d+\.\d+\.\d+$/.test(String(id))) {
        // optional drawer if exists
        try {
          openHostDrawer(id);
        } catch (_) {}
      }
    }
  });
}

window.colorForRole = function colorForRole(role) {
  const map = {
    internet: {
      background: "#121820",
      border: "#6b7688",
      highlight: "#1c2430",
      glow: "rgba(107,118,136,0.35)",
    },
    gateway: {
      background: "#0d3d28",
      border: "#22c55e",
      highlight: "#145c38",
      glow: "rgba(34,197,94,0.45)",
    },
    android: {
      background: "#052e16",
      border: "#3DDC84",
      highlight: "#14532d",
      glow: "rgba(61,220,132,0.5)",
    },
    apple: {
      background: "#1c1917",
      border: "#f5f5f7",
      highlight: "#292524",
      glow: "rgba(245,245,247,0.35)",
    },
    server: {
      background: "#0c4a6e",
      border: "#38bdf8",
      highlight: "#075985",
      glow: "rgba(56,189,248,0.4)",
    },
    tv: {
      background: "#2e1065",
      border: "#a78bfa",
      highlight: "#4c1d95",
      glow: "rgba(167,139,250,0.4)",
    },
    router: {
      background: "#0c2f3d",
      border: "#2fd9d0",
      highlight: "#124a5c",
      glow: "rgba(47,217,208,0.4)",
    },
    ap: {
      background: "#3d2208",
      border: "#f77f00",
      highlight: "#5a320c",
      glow: "rgba(247,127,0,0.4)",
    },
    switch: {
      background: "#0c2440",
      border: "#3b9eff",
      highlight: "#143560",
      glow: "rgba(59,158,255,0.35)",
    },
    pc: {
      background: "#1a2040",
      border: "#7b8cff",
      highlight: "#2a3070",
      glow: "rgba(123,140,255,0.35)",
    },
    apple: {
      background: "#1c1c1c",
      border: "#c0c0c0",
      highlight: "#2a2a2a",
      glow: "rgba(192,192,192,0.25)",
    },
    mobile: {
      background: "#2e1530",
      border: "#ff5ca8",
      highlight: "#4a2050",
      glow: "rgba(255,92,168,0.35)",
    },
    raspberry: {
      background: "#3a0a0a",
      border: "#ef4444",
      highlight: "#5a1212",
      glow: "rgba(239,68,68,0.35)",
    },
    vm: {
      background: "#1e0a38",
      border: "#a855f7",
      highlight: "#301050",
      glow: "rgba(168,85,247,0.35)",
    },
    iot: {
      background: "#063333",
      border: "#2fd9d0",
      highlight: "#0a4a4a",
      glow: "rgba(47,217,208,0.3)",
    },
    camera: {
      background: "#2a1010",
      border: "#f87171",
      highlight: "#401818",
      glow: "rgba(248,113,113,0.3)",
    },
    printer: {
      background: "#2a1a00",
      border: "#fbbf24",
      highlight: "#3d2800",
      glow: "rgba(251,191,36,0.3)",
    },
    self: {
      background: "#7a3a00",
      border: "#ff9f1a",
      highlight: "#9a4c00",
      glow: "rgba(255,159,26,0.45)",
    },
    host_open_ports: {
      background: "#12281c",
      border: "#34d399",
      highlight: "#1a3d2a",
      glow: "rgba(52,211,153,0.3)",
    },
    host: {
      background: "#151b25",
      border: "#64748b",
      highlight: "#1e2633",
      glow: "rgba(100,116,139,0.25)",
    },
    unknown: {
      background: "#151b25",
      border: "#64748b",
      highlight: "#1e2633",
      glow: "rgba(100,116,139,0.25)",
    },
  };
  return map[role] || map.unknown;
}

window.edgeStyle = function edgeStyle(e) {
  const t = e.edge_type || "client";
  const base = { ...e };
  if (!base.color || typeof base.color === "string") {
    if (t === "uplink") {
      base.color = { color: "rgba(107,118,136,0.75)", highlight: "#a8b4c8", hover: "#a8b4c8" };
    } else if (t === "backbone") {
      base.color = { color: "rgba(47,217,208,0.85)", highlight: "#7aefe8", hover: "#7aefe8" };
    } else {
      base.color = { color: "rgba(70,82,104,0.7)", highlight: "#f77f00", hover: "#f77f00" };
    }
  }
  if (base.width == null) {
    base.width = t === "backbone" ? 2.8 : t === "uplink" ? 1.8 : 1.35;
  }
  if (base.smooth == null) {
    base.smooth = { type: "continuous", roundness: 0.3 };
  }
  return base;
}

document.getElementById("btn-refresh-topology")?.addEventListener("click", renderTopology);
document.getElementById("btn-export-topo-csv")?.addEventListener("click", () => {
  window.location = tokenUrl("/api/topology/export.csv");
});
document.getElementById("btn-topo-fit")?.addEventListener("click", () => {
  if (state.networkGraph) {
    state.networkGraph.fit({
      animation: { duration: 350, easingFunction: "easeInOutQuad" },
      padding: 40,
    });
  }
});

document.getElementById("btn-layout-toggle")?.addEventListener("click", () => {
  state.hierarchical = !state.hierarchical;
  document.getElementById("btn-layout-toggle").textContent = state.hierarchical
    ? "Hiérarchique"
    : "Force Atlas";
  renderTopology();
});

let _topoFilterTimer = null;
document.getElementById("topo-search")?.addEventListener("input", (e) => {
  state.topoFilter.q = e.target.value || "";
  clearTimeout(_topoFilterTimer);
  _topoFilterTimer = setTimeout(() => renderTopology(), 200);
});
document.getElementById("topo-filter-role")?.addEventListener("change", (e) => {
  state.topoFilter.role = e.target.value || "";
  syncLegendActive();
  const tf = document.getElementById("tp-filter");
  if (tf) tf.textContent = state.topoFilter.role || "tous";
  renderTopology();
});

window.syncLegendActive = function syncLegendActive() {
  document.querySelectorAll("#topo-legend .leg-item").forEach((el) => {
    const r = el.dataset.role || "";
    el.classList.toggle("active", r === (state.topoFilter.role || ""));
  });
}

document.getElementById("topo-legend")?.addEventListener("click", (e) => {
  const item = e.target.closest(".leg-item");
  if (!item) return;
  const role = item.dataset.role || "";
  // toggle if same role
  state.topoFilter.role =
    state.topoFilter.role === role && role !== "" ? "" : role;
  const sel = document.getElementById("topo-filter-role");
  if (sel) sel.value = state.topoFilter.role;
  const tf = document.getElementById("tp-filter");
  if (tf) tf.textContent = state.topoFilter.role || "tous";
  syncLegendActive();
  renderTopology();
});

document.getElementById("btn-live-toggle").addEventListener("click", async () => {
  state.liveOn = !state.liveOn;
  const btn = document.getElementById("btn-live-toggle");
  btn.textContent = state.liveOn ? "Live ON" : "Live OFF";
  btn.classList.toggle("live-on", state.liveOn);
  if (state.liveTimer) clearInterval(state.liveTimer);
  if (state.liveOn) {
    const sec = parseInt(document.getElementById("live-interval").value, 10) || 60;
    log(`Live monitoring (léger) toutes les ${sec}s`);
    toast(`Live ON · ${sec}s`, "ok");
    state.liveTimer = setInterval(async () => {
      const subnet = document.getElementById("arp-subnet").value.trim();
      const res = await api("/api/arp-scan", {
        method: "POST",
        body: JSON.stringify({ subnet, enrich: true, light: true, async: true }),
      });
      if (res.job_id) {
        // lightweight wait
        const wait = async () => {
          for (let i = 0; i < 40; i++) {
            await new Promise((r) => setTimeout(r, 500));
            const j = await api(`/api/jobs/${res.job_id}`);
            if (j.status === "done" && j.result && !j.result.error) {
              state.arp = j.result;
              renderArpResults(j.result);
              populateTargetDropdown(j.result.hosts || []);
              updateDashboard();
              if (document.getElementById("view-topology").classList.contains("active")) {
                renderTopology();
              }
              log(`↻ Live: ${j.result.count} hôte(s)`);
              return;
            }
            if (j.status === "error" || j.status === "cancelled") return;
          }
        };
        wait();
      }
    }, sec * 1000);
  } else {
    log("Live monitoring OFF");
  }
});

// ---------- Present mode + PNG export ----------
window.enterPresentMode = function enterPresentMode() {
  state.presentMode = true;
  document.body.classList.add("present-mode");
  showView("topology");
  let hint = document.getElementById("present-hint");
  if (!hint) {
    hint = document.createElement("div");
    hint.id = "present-hint";
    hint.className = "present-exit-hint";
    hint.innerHTML = `Mode présentation · <kbd>Esc</kbd> pour quitter · <kbd>F</kbd> fit`;
    document.body.appendChild(hint);
  }
  setTimeout(() => {
    try {
      state.networkGraph?.fit({ animation: true });
    } catch (_) {}
  }, 200);
  toast("Mode présentation", "ok");
}

window.exitPresentMode = function exitPresentMode() {
  state.presentMode = false;
  document.body.classList.remove("present-mode");
  document.getElementById("present-hint")?.remove();
  setTimeout(() => {
    try {
      state.networkGraph?.fit({ animation: true });
    } catch (_) {}
  }, 100);
}

document.getElementById("btn-present-mode")?.addEventListener("click", () => {
  if (state.presentMode) exitPresentMode();
  else enterPresentMode();
});

document.getElementById("btn-export-topo-png")?.addEventListener("click", () => {
  try {
    if (!state.networkGraph) {
      toast("Aucune topologie affichée", "warn");
      return;
    }
    const canvas = document.querySelector("#network-graph canvas");
    if (!canvas) {
      toast("Canvas topologie introuvable", "err");
      return;
    }
    const a = document.createElement("a");
    a.download = `harmattan-topo-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, "-")}.png`;
    a.href = canvas.toDataURL("image/png");
    a.click();
    toast("PNG topologie exporté", "ok");
    log("Export topologie PNG");
  } catch (e) {
    toast("Export PNG échoué: " + (e.message || e), "err");
  }
});

