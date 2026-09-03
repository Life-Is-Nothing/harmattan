/**
 * HARMATTAN v3.22 — Module: traffic
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

// ---------- Traffic ----------
window.fillTrafficIfaces = function fillTrafficIfaces(interfaces, preferred) {
  const sel = document.getElementById("traffic-iface");
  if (!sel || sel.dataset.filled === "1") return;
  (interfaces || []).forEach((i) => {
    const o = document.createElement("option");
    o.value = i.name;
    o.textContent = `${i.name} — ${i.ip || "?"}${i.virtual ? " (virt)" : ""}`;
    if (preferred && i.name === preferred) o.selected = true;
    sel.appendChild(o);
  });
  sel.dataset.filled = "1";
}

state.wsSelected = null;
state.wsFilter = "";

window.renderTrafficSnap = function renderTrafficSnap(snap) {
  if (!snap) return;
  document.getElementById("traffic-bytes").textContent = (
    (snap.bytes_total || 0) / 1024
  ).toFixed(1);
  if (document.getElementById("traffic-buffer")) {
    document.getElementById("traffic-buffer").textContent = snap.buffer_size || snap.total_packets || 0;
  }
  document.getElementById("traffic-flows").innerHTML =
    (snap.top_flows || [])
      .map(
        (f) => `
    <tr>
      <td>${esc(f.src)}</td><td>${esc(f.dst)}</td>
      <td><span class="proto ${esc(f.protocol)}">${esc(f.protocol)}</span></td>
      <td>${esc(f.dport ?? "—")}</td>
      <td>${esc(f.packets)}</td><td>${((f.bytes || 0) / 1024).toFixed(1)} Ko</td>
    </tr>`
      )
      .join("") || `<tr><td colspan="6">En attente…</td></tr>`;
  // refresh packet list from dedicated API
  refreshPacketList();
}

window.renderPacketList = function renderPacketList(data) {
  const body = document.getElementById("ws-packet-body");
  if (!body) return;
  const pkts = data.packets || [];
  document.getElementById("traffic-total").textContent = data.total ?? pkts.length;
  if (document.getElementById("traffic-buffer")) {
    document.getElementById("traffic-buffer").textContent = data.buffer_total ?? data.packets_total ?? "—";
  }
  if (data.bytes_total != null) {
    document.getElementById("traffic-bytes").textContent = ((data.bytes_total || 0) / 1024).toFixed(1);
  }
  const meta = document.getElementById("ws-list-meta");
  if (meta) {
    meta.textContent = `${data.total || 0} affiché(s) · buffer ${data.buffer_total || 0}${
      data.filter ? " · filter: " + data.filter : ""
    }`;
  }
  if (!pkts.length) {
    body.innerHTML = `<tr><td colspan="7" class="muted">Aucun paquet${
      data.filter ? " (filtre trop strict ?)" : " — capture / import PCAP"
    }</td></tr>`;
    return;
  }
  body.innerHTML = pkts
    .map((p) => {
      const proto = p.protocol || "OTHER";
      const selected = state.wsSelected === p.no ? "selected" : "";
      const src =
        p.sport != null && p.sport !== "" ? `${p.src}:${p.sport}` : p.src;
      const dst =
        p.dport != null && p.dport !== "" ? `${p.dst}:${p.dport}` : p.dst;
      return `<tr class="proto-${esc(proto)} ${selected}" data-no="${p.no}">
        <td class="col-no">${p.no}</td>
        <td class="col-time">${esc(p.time)}</td>
        <td class="col-src">${esc(src)}</td>
        <td class="col-dst">${esc(dst)}</td>
        <td class="col-proto"><span class="proto-chip ${esc(proto)}">${esc(proto)}</span></td>
        <td class="col-len">${esc(p.length)}</td>
        <td class="col-info" title="${esc(p.info || "")}">${esc(p.info || "")}</td>
      </tr>`;
    })
    .join("");
}

window.refreshPacketList = function refreshPacketList() {
  const filt = state.wsFilter || document.getElementById("display-filter")?.value || "";
  const q = new URLSearchParams({
    limit: "400",
    offset: "0",
    filter: filt,
  });
  try {
    const data = await api("/api/traffic/packets?" + q.toString());
    renderPacketList(data);
    refreshProtoStats();
  } catch (e) {
    /* ignore */
  }
}

window.selectPacket = function selectPacket(no) {
  state.wsSelected = no;
  document.getElementById("traffic-selected").textContent = "#" + no;
  const followBtn = document.getElementById("btn-follow-stream");
  if (followBtn) followBtn.disabled = false;
  document.querySelectorAll("#ws-packet-body tr").forEach((tr) => {
    tr.classList.toggle("selected", String(tr.dataset.no) === String(no));
  });
  try {
    const p = await api(`/api/traffic/packet/${no}`);
    if (p.error) {
      document.getElementById("ws-layers").textContent = p.message || p.error;
      return;
    }
    renderPacketDetail(p);
  } catch (e) {
    document.getElementById("ws-layers").textContent = String(e.message || e);
  }
}

window.refreshProtoStats = function refreshProtoStats() {
  try {
    const d = await api("/api/traffic/proto-stats");
    const el = document.getElementById("proto-stats-bars");
    if (!el) return;
    const items = d.protocols || [];
    if (!items.length) {
      el.innerHTML = "—";
      return;
    }
    const max = Math.max(...items.map((x) => x.packets), 1);
    el.innerHTML = items
      .slice(0, 12)
      .map(
        (x) => `<span class="proto-stat">
        <span class="proto-chip ${esc(x.protocol)}">${esc(x.protocol)}</span>
        <span class="bar"><i style="width:${Math.max(6, (x.packets / max) * 100)}%"></i></span>
        <b>${x.packets}</b>
      </span>`
      )
      .join("");
  } catch (_) {}
}

document.getElementById("btn-refresh-proto")?.addEventListener("click", refreshProtoStats);
document.getElementById("btn-traffic-clear")?.addEventListener("click", async () => {
  await api("/api/traffic/clear", { method: "POST", body: "{}" });
  state.wsSelected = null;
  document.getElementById("ws-layers").textContent = "Buffer vidé.";
  document.getElementById("ws-hex").textContent = "—";
  document.getElementById("btn-follow-stream").disabled = true;
  refreshPacketList();
  refreshProtoStats();
  toast("Buffer trafic vidé", "ok");
});

document.getElementById("btn-follow-stream")?.addEventListener("click", async () => {
  if (!state.wsSelected) return;
  const r = await api(`/api/traffic/follow/${state.wsSelected}`);
  if (!r.ok) {
    toast(r.message || r.error || "Follow stream impossible", "err");
    return;
  }
  state.wsStreamNo = state.wsSelected;
  const st = r.stream || {};
  document.getElementById("stream-title").textContent =
    `Stream ${st.client || ""} ↔ ${st.server || ""}` + (st.http ? " · HTTP" : "");
  document.getElementById("stream-meta").textContent =
    `${st.packets || 0} paquets · ${st.payload_bytes || 0} o payload · #${(r.member_nos || []).join(",")}` +
    (r.http?.method ? ` · ${r.http.method} ${r.http.path || ""} → ${r.http.status || ""}` : "");
  // Prefer HTTP pretty reassembly when available
  document.getElementById("stream-body").textContent =
    (r.http && r.http.pretty) || r.assembled || "(vide)";
  document.getElementById("stream-modal")?.classList.remove("hidden");
});

// Scheduled ARP + report
let _schedOn = false;
document.getElementById("btn-sched-toggle")?.addEventListener("click", async () => {
  const btn = document.getElementById("btn-sched-toggle");
  if (!_schedOn) {
    const r = await api("/api/scheduler/start", {
      method: "POST",
      body: JSON.stringify({ interval: 300, with_report: true }),
    });
    _schedOn = true;
    if (btn) btn.textContent = "⏱ Scheduler ON";
    toast(r.message || "Scheduler ON (5 min + rapport)", "ok");
    log("Scheduler ARP planifié démarré");
  } else {
    const r = await api("/api/scheduler/stop", { method: "POST", body: "{}" });
    _schedOn = false;
    if (btn) btn.textContent = "⏱ Scheduler";
    toast(r.message || "Scheduler OFF", "warn");
  }
});
document.getElementById("btn-stream-close")?.addEventListener("click", () => {
  document.getElementById("stream-modal")?.classList.add("hidden");
});
document.getElementById("stream-modal")?.addEventListener("click", (e) => {
  if (e.target.id === "stream-modal") e.target.classList.add("hidden");
});
document.getElementById("btn-stream-export-txt")?.addEventListener("click", () => {
  const no = state.wsStreamNo || state.wsSelected;
  if (!no) return;
  window.location = tokenUrl(`/api/traffic/follow/${no}/export.txt`);
  toast("Export stream TXT…", "ok");
});
document.getElementById("btn-stream-export-json")?.addEventListener("click", () => {
  const no = state.wsStreamNo || state.wsSelected;
  if (!no) return;
  window.location = tokenUrl(`/api/traffic/follow/${no}/export.json`);
  toast("Export stream JSON…", "ok");
});

document.getElementById("btn-sahel-correlate")?.addEventListener("click", async () => {
  toast("Corrélation Sahel…", "ok");
  log("Corrélation paquets ↔ alertes Sahel…");
  const url = document.getElementById("sahel-url")?.value?.trim() || "";
  const r = await api("/api/sahel/correlate", {
    method: "POST",
    body: JSON.stringify(url ? { url } : {}),
  });
  const panel = document.getElementById("corr-panel");
  const sum = document.getElementById("corr-summary");
  const res = document.getElementById("corr-results");
  if (panel) panel.style.display = "block";
  const loc = r.local || {};
  const rem = r.remote || {};
  if (sum) {
    sum.textContent = `Paquets: ${r.packets || 0} · Alertes: ${r.alerts_used || 0} · ` +
      `Match local: ${loc.matched || 0} · Remote: ${rem.ok ? "OK" : "offline"} (${rem.message || rem.via || ""})`;
  }
  const matches = loc.matches || rem.matches || [];
  if (res) {
    if (!matches.length) {
      res.innerHTML = `<span class="muted">Aucun match IP (lance des alertes Sahel + capture avec les mêmes IP).</span>`;
    } else {
      res.innerHTML = matches
        .slice(0, 25)
        .map(
          (m) => `<div class="hist-line">
          <span class="t">${esc(m.severity || "")}</span>
          <span class="k">${esc(m.alert_id || "")}</span>
          <span><b>${esc(m.src || "")}</b>→<b>${esc(m.dst || "")}</b>
            · pkts #${esc((m.top_packet_nos || []).join(","))}
            · ${esc(m.title || "")}</span>
        </div>`
        )
        .join("");
    }
  }
  toast(
    `Corrélation: ${loc.matched || 0} match(s)` +
      (rem.matched != null ? ` · Sahel ${rem.matched}` : ""),
    "ok"
  );
  log(`Corrélation Sahel: local=${loc.matched || 0}`);
});

window.renderPacketDetail = function renderPacketDetail(p) {
  const layers = p.layers || [];
  const el = document.getElementById("ws-layers");
  if (!layers.length) {
    el.innerHTML = `<div class="muted">Pas de couches pour #${p.no}</div>
      <div>${esc(p.info || "")}</div>`;
  } else {
    el.innerHTML = layers
      .map((L, i) => {
        const fields = (L.fields || [])
          .map(
            (f) =>
              `<div class="ws-field"><span class="k">${esc(f.k)}</span><span class="v">${esc(
                f.v
              )}</span></div>`
          )
          .join("");
        return `<details class="ws-layer" ${i < 3 ? "open" : ""}>
          <summary>${esc(L.name)}${L.summary ? " · " + esc(L.summary) : ""}</summary>
          <div class="ws-fields">${fields || '<span class="muted">—</span>'}</div>
        </details>`;
      })
      .join("");
  }
  const hexEl = document.getElementById("ws-hex");
  const lines = p.hex || [];
  if (!lines.length) {
    hexEl.textContent = "—";
    return;
  }
  hexEl.innerHTML = lines
    .map(
      (ln) =>
        `<span class="off">${esc(ln.offset)}</span> ${esc(ln.hex)} <span class="asc">${esc(
          ln.ascii
        )}</span>`
    )
    .join("\n");
}

document.getElementById("ws-packet-body")?.addEventListener("click", (e) => {
  const tr = e.target.closest("tr[data-no]");
  if (!tr) return;
  selectPacket(parseInt(tr.dataset.no, 10));
});

document.getElementById("btn-display-filter")?.addEventListener("click", () => {
  state.wsFilter = document.getElementById("display-filter")?.value?.trim() || "";
  refreshPacketList();
  toast(state.wsFilter ? "Filtre: " + state.wsFilter : "Filtre effacé", "ok");
});
document.getElementById("btn-df-clear")?.addEventListener("click", () => {
  const el = document.getElementById("display-filter");
  if (el) el.value = "";
  state.wsFilter = "";
  refreshPacketList();
});
document.getElementById("display-filter")?.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    state.wsFilter = e.target.value.trim();
    refreshPacketList();
  }
});

document.getElementById("btn-traffic-oneshot")?.addEventListener("click", async () => {
  const iface = document.getElementById("traffic-iface").value.trim();
  const filter = document.getElementById("traffic-filter").value.trim();
  const btn = document.getElementById("btn-traffic-oneshot");
  btn.disabled = true;
  btn.textContent = "Capture…";
  log("⚡ Capture oneshot 10 s…");
  toast("Capture 10 s en cours…", "ok");
  try {
    const r = await api("/api/traffic/oneshot", {
      method: "POST",
      body: JSON.stringify({ iface, filter, seconds: 10 }),
    });
    if (r.error) {
      toast(r.message || r.error, "err");
      log(`⚠ ${esc(r.message || r.error)}`);
    } else {
      toast(r.message || "Capture terminée", r.warning ? "warn" : "ok");
      log(
        `⚡ ${r.total_packets || 0} paquets · iface ${esc(r.iface || "auto")} · ${esc(
          r.running_as_root ? "root" : "user"
        )}`
      );
      renderTrafficSnap(r);
    }
  } finally {
    btn.disabled = false;
    btn.textContent = "⚡ Capture 10 s";
  }
});

document.getElementById("btn-traffic-start").addEventListener("click", async () => {
  const iface = document.getElementById("traffic-iface").value.trim();
  const filter = document.getElementById("traffic-filter").value.trim();
  const r = await api("/api/traffic/start", {
    method: "POST",
    body: JSON.stringify({ iface, filter }),
  });
  if (r.error) {
    toast(r.message || r.error, "err");
    return;
  }
  if (r.error && typeof r.error === "string") {
    toast(r.error, "err");
  }
  log(`▶ Capture live · ${esc(r.iface || "auto")}`);
  toast(r.message || "Capture démarrée", r.running_as_root === false ? "warn" : "ok");
  document.getElementById("btn-traffic-start").disabled = true;
  document.getElementById("btn-traffic-stop").disabled = false;
  state.trafficTimer = setInterval(pollTraffic, 1500);
});

document.getElementById("btn-traffic-stop").addEventListener("click", async () => {
  await api("/api/traffic/stop", { method: "POST" });
  clearInterval(state.trafficTimer);
  log("■ Capture arrêtée");
  document.getElementById("btn-traffic-start").disabled = false;
  document.getElementById("btn-traffic-stop").disabled = true;
});

window.pollTraffic = function pollTraffic() {
  const snap = await api("/api/traffic/snapshot");
  if (snap.error) log(`⚠ ${esc(snap.error)}`);
  renderTrafficSnap(snap);
}

// ensure traffic view refreshes list when opened
const _showViewOrig = showView;
showView = function (name) {
  _showViewOrig(name);
  if (name === "traffic") {
    refreshPacketList();
    api("/api/traffic/snapshot").then(renderTrafficSnap).catch(() => {});
  }
};

document.getElementById("btn-traffic-export").addEventListener("click", () => {
  window.location = tokenUrl("/api/traffic/export.csv");
});

