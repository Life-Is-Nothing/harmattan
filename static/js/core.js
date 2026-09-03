// HARMATTAN shared helpers (loaded before app.js)
window.HarmattanCore = (function () {
  const TOKEN = window.HARMATTAN_TOKEN || "";

  function esc(s) {
    return String(s ?? "").replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );
  }

  function toast(msg, type = "ok") {
    const root = document.getElementById("toast-root");
    if (!root) {
      console.log(`[toast:${type}]`, msg);
      return;
    }
    const el = document.createElement("div");
    el.className = `toast ${type}`;
    el.textContent = msg;
    root.appendChild(el);
    setTimeout(() => el.remove(), 4200);
  }

  function log(msg) {
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

  async function api(path, opts = {}) {
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
        if (window.HarmattanSSO && window.HarmattanSSO.loginUrl) {
          window.location.href = window.HarmattanSSO.loginUrl();
          return data;
        }
        toast("Session requise — reconnectez-vous (Identity)", "err");
      }
      if (res.status === 429) {
        toast(data.message || "Rate limit — ralentissez", "err");
      }
      return data;
    }
    if (!res.ok) {
      return { ok: false, error: "http_" + res.status, status: res.status };
    }
    return { ok: true, status: res.status };
  }

  /** Downloads use cookie auth — never put token in the URL. */
  function safeUrl(path) {
    return path;
  }

  return { TOKEN, esc, toast, log, api, safeUrl };
})();
