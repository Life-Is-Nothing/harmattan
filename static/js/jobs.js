/**
 * HARMATTAN v3.22 — Module: jobs
 * Auto-split from app.js monolith
 */
'use strict';

// Access global state
const state = window.state || {};
const TOKEN = window.HARMATTAN_TOKEN || '';

// ---------- Jobs ----------
window.refreshJobQueueHint = function refreshJobQueueHint() {
  const el = document.getElementById("job-queue");
  if (!el) return;
  try {
    const d = await api("/api/jobs");
    const active = (d.jobs || []).filter((j) => j.status === "running" || j.status === "pending");
    el.textContent = active.length > 1 ? `+${active.length - 1} en file` : active.length === 1 ? "1 actif" : "";
  } catch (_) {
    /* ignore */
  }
}

window.showJobBar = function showJobBar(kind, msg, pct) {
  const bar = document.getElementById("job-bar");
  bar.classList.remove("hidden");
  bar.classList.add("active");
  document.getElementById("job-kind").textContent = kind;
  document.getElementById("job-msg").textContent = msg || "";
  const p = Math.max(0, Math.min(100, Number(pct) || 0));
  document.getElementById("job-fill").style.width = `${p}%`;
  const pctEl = document.getElementById("job-pct");
  if (pctEl) pctEl.textContent = `${Math.round(p)}%`;
  refreshJobQueueHint();
}

window.hideJobBar = function hideJobBar() {
  const bar = document.getElementById("job-bar");
  bar.classList.add("hidden");
  bar.classList.remove("active");
  document.getElementById("job-fill").style.width = "0%";
  const pctEl = document.getElementById("job-pct");
  if (pctEl) pctEl.textContent = "0%";
  state.currentJob = null;
  if (state.jobPoll) {
    clearInterval(state.jobPoll);
    state.jobPoll = null;
  }
}

window.pollJob = function pollJob(jobId, onDone) {
  state.currentJob = jobId;
  showJobBar("…", "Démarrage", 2);

  const tick = async () => {
    try {
      const j = await api(`/api/jobs/${jobId}`);
      if (!j || j.error === "not_found") {
        hideJobBar();
        toast("Job introuvable", "err");
        return true;
      }
      showJobBar(j.kind, j.message || j.status, j.progress || 0);
      if (j.status === "done") {
        hideJobBar();
        await onDone(j.result);
        return true;
      }
      if (j.status === "error") {
        hideJobBar();
        log(`⚠ ${esc(j.error || "Erreur job")}`);
        toast(j.error || "Erreur", "err");
        return true;
      }
      if (j.status === "cancelled") {
        hideJobBar();
        toast("Job annulé", "warn");
        return true;
      }
    } catch (e) {
      hideJobBar();
      toast("Erreur polling job", "err");
      return true;
    }
    return false;
  };

  if (await tick()) return;
  state.jobPoll = setInterval(async () => {
    if (await tick()) {
      clearInterval(state.jobPoll);
      state.jobPoll = null;
    }
  }, 700);
}

document.getElementById("btn-job-cancel")?.addEventListener("click", async () => {
  if (!state.currentJob) return;
  await api(`/api/jobs/${state.currentJob}/cancel`, { method: "POST" });
  toast("Annulation demandée", "warn");
});

