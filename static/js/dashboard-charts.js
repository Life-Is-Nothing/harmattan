/**
 * HARMATTAN Dashboard Charts — Pure CSS + minimal JS
 * No external libraries needed
 */
'use strict';

const HarmattanCharts = (() => {

  /**
   * Render a CSS bar chart of scans per day
   * @param {string} containerId - DOM container
   * @param {Array} scans - [{created: "2026-07-16T01:04:08", kind: "arp"}, ...]
   */
  function renderScanTimeline(containerId, scans) {
    const el = document.getElementById(containerId);
    if (!el || !scans || !scans.length) return;

    // Group by date
    const byDate = {};
    scans.forEach((s) => {
      const day = (s.created || '').slice(0, 10);
      if (day) byDate[day] = (byDate[day] || 0) + 1;
    });

    const days = Object.keys(byDate).sort().slice(-14); // last 14 days
    if (!days.length) return;

    const maxCount = Math.max(...days.map((d) => byDate[d]), 1);

    const bars = days.map((day) => {
      const count = byDate[day];
      const pct = Math.round((count / maxCount) * 100);
      const label = day.slice(5); // MM-DD
      return `<div class="chart-bar-wrap" title="${day}: ${count} scan(s)">
        <div class="chart-bar" style="height:${pct}%"></div>
        <div class="chart-bar-label">${label}</div>
        <div class="chart-bar-value">${count}</div>
      </div>`;
    }).join('');

    el.innerHTML = `
      <div class="chart-title">Scans par jour (14 derniers)</div>
      <div class="bar-chart">${bars}</div>`;
  }

  /**
   * Render host count evolution
   * @param {string} containerId
   * @param {Array} data - [{date: "2026-07-16", count: 12}, ...]
   */
  function renderHostEvolution(containerId, data) {
    const el = document.getElementById(containerId);
    if (!el || !data || !data.length) return;

    const maxCount = Math.max(...data.map((d) => d.count || 0), 1);

    const bars = data.slice(-14).map((d) => {
      const pct = Math.round(((d.count || 0) / maxCount) * 100);
      return `<div class="chart-bar-wrap" title="${d.date}: ${d.count} hôtes">
        <div class="chart-bar green" style="height:${pct}%"></div>
        <div class="chart-bar-label">${(d.date || '').slice(5)}</div>
        <div class="chart-bar-value">${d.count}</div>
      </div>`;
    }).join('');

    el.innerHTML = `
      <div class="chart-title">Évolution hôtes</div>
      <div class="bar-chart">${bars}</div>`;
  }

  /**
   * Render risk distribution as CSS donut chart
   * @param {string} containerId
   * @param {Object} findings - {critical: 2, high: 5, medium: 12, low: 8, info: 15}
   */
  function renderRiskDistribution(containerId, findings) {
    const el = document.getElementById(containerId);
    if (!el || !findings) return;

    const levels = [
      { key: 'critical', color: '#ff3366', label: 'Critique' },
      { key: 'high', color: '#ff8800', label: 'Haute' },
      { key: 'medium', color: '#ffdd00', label: 'Moyenne' },
      { key: 'low', color: '#00f0ff', label: 'Basse' },
      { key: 'info', color: '#8b5cf6', label: 'Info' },
    ];

    const total = levels.reduce((sum, l) => sum + (findings[l.key] || 0), 0);
    if (total === 0) {
      el.innerHTML = '<div class="chart-title">Distribution des risques</div><div class="empty-state"><div class="icon">◌</div>Aucun finding.</div>';
      return;
    }

    // Build conic gradient
    let angle = 0;
    const segments = [];
    const legend = [];
    levels.forEach((l) => {
      const count = findings[l.key] || 0;
      if (count === 0) return;
      const pct = (count / total) * 100;
      segments.push(`${l.color} ${angle}deg ${angle + pct * 3.6}deg`);
      angle += pct * 3.6;
      legend.push(`<div class="donut-legend-item">
        <span class="donut-dot" style="background:${l.color}"></span>
        ${l.label}: <strong>${count}</strong>
      </div>`);
    });

    const gradient = `conic-gradient(${segments.join(', ')})`;

    el.innerHTML = `
      <div class="chart-title">Distribution risques (${total})</div>
      <div class="donut-row">
        <div class="donut-chart" style="background:${gradient}">
          <div class="donut-hole">${total}</div>
        </div>
        <div class="donut-legend">${legend.join('')}</div>
      </div>`;
  }

  return { renderScanTimeline, renderHostEvolution, renderRiskDistribution };
})();

window.HarmattanCharts = HarmattanCharts;
