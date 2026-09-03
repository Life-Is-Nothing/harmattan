/**
 * HARMATTAN Loading Skeletons — Helper module
 * Usage: showSkeleton(containerId, type) / hideSkeleton(containerId)
 */
'use strict';

const HarmattanSkeletons = (() => {
  const SKELETONS = {
    card: () => `
      <div class="skeleton-card">
        <div class="skeleton skeleton-title"></div>
        <div class="skeleton-body">
          <div class="skeleton skeleton-text long"></div>
          <div class="skeleton skeleton-text medium"></div>
          <div class="skeleton skeleton-text short"></div>
        </div>
      </div>`,

    table: (rows = 5) => {
      let trs = '';
      for (let i = 0; i < rows; i++) {
        trs += `<tr><td><div class="skeleton skeleton-text medium"></div></td>
                      <td><div class="skeleton skeleton-text short"></div></td>
                      <td><div class="skeleton skeleton-text long"></div></td></tr>`;
      }
      return `<table class="skeleton-table"><tbody>${trs}</tbody></table>`;
    },

    stats: (count = 4) => {
      let cards = '';
      for (let i = 0; i < count; i++) {
        cards += `<div class="skeleton-stat">
          <div class="skeleton skeleton-value"></div>
          <div class="skeleton skeleton-label"></div>
        </div>`;
      }
      return `<div class="stat-grid">${cards}</div>`;
    },

    text: (lines = 4) => {
      const widths = ['long', 'medium', 'short', 'long', 'medium'];
      let html = '';
      for (let i = 0; i < lines; i++) {
        html += `<div class="skeleton skeleton-text ${widths[i % widths.length]}"></div>`;
      }
      return html;
    },

    rows: (count = 5) => {
      let html = '';
      for (let i = 0; i < count; i++) {
        html += `<div class="skeleton-row">
          <div class="skeleton skeleton-avatar"></div>
          <div class="skeleton-content">
            <div class="skeleton skeleton-text medium"></div>
            <div class="skeleton skeleton-text short"></div>
          </div>
        </div>`;
      }
      return html;
    },

    chart: () => `<div class="skeleton-chart"></div>`,

    topo: () => {
      const nodes = [];
      for (let i = 0; i < 8; i++) {
        const x = 40 + Math.random() * 320;
        const y = 40 + Math.random() * 300;
        nodes.push(`<div class="skeleton-node" style="left:${x}px;top:${y}px;"></div>`);
      }
      return `<div class="skeleton-topo">${nodes.join('')}</div>`;
    },
  };

  function showSkeleton(containerId, type = 'card', opts = {}) {
    const el = document.getElementById(containerId);
    if (!el) return;
    const generator = SKELETONS[type] || SKELETONS.card;
    el.innerHTML = generator(opts.rows || 5);
    el.classList.remove('loaded');
  }

  function hideSkeleton(containerId) {
    const el = document.getElementById(containerId);
    if (!el) return;
    el.classList.add('loaded');
    setTimeout(() => el.classList.remove('loaded'), 350);
  }

  return { showSkeleton, hideSkeleton };
})();

window.HarmattanSkeletons = HarmattanSkeletons;
