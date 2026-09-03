/**
 * HARMATTAN Global Search — Ctrl+K fuzzy search modal
 */
'use strict';

const HarmattanSearch = (() => {
  let overlay = null;
  let input = null;
  let results = null;
  let activeIndex = -1;
  let allItems = [];

  const NAV_ITEMS = [
    { name: 'Dashboard', icon: '◆', meta: 'Vue d\'ensemble', action: () => showView('dashboard') },
    { name: 'Découverte ARP', icon: '📡', meta: 'Scan broadcast', action: () => showView('discovery') },
    { name: 'Scan Nmap', icon: '🔍', meta: 'Ports & services', action: () => showView('scan') },
    { name: 'Topologie', icon: '🗺', meta: 'Carte réseau', action: () => showView('topology') },
    { name: 'Attack Surface', icon: '⚡', meta: 'Scoring risques', action: () => showView('attack') },
    { name: 'Vulnérabilités', icon: '🛡', meta: 'CVE correlation', action: () => showView('vuln') },
    { name: 'Trafic', icon: '📊', meta: 'Capture & PCAP', action: () => showView('traffic') },
    { name: 'Outils', icon: '🔧', meta: 'Ping, DNS, TLS...', action: () => showView('tools') },
    { name: 'Intel', icon: '🧠', meta: 'SNMP, MITRE, ML', action: () => showView('intel') },
    { name: 'Historique', icon: '📋', meta: 'Scans & cleanup', action: () => showView('history') },
    { name: 'Export HTML', icon: '📄', meta: 'Rapport pro', action: () => { window.location = '/api/report.html'; } },
    { name: 'Export PDF', icon: '📑', meta: 'PDF pro', action: () => { window.location = '/api/report.pdf'; } },
    { name: 'Export DOCX', icon: '📝', meta: 'Word document', action: () => { window.location = '/api/report.docx'; } },
    { name: 'Scan maison', icon: '⚡', meta: 'Full-chain ARP→nmap', action: () => document.getElementById('btn-home-scan')?.click() },
    { name: 'AI Analyst', icon: '🤖', meta: 'Analyse cognitive', action: () => document.getElementById('btn-ai-analyze')?.click() },
  ];

  function buildOverlay() {
    if (overlay) return;
    overlay = document.createElement('div');
    overlay.className = 'search-overlay';
    overlay.innerHTML = `
      <div class="search-dialog">
        <div class="search-input-wrap">
          <span class="search-icon">⌕</span>
          <input type="text" class="search-input" placeholder="Rechercher hosts, scans, outils..." autocomplete="off" spellcheck="false">
          <span class="search-kbd">ESC</span>
        </div>
        <div class="search-results"></div>
        <div class="search-footer">
          <span><kbd>↑↓</kbd> naviguer</span>
          <span><kbd>Enter</kbd> ouvrir</span>
          <span><kbd>Esc</kbd> fermer</span>
        </div>
      </div>`;
    document.body.appendChild(overlay);

    input = overlay.querySelector('.search-input');
    results = overlay.querySelector('.search-results');

    input.addEventListener('input', onInput);
    input.addEventListener('keydown', onKeydown);
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) close();
    });
  }

  function open() {
    buildOverlay();
    activeIndex = -1;
    input.value = '';
    results.innerHTML = '';
    overlay.classList.add('open');
    input.focus();
    loadDynamicItems();
  }

  function close() {
    if (overlay) overlay.classList.remove('open');
    activeIndex = -1;
  }

  function isOpen() {
    return overlay && overlay.classList.contains('open');
  }

  function loadDynamicItems() {
    allItems = [...NAV_ITEMS];
    // Add hosts from state
    const st = window.state || {};
    if (st.arp && st.arp.hosts) {
      st.arp.hosts.forEach((h) => {
        allItems.push({
          name: h.hostname || h.ip,
          icon: '💻',
          meta: `${h.ip} · ${h.vendor || '?'} · ${h.role || '?'}`,
          type: 'host',
          action: () => { showView('topology'); setTimeout(() => window.showTopoDetail && window.showTopoDetail(h.ip), 200); },
        });
      });
    }
    // Add recent scans from DOM
    const scanRows = document.querySelectorAll('#scans-tbody tr');
    scanRows.forEach((row) => {
      const cells = row.querySelectorAll('td');
      if (cells.length >= 3) {
        allItems.push({
          name: `Scan #${cells[0]?.textContent || '?'}`,
          icon: '📋',
          meta: `${cells[1]?.textContent || ''} · ${cells[2]?.textContent || ''}`,
          type: 'scan',
          action: () => showView('history'),
        });
      }
    });
  }

  function onInput() {
    const q = input.value.trim().toLowerCase();
    if (!q) {
      results.innerHTML = '';
      activeIndex = -1;
      return;
    }
    const scored = allItems
      .map((item) => ({ ...item, score: fuzzyScore(q, `${item.name} ${item.meta}`.toLowerCase()) }))
      .filter((item) => item.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 12);

    if (scored.length === 0) {
      results.innerHTML = `<div class="search-empty"><div class="icon">◌</div>Aucun résultat pour "${escHtml(q)}"</div>`;
      activeIndex = -1;
      return;
    }

    activeIndex = 0;
    results.innerHTML = scored
      .map((item, i) => {
        const typeName = item.type || 'nav';
        const badgeClass = typeName;
        return `<div class="search-result-item ${i === 0 ? 'active' : ''}" data-idx="${i}">
          <div class="search-result-icon">${item.icon}</div>
          <div class="search-result-body">
            <div class="search-result-name">${highlight(item.name, q)}</div>
            <div class="search-result-meta">${escHtml(item.meta)}</div>
          </div>
          <span class="search-result-badge ${badgeClass}">${typeName}</span>
        </div>`;
      })
      .join('');

    // Click handlers
    results.querySelectorAll('.search-result-item').forEach((el, i) => {
      el.addEventListener('click', () => {
        scored[i].action();
        close();
      });
    });
  }

  function onKeydown(e) {
    const items = results.querySelectorAll('.search-result-item');
    if (e.key === 'Escape') {
      e.preventDefault();
      close();
      return;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      activeIndex = Math.min(activeIndex + 1, items.length - 1);
      updateActive(items);
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      activeIndex = Math.max(activeIndex - 1, 0);
      updateActive(items);
    }
    if (e.key === 'Enter') {
      e.preventDefault();
      if (activeIndex >= 0 && items[activeIndex]) {
        items[activeIndex].click();
      }
    }
  }

  function updateActive(items) {
    items.forEach((el, i) => el.classList.toggle('active', i === activeIndex));
    if (items[activeIndex]) items[activeIndex].scrollIntoView({ block: 'nearest' });
  }

  function fuzzyScore(query, text) {
    // Simple substring + word start scoring
    let score = 0;
    if (text.includes(query)) score += 100;
    // Check each word start
    const words = text.split(/\s+/);
    const qWords = query.split(/\s+/);
    for (const qw of qWords) {
      for (const w of words) {
        if (w.startsWith(qw)) score += 20;
        else if (w.includes(qw)) score += 5;
      }
    }
    // Exact start bonus
    if (text.startsWith(query)) score += 50;
    return score;
  }

  function highlight(text, query) {
    const escaped = escHtml(text);
    const qEsc = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return escaped.replace(new RegExp(`(${qEsc})`, 'gi'), '<mark>$1</mark>');
  }

  function escHtml(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
    );
  }

  // Keyboard shortcut
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      if (isOpen()) close();
      else open();
    }
  });

  return { open, close, isOpen };
})();

window.HarmattanSearch = HarmattanSearch;
