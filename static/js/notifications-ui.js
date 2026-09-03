// Minimal Notifications panel UI
(function(){
  function renderList(list){
    const el = document.getElementById('notifications-list');
    if(!el) return;
    el.innerHTML = '';
    list.forEach(n=>{
      const row = document.createElement('div'); row.className='notif-row';
      const t = document.createElement('div'); t.className='notif-time'; t.textContent = n.time;
      const b = document.createElement('div'); b.className='notif-body'; b.textContent = (n.payload && n.payload.type) ? JSON.stringify(n.payload) : JSON.stringify(n);
      row.appendChild(t); row.appendChild(b);
      el.appendChild(row);
    });
  }

  window.openNotifications = function(){
    const panel = document.getElementById('notifications-drawer');
    panel.classList.add('open'); panel.setAttribute('aria-hidden','false'); document.getElementById('drawer-backdrop').classList.remove('hidden');
    fetch('/api/notifications',{headers:{'X-Harmattan-Token':window.HARMATTAN_TOKEN||''}}).then(r=>r.json()).then(j=>{ if(j.ok) renderList(j.notifications||[]); else console.error(j);} ).catch(e=>console.error(e));
  }
  document.addEventListener('DOMContentLoaded', ()=>{
    const btn = document.getElementById('btn-notifications'); if(btn) btn.addEventListener('click', openNotifications);
    const close = document.getElementById('notif-close'); if(close) close.addEventListener('click', ()=>{ document.getElementById('notifications-drawer').classList.remove('open'); document.getElementById('notifications-drawer').setAttribute('aria-hidden','true'); document.getElementById('drawer-backdrop').classList.add('hidden'); });
  });
})();
