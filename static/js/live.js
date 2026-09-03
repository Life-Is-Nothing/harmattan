// SSE client for HARMATTAN live updates (cookie / same-origin auth)
(function(){
  // EventSource cannot set custom headers — rely on httponly cookie set by /
  const evtSrc = new EventSource('/api/stream', { withCredentials: true });

  function toast(msg, type='info'){
    try{ window.Toast && window.Toast.push({text:msg,type:type}); }catch(e){ console.log('toast',msg); }
  }

  evtSrc.addEventListener('job.update', e=>{
    try{
      const data = JSON.parse(e.data);
      const job = data.job || {};
      const jb = document.getElementById('job-bar');
      if(jb){
        jb.classList.remove('hidden');
        const kind = document.getElementById('job-kind');
        const pct = document.getElementById('job-pct');
        const msg = document.getElementById('job-msg');
        if (kind) kind.textContent = job.kind || 'job';
        if (pct) pct.textContent = (job.progress||0)+'%';
        if (msg) msg.textContent = job.message||'';
        const fill = document.getElementById('job-fill'); if(fill) fill.style.width = (job.progress||0)+'%';
        if((job.status||'')!=='running') setTimeout(()=>jb.classList.add('hidden'), 4000);
      }
      toast(`Job ${job.kind} ${job.status} (${job.progress}%)`, job.status==='error'?'danger':'info');
    }catch(err){console.error(err)}
  });

  evtSrc.addEventListener('arp.update', e=>{
    try{ const d = JSON.parse(e.data); toast('ARP: scan terminé', 'info'); window.refreshARP && window.refreshARP(d.result); }catch(e){console.error(e)}
  });

  evtSrc.addEventListener('preflight', e=>{
    try{ const d = JSON.parse(e.data); window.updatePreflight && window.updatePreflight(d.preflight); }catch(e){console.error(e)}
  });

  evtSrc.addEventListener('message', e=>{
    try{ const d = JSON.parse(e.data); if(d.toast) toast(d.toast.text,d.toast.type); }catch(e){console.error(e)}
  });

  evtSrc.onerror = function(){ console.warn('EventSource error'); };

  function applyDark(dark){
    if(dark) document.documentElement.classList.add('harmattan-dark');
    else document.documentElement.classList.remove('harmattan-dark');
    try{ localStorage.setItem('harmattan_dark', dark? '1':'0'); }catch(e){}
  }
  document.addEventListener('DOMContentLoaded', function(){
    const btn = document.getElementById('btn-toggle-dark');
    try{ const pref = localStorage.getItem('harmattan_dark'); if(pref==='1') applyDark(true); }
    catch(e){}
    if(btn) btn.addEventListener('click', function(){ applyDark(!document.documentElement.classList.contains('harmattan-dark')); });

    window.showHostDetail = function(ip){
      if(!ip) return;
      fetch('/api/hosts/'+encodeURIComponent(ip), {
        credentials: 'same-origin',
        headers: {'X-Harmattan-Token': window.HARMATTAN_TOKEN || ''}
      })
        .then(r=>r.json())
        .then(j=>{
          if(!j.ok) return toast('Erreur host detail','danger');
          const h = j.host || {};
          const drawer = document.getElementById('host-drawer');
          const body = document.getElementById('drawer-body');
          document.getElementById('drawer-title').textContent = h.hostname || h.ip || 'Hôte';
          body.innerHTML = '';
          const pre = document.createElement('pre'); pre.textContent = JSON.stringify(h, null, 2); body.appendChild(pre);
          drawer.setAttribute('aria-hidden','false'); drawer.classList.add('open'); document.getElementById('drawer-backdrop').classList.remove('hidden');
        }).catch(e=>{ console.error(e); toast('Erreur fetching host','danger'); });
    };

    const close = document.getElementById('btn-drawer-close');
    if(close) close.addEventListener('click', ()=>{ document.getElementById('host-drawer').classList.remove('open'); document.getElementById('host-drawer').setAttribute('aria-hidden','true'); document.getElementById('drawer-backdrop').classList.add('hidden'); });
  });

})();
