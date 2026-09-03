// Socket.IO client for HARMATTAN (fallback to SSE exists in live.js)
(function(){
  if(!window.io) return; // socket.io client not loaded
  const token = window.HARMATTAN_TOKEN || '';
  const socket = io('/live', { auth: { token: token } });

  socket.on('connect', ()=>{ console.debug('ws connected'); });
  socket.on('live_event', (ev)=>{
    try{
      // mimic SSE event types
      const type = ev.type || 'message';
      if(type === 'job.update'){
        window.dispatchEvent(new CustomEvent('harmattan.job', {detail: ev}));
        window.Toast && window.Toast.push({text:`Job ${ev.job?.kind} ${ev.job?.status}`, type: ev.job?.status==='error'?'danger':'info'});
      } else if(type === 'arp.update'){
        window.Toast && window.Toast.push({text:'ARP: scan terminé', type:'info'});
        window.refreshARP && window.refreshARP(ev.result);
      } else if(type === 'preflight'){
        window.updatePreflight && window.updatePreflight(ev.preflight);
      } else {
        // generic
        if(ev.toast) window.Toast && window.Toast.push({text:ev.toast.text, type:ev.toast.type});
      }
    }catch(e){ console.error(e); }
  });

  socket.on('disconnect', ()=>{ console.debug('ws disconnected'); });
})();
