// Minimal toast system used by live.js
window.Toast = (function(){
  const root = document.getElementById('toast-root');
  function push({text='', type='info', timeout=4000}){
    if(!root) return;
    const el = document.createElement('div');
    el.className = 'toast '+type;
    el.textContent = text;
    root.appendChild(el);
    setTimeout(()=>{ el.classList.add('visible'); }, 10);
    setTimeout(()=>{ el.classList.remove('visible'); setTimeout(()=>el.remove(),300); }, timeout);
  }
  return { push };
})();
