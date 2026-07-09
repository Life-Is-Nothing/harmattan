// HARMATTAN — effet de vent en fond de la vue topologie.
// Volontairement léger (peu de particules) pour rester fluide sur matériel modeste.
(function () {
  const canvas = document.getElementById("wind-canvas");
  if (!canvas) return;
  const ctx = canvas.getContext("2d");
  let particles = [];
  let raf = null;

  function resize() {
    canvas.width = canvas.clientWidth;
    canvas.height = canvas.clientHeight;
  }

  function spawn(n) {
    particles = [];
    for (let i = 0; i < n; i++) {
      particles.push({
        x: Math.random() * canvas.width,
        y: Math.random() * canvas.height,
        len: 20 + Math.random() * 60,
        speed: 0.6 + Math.random() * 1.8,
        opacity: 0.05 + Math.random() * 0.12,
      });
    }
  }

  function tick() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.strokeStyle = "#f77f00";
    for (const p of particles) {
      ctx.globalAlpha = p.opacity;
      ctx.beginPath();
      ctx.moveTo(p.x, p.y);
      ctx.lineTo(p.x - p.len, p.y + p.len * 0.08);
      ctx.stroke();
      p.x += p.speed;
      if (p.x - p.len > canvas.width) {
        p.x = -p.len;
        p.y = Math.random() * canvas.height;
      }
    }
    raf = requestAnimationFrame(tick);
  }

  function start() {
    resize();
    spawn(26); // volontairement peu nombreux
    if (!raf) tick();
  }

  function stop() {
    if (raf) cancelAnimationFrame(raf);
    raf = null;
  }

  window.addEventListener("resize", resize);
  window.HarmattanWind = { start, stop };

  if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    start();
  }
})();
