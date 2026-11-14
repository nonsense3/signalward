/**
 * Footer wordmark as a particle field. The text is rasterised offscreen, sampled into particles that
 * spring to their letterform, drift gently at rest, and are pushed aside by the cursor before settling.
 * 2D canvas only; respects reduced motion (falls back to plain text).
 */
export function mountFooterLogo(container, { text = "SignalWard" } = {}) {
  if (matchMedia("(prefers-reduced-motion: reduce)").matches) {
    container.textContent = text;
    container.classList.add("is-static");
    return;
  }
  const canvas = container.querySelector("canvas") ?? container.appendChild(document.createElement("canvas"));
  canvas.setAttribute("aria-hidden", "true");
  const ctx = canvas.getContext("2d", { alpha: true });
  const compact = matchMedia("(max-width: 680px)").matches;

  let particles = [];
  let w = 0, h = 0, dpr = 1, raf = 0, active = false, ready = false;
  const pointer = { x: -9999, y: -9999, strength: 0 };

  const palette = () => {
    const cs = getComputedStyle(document.documentElement);
    return { ink: cs.getPropertyValue("--footer-ink").trim() || "#f4f2ec", accent: cs.getPropertyValue("--accent").trim() || "#9b8cff" };
  };
  let colors = palette();
  addEventListener("themechange", () => (colors = palette()));

  function build() {
    const width = container.clientWidth;
    if (!width) return;
    dpr = Math.min(devicePixelRatio || 1, 2);
    w = width;
    h = Math.round(width * (compact ? 0.22 : 0.17));
    container.style.height = `${h}px`;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h * dpr);
    canvas.style.width = `${w}px`;
    canvas.style.height = `${h}px`;

    const off = document.createElement("canvas");
    off.width = Math.min(compact ? 720 : 1500, Math.round(w));
    off.height = Math.round((off.width * h) / w);
    const octx = off.getContext("2d");
    let size = off.height * 0.84;
    octx.font = `650 ${size}px "Hubot Sans", "Mona Sans", sans-serif`;
    const measured = octx.measureText(text).width;
    size *= Math.min(1, (off.width * 0.98) / measured);
    octx.font = `650 ${size}px "Hubot Sans", "Mona Sans", sans-serif`;
    octx.textAlign = "center";
    octx.textBaseline = "middle";
    octx.fillStyle = "#fff";
    octx.fillText(text, off.width / 2, off.height / 2 + size * 0.02);

    const data = octx.getImageData(0, 0, off.width, off.height).data;
    const step = off.width > 1000 ? 5 : 4;
    const sx = w / off.width, sy = h / off.height;
    const next = [];
    for (let y = 0; y < off.height; y += step) {
      for (let x = 0; x < off.width; x += step) {
        if (data[(y * off.width + x) * 4 + 3] > 130) {
          const reused = next.length < particles.length ? particles[next.length] : { x: Math.random() * w, y: h * (Math.random() < 0.5 ? -0.2 : 1.2), vx: 0, vy: 0 };
          reused.tx = x * sx;
          reused.ty = y * sy;
          reused.rand = reused.rand ?? Math.random();
          next.push(reused);
        }
      }
    }
    particles = next;
    ready = true;
  }

  function frame() {
    raf = requestAnimationFrame(frame);
    if (!ready) return;
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const t = performance.now() * 0.001;
    pointer.strength *= 0.94;
    const reach = (compact ? 90 : 130) * (1 + pointer.strength);
    const reach2 = reach * reach;
    for (const p of particles) {
      const idleX = Math.sin(t * 0.7 + p.rand * 21) * 0.5;
      const idleY = Math.cos(t * 0.6 + p.rand * 17) * 0.5;
      let fx = (p.tx + idleX - p.x) * 0.055;
      let fy = (p.ty + idleY - p.y) * 0.055;
      const dx = p.x - pointer.x, dy = p.y - pointer.y;
      const d2 = dx * dx + dy * dy;
      if (d2 < reach2) {
        const d = Math.sqrt(d2) || 1;
        const push = (1 - d / reach) * (3.5 + pointer.strength * 9);
        fx += (dx / d) * push;
        fy += (dy / d) * push;
      }
      p.vx = (p.vx + fx) * 0.84;
      p.vy = (p.vy + fy) * 0.84;
      p.x += p.vx;
      p.y += p.vy;
      const speed = Math.min(1, (p.vx * p.vx + p.vy * p.vy) / 7);
      ctx.globalAlpha = 0.6 + speed * 0.4;
      ctx.fillStyle = speed > 0.18 ? colors.accent : colors.ink;
      const s = 1.2 + speed * 1.5;
      ctx.fillRect(p.x, p.y, s, s);
    }
    ctx.globalAlpha = 1;
  }

  function setPointer(event) {
    const rect = canvas.getBoundingClientRect();
    const inside = event.clientX >= rect.left && event.clientX <= rect.right && event.clientY >= rect.top && event.clientY <= rect.bottom;
    pointer.x = event.clientX - rect.left;
    pointer.y = event.clientY - rect.top;
    if (inside) pointer.strength = Math.min(1.4, pointer.strength + 0.08);
  }
  addEventListener("pointermove", setPointer, { passive: true });
  addEventListener("pointerdown", (event) => { setPointer(event); pointer.strength = 1.4; }, { passive: true });

  const start = () => { if (!raf) { raf = requestAnimationFrame(frame); } };
  const stop = () => { if (raf) { cancelAnimationFrame(raf); raf = 0; } };
  build();
  new ResizeObserver(() => build()).observe(container);
  document.fonts?.ready.then(build);
  new IntersectionObserver(([entry]) => {
    active = entry.isIntersecting;
    if (active && !document.hidden) start();
    else stop();
  }, { rootMargin: "100px" }).observe(container);
  document.addEventListener("visibilitychange", () => (document.hidden || !active ? stop() : start()));
}
