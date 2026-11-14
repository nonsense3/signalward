import { $, $$, api, h, init, navigate, reducedMotion, reportError, setFieldError, currentTheme, VERDICT } from "./ui.js";
import { mountFooterLogo } from "./footer-logo.js";

init();

const footerWord = $("[data-logo]");
if (footerWord) mountFooterLogo(footerWord);

const stage = $(".stage");
const canvas = $("canvas", stage);
const heroCard = $('[data-frame="hero"]');
const dock = $('[data-frame="dock"]');
const dockLabel = $('[data-hud="label"]');
const chapters = $$(".chapter");
const hud = { count: $('[data-hud="count"]'), frame: $('[data-hud="frame"]') };

/* ---------- CTA ---------- */
$("#cta-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const input = event.currentTarget.elements.url;
  const value = input.value.trim();
  if (!value) return setFieldError(input, "Paste a link or domain first.");
  if (value.length > 2048) return setFieldError(input, "That link is longer than 2048 characters.");
  navigate(`/scan?url=${encodeURIComponent(value)}#url`);
});

/* ---------- Statement: words light up as it scrolls through ---------- */
const statement = $("[data-words]");
const words = statement.textContent.trim().split(/\s+/).map((word) => h("span", { class: "w", text: word }));
statement.replaceChildren(...words.flatMap((word, index) => (index ? [" ", word] : [word])));
statement.setAttribute("aria-label", statement.textContent);
function updateWords() {
  const rect = statement.getBoundingClientRect();
  const progress = Math.min(1, Math.max(0, (innerHeight * 0.85 - rect.top) / (rect.height + innerHeight * 0.35)));
  const lit = Math.round(progress * words.length);
  words.forEach((word, index) => word.classList.toggle("on", index < lit));
}

/* ---------- Frame tracking: the canvas lives in the hero card, then in the observatory dock ---------- */
const smooth = (current, target, rate, dt) => current + (target - current) * Math.min(1, dt * rate);
function frameRect() {
  const d = dock.getBoundingClientRect();
  if (d.top < innerHeight && d.bottom > 0) return { rect: d, where: "dock" };
  return { rect: heroCard.getBoundingClientRect(), where: "hero" };
}
function applyClip(rect) {
  const s = stage.style;
  s.setProperty("--ct", `${Math.max(-2, rect.top)}px`);
  s.setProperty("--cl", `${rect.left}px`);
  s.setProperty("--cr", `${innerWidth - rect.right}px`);
  s.setProperty("--cb", `${innerHeight - rect.bottom}px`);
}

function activeChapter() {
  let best = null, bestDistance = Infinity;
  for (const chapter of chapters) {
    const rect = chapter.getBoundingClientRect();
    const distance = Math.abs(rect.top + rect.height / 2 - innerHeight / 2);
    if (distance < bestDistance && rect.bottom > 0 && rect.top < innerHeight) { best = chapter; bestDistance = distance; }
  }
  return best;
}

let scene = null;
let shown = 0, target = 0;
let lastScroll = scrollY, lastFrame = performance.now(), frameAvg = 16, currentChapter = null;

function tick(now) {
  requestAnimationFrame(tick);
  const dt = Math.min(0.05, (now - lastFrame) / 1000);
  lastFrame = now;
  updateWords();
  const { rect, where } = frameRect();
  applyClip(rect);

  const chapter = where === "dock" ? activeChapter() : null;
  if (chapter !== currentChapter) {
    currentChapter = chapter;
    chapters.forEach((item) => item.classList.toggle("is-active", item === chapter));
    if (chapter) dockLabel.textContent = chapter.dataset.label;
  }
  if (!scene) return;

  const s = scene.state;
  const visible = rect.bottom > 0 && rect.top < innerHeight && rect.width > 4;
  if (!visible) return;
  s.clip = { x: rect.left, y: rect.top, w: rect.width, h: rect.height };
  const wide = innerWidth > 820;
  let cx = ((rect.left + rect.width / 2) / innerWidth) * 2 - 1;
  let cy = 1 - ((rect.top + rect.height / 2) / innerHeight) * 2;
  const hh = Math.min(1, rect.height / innerHeight);
  if (where === "hero") {
    if (wide) cx += 0.32 * (rect.width / innerWidth);
    else cy += 0.22;
  } else if (wide) {
    // The chapter card sits bottom-left in the frame; keep the formation clear of it.
    cx += 0.24 * (rect.width / innerWidth);
  }
  s.view.cx = smooth(s.view.cx, cx, 14, dt);
  s.view.cy = smooth(s.view.cy, cy, 14, dt);
  s.view.h = smooth(s.view.h, where === "hero" ? hh : hh * 0.92, 6, dt);

  // Formation: hero keeps the spectral stream; each chapter has its own shape. Morphs run on time, not scroll.
  const next = chapter ? Number(chapter.dataset.shape) : 0;
  if (next !== target) {
    shown = s.mix > 0.5 ? s.shapeB : s.shapeA;
    target = next;
    s.shapeA = shown;
    s.shapeB = target;
    s.mix = 0;
  }
  s.mix = Math.min(1, s.mix + dt / 1.3);
  s.prismBlend = smooth(s.prismBlend, where === "hero" ? 1 : 0, 3, dt);
  // The glass case crowds the small mobile dock, so it only appears on wide screens.
  s.caseBlend = smooth(s.caseBlend, where === "dock" && wide ? 1 : 0, 3, dt);
  const velocity = Math.abs(scrollY - lastScroll) / Math.max(dt, 0.001);
  lastScroll = scrollY;
  const wave = Math.sin(Math.PI * s.mix);
  const speed = Math.min(1, velocity / 3000);
  s.energy = smooth(s.energy, wave * 0.5 + speed * 0.3, 5, dt);
  s.aberration = smooth(s.aberration, wave * 0.4 + speed * 0.7, 5, dt);
}
requestAnimationFrame(tick);

addEventListener("pointermove", (event) => {
  if (!scene) return;
  const c = scene.state.clip;
  const inside = c && event.clientX >= c.x && event.clientX <= c.x + c.w && event.clientY >= c.y && event.clientY <= c.y + c.h;
  scene.pointer((event.clientX / innerWidth) * 2 - 1, 1 - (event.clientY / innerHeight) * 2, Boolean(inside) && (event.pointerType !== "touch" || event.pressure > 0));
}, { passive: true });
document.addEventListener("pointerleave", () => scene?.pointer(0, 0, false));

async function startMotion() {
  if (reducedMotion()) {
    scene?.pause();
    stage.classList.remove("is-live");
    return;
  }
  try {
    const { startScene } = await import("./scene.js");
    const compact = matchMedia("(max-width: 680px)").matches || (navigator.deviceMemory ?? 8) <= 2;
    scene ??= startScene(canvas, { compact, light: currentTheme() === "light" });
    scene.resume();
    stage.classList.add("is-live");
    hud.count.textContent = scene.count.toLocaleString("en");
    canvas.addEventListener("scene:frame", (event) => {
      frameAvg = frameAvg * 0.94 + event.detail.dt * 1000 * 0.06;
      hud.frame.textContent = `${frameAvg.toFixed(1)} ms`;
    });
    canvas.addEventListener("scene:lost", () => stage.classList.remove("is-live"), { once: true });
  } catch (error) {
    console.warn("Scene unavailable, showing the static poster:", error instanceof Error ? error.message : error);
    stage.classList.remove("is-live");
  }
}
addEventListener("themechange", (event) => scene?.setLight(event.detail === "light"));
matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", startMotion);
startMotion();
