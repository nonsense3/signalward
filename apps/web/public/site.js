import { $, $$, api, h, init, navigate, reducedMotion, reportError, setFieldError, currentTheme, VERDICT } from "./ui.js";
import { mountFooterLogo } from "./footer-logo.js";

init();

const footerWord = $("[data-logo]");
if (footerWord) mountFooterLogo(footerWord);

const stage = $(".stage");
const canvas = $("canvas", stage);
const heroCard = $('[data-frame="hero"]');

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

/* ---------- Hero canvas ---------- */
const smooth = (current, target, rate, dt) => current + (target - current) * Math.min(1, dt * rate);
function applyClip(rect) {
  const s = stage.style;
  s.setProperty("--ct", `${Math.max(-2, rect.top)}px`);
  s.setProperty("--cl", `${rect.left}px`);
  s.setProperty("--cr", `${innerWidth - rect.right}px`);
  s.setProperty("--cb", `${innerHeight - rect.bottom}px`);
}

let scene = null;
let lastScroll = scrollY, lastFrame = performance.now(), frameAvg = 16;

function tick(now) {
  requestAnimationFrame(tick);
  const dt = Math.min(0.05, (now - lastFrame) / 1000);
  lastFrame = now;
  updateWords();
  const rect = heroCard.getBoundingClientRect();
  applyClip(rect);
  if (!scene) return;

  const s = scene.state;
  const visible = rect.bottom > 0 && rect.top < innerHeight && rect.width > 4;
  if (!visible) return;
  s.clip = { x: rect.left, y: rect.top, w: rect.width, h: rect.height };
  const wide = innerWidth > 820;
  let cx = ((rect.left + rect.width / 2) / innerWidth) * 2 - 1;
  let cy = 1 - ((rect.top + rect.height / 2) / innerHeight) * 2;
  const hh = Math.min(1, rect.height / innerHeight);
  if (wide) cx += 0.32 * (rect.width / innerWidth);
  else cy += 0.22;
  s.view.cx = smooth(s.view.cx, cx, 14, dt);
  s.view.cy = smooth(s.view.cy, cy, 14, dt);
  s.view.h = smooth(s.view.h, hh, 6, dt);

  const velocity = Math.abs(scrollY - lastScroll) / Math.max(dt, 0.001);
  lastScroll = scrollY;
  const speed = Math.min(1, velocity / 3000);
  s.energy = smooth(s.energy, speed * 0.2, 5, dt);
  s.aberration = smooth(s.aberration, speed * 0.3, 5, dt);
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
  // The poster only appears when there is no live scene (reduced motion, no WebGL2, lost context).
  // While the scene loads the frame shows its plain gradient, so nothing static lingers on refresh.
  const showPoster = () => {
    stage.classList.remove("is-live");
    stage.classList.add("is-static");
  };
  if (reducedMotion()) {
    scene?.pause();
    return showPoster();
  }
  try {
    const { startScene } = await import("./scene.js");
    const compact = matchMedia("(max-width: 680px)").matches || (navigator.deviceMemory ?? 8) <= 2;
    const first = !scene;
    scene ??= startScene(canvas, { compact, prisms: false, light: currentTheme() === "light" });
    scene.resume();
    stage.classList.remove("is-static");
    if (first) {
      // Reveal on the first drawn frame, never on a blank (black) canvas.
      canvas.addEventListener("scene:frame", () => stage.classList.add("is-live"), { once: true });
      canvas.addEventListener("scene:lost", showPoster, { once: true });
    } else {
      stage.classList.add("is-live");
    }
  } catch (error) {
    console.warn("Scene unavailable, showing the static poster:", error instanceof Error ? error.message : error);
    showPoster();
  }
}
addEventListener("themechange", (event) => scene?.setLight(event.detail === "light"));
matchMedia("(prefers-reduced-motion: reduce)").addEventListener("change", startMotion);
startMotion();
