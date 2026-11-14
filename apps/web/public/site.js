const motionQuery = matchMedia("(prefers-reduced-motion: reduce)");
const compact = matchMedia("(max-width: 680px)").matches || (navigator.deviceMemory ?? 8) <= 2;
const root = document.documentElement;
const stage = document.querySelector(".stage");
const canvas = stage.querySelector("canvas");
const hud = Object.fromEntries([...document.querySelectorAll("[data-hud]")].map((el) => [el.dataset.hud, el]));

/* ---------- Sample scan (works without WebGL) ---------- */

const sampleButton = document.querySelector("#sample");
const sampleResult = document.querySelector("#sample-result");
sampleButton.addEventListener("click", async () => {
  sampleButton.disabled = true;
  sampleResult.hidden = false;
  sampleResult.textContent = "Scanning the synthetic repository…";
  try {
    const response = await fetch("/api/sample-scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
    if (!response.ok) throw new Error("failed");
    const report = await response.json();
    const title = document.createElement("strong");
    title.textContent = `Policy result: ${report.result} · ${report.findings} findings`;
    const location = document.createElement("code");
    location.textContent = `${report.finding.location}  ${report.finding.evidence}`;
    const text = document.createElement("p");
    text.textContent = `${report.summary} ${report.finding.remediation} `;
    const more = document.createElement("a");
    more.className = "link";
    more.href = "/scan#repository";
    more.textContent = "See the full report ↗";
    text.append(more);
    sampleResult.replaceChildren(title, location, text);
  } catch {
    sampleResult.textContent = "The sample could not run. Check that the local server is still running.";
  } finally {
    sampleButton.disabled = false;
  }
});

/* ---------- Text scramble ---------- */

const GLYPHS = "▚▞▖▗▘▝#%&/<>=+*01ABCDEFXYZ";
function prepareScramble(element) {
  if (element.dataset.ready) return;
  const text = element.textContent;
  element.dataset.ready = "1";
  element.textContent = "";
  const real = document.createElement("span");
  real.className = "sr-only";
  real.textContent = text;
  const shown = document.createElement("span");
  shown.setAttribute("aria-hidden", "true");
  shown.textContent = text;
  element.append(real, shown);
  element._scramble = { text, shown };
}
function scramble(element, duration = 900) {
  const { text, shown } = element._scramble ?? {};
  if (!shown || motionQuery.matches) return;
  const start = performance.now();
  const step = (now) => {
    const t = Math.min(1, (now - start) / duration);
    let out = "";
    for (let i = 0; i < text.length; i++) {
      const settle = i / text.length * 0.7 + 0.3;
      out += text[i] === " " || t >= settle ? text[i] : GLYPHS[(Math.random() * GLYPHS.length) | 0];
    }
    shown.textContent = out;
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}
const scrambles = [...document.querySelectorAll("[data-scramble]")];
scrambles.forEach(prepareScramble);

/* ---------- Chapters and reveal ---------- */

const sections = [...document.querySelectorAll("[data-shape]")];
const navLinks = [...document.querySelectorAll("nav a")];
hud.total.textContent = String(sections.length - 1).padStart(2, "0");

if (!motionQuery.matches) root.classList.add("reveal-ready");
const revealObserver = new IntersectionObserver((entries) => {
  for (const entry of entries) {
    if (!entry.isIntersecting) continue;
    entry.target.classList.add("is-visible");
    entry.target.querySelectorAll("[data-scramble]").forEach((el, index) => setTimeout(() => scramble(el), 120 + index * 180));
    revealObserver.unobserve(entry.target);
  }
}, { threshold: 0.25 });
sections.forEach((section) => revealObserver.observe(section));

let layout = [];
function measure() {
  layout = sections.map((section) => {
    const rect = section.getBoundingClientRect();
    const top = rect.top + scrollY;
    return {
      mid: top + rect.height / 2, top, height: rect.height, el: section,
      shape: Number(section.dataset.shape), case: Number(section.dataset.case ?? 0), prism: Number(section.dataset.prism ?? 0),
    };
  });
}
measure();
new ResizeObserver(measure).observe(document.body);
addEventListener("load", measure);

const smoothstep = (a, b, x) => { const t = Math.min(1, Math.max(0, (x - a) / (b - a))); return t * t * (3 - 2 * t); };
const lerp = (a, b, t) => a + (b - a) * t;

function chapterState(scroll) {
  const center = scroll + innerHeight * 0.5;
  if (!layout.length) return { a: layout[0], b: layout[0], f: 0, index: 0 };
  if (center <= layout[0].mid) return { a: layout[0], b: layout[0], f: 0, index: 0 };
  for (let i = 0; i < layout.length - 1; i++) {
    if (center < layout[i + 1].mid) {
      const f = smoothstep(0.28, 0.72, (center - layout[i].mid) / (layout[i + 1].mid - layout[i].mid));
      // Once a transition completes, report the destination alone so "holding" a chapter is exact.
      if (f >= 1) return { a: layout[i + 1], b: layout[i + 1], f: 0, index: i + 1 };
      return { a: layout[i], b: layout[i + 1], f, index: f > 0.5 ? i + 1 : i };
    }
  }
  const last = layout[layout.length - 1];
  return { a: last, b: last, f: 0, index: layout.length - 1 };
}

/* ---------- Footer hover forms ---------- */

const footer = document.querySelector(".footer");
const footerShape = Number(footer.dataset.shape);
/** Active footer morph: from one formation to another, independent of scroll. */
let morph = null;
function morphTo(next) {
  const current = morph ? (morph.mix > 0.5 ? morph.to : morph.from) : footerShape;
  if (morph?.to === next) return;
  morph = { from: current, to: next, mix: current === next ? 1 : 0 };
}
for (const link of document.querySelectorAll("[data-form]")) {
  const enter = () => morphTo(Number(link.dataset.form));
  const leave = () => morphTo(footerShape);
  link.addEventListener("pointerenter", enter);
  link.addEventListener("focus", enter);
  link.addEventListener("pointerleave", leave);
  link.addEventListener("blur", leave);
}

/* ---------- Scene loop ---------- */

let scene = null;
let smoothScroll = scrollY;
let lastScroll = scrollY;
let lastFrame = performance.now();
let loop = 0;
let activeIndex = -1;
let frameAvg = 16;

function tick(now) {
  loop = requestAnimationFrame(tick);
  const dt = Math.min(0.05, (now - lastFrame) / 1000);
  lastFrame = now;
  smoothScroll += (scrollY - smoothScroll) * Math.min(1, dt * 9);
  const velocity = (smoothScroll - lastScroll) / Math.max(dt, 0.001);
  lastScroll = smoothScroll;

  const chapter = chapterState(smoothScroll);
  const s = scene.state;
  const inFooter = chapter.a.el === footer && chapter.b.el === footer;
  if (inFooter && morph) {
    morph.mix = Math.min(1, morph.mix + dt * 1.4);
    s.shapeA = morph.from;
    s.shapeB = morph.to;
    s.mix = morph.mix;
  } else {
    if (!inFooter) morph = null;
    s.shapeA = chapter.a.shape;
    s.shapeB = chapter.b.shape;
    s.mix = chapter.f;
  }
  s.caseBlend = lerp(chapter.a.case, chapter.b.case, chapter.f);
  s.prismBlend = lerp(chapter.a.prism, chapter.b.prism, chapter.f);
  const wave = Math.sin(Math.PI * s.mix);
  const speed = Math.min(1, Math.abs(velocity) / 2400);
  s.energy = lerp(s.energy, wave * 0.9 + speed * 0.7, Math.min(1, dt * 6));
  s.aberration = lerp(s.aberration, wave * 0.7 + speed * 1.4, Math.min(1, dt * 6));

  if (chapter.index !== activeIndex) {
    activeIndex = chapter.index;
    hud.chapter.textContent = String(activeIndex).padStart(2, "0");
    const id = layout[activeIndex]?.el.id;
    navLinks.forEach((link) => link.classList.toggle("is-current", link.hash === `#${id}`));
  }
  const max = document.documentElement.scrollHeight - innerHeight;
  hud.progress.style.width = `${(max > 0 ? smoothScroll / max : 0) * 100}%`;
}

addEventListener("pointermove", (event) => {
  if (!scene) return;
  const x = (event.clientX / innerWidth) * 2 - 1;
  const y = 1 - (event.clientY / innerHeight) * 2;
  scene.pointer(x, y, event.pointerType !== "touch" || event.pressure > 0);
  hud.pointer.textContent = `${x >= 0 ? "+" : ""}${x.toFixed(3)} ${y >= 0 ? "+" : ""}${y.toFixed(3)}`;
}, { passive: true });
document.addEventListener("pointerleave", () => scene?.pointer(0, 0, false));
addEventListener("pointerup", (event) => { if (event.pointerType === "touch") scene?.pointer(0, 0, false); });

/* ---------- Boot ---------- */

const boot = document.querySelector(".boot");
const bootSteps = Object.fromEntries([...boot.querySelectorAll("[data-step]")].map((el) => [el.dataset.step, el]));
const bootCount = boot.querySelector(".boot__count");
const bootBar = boot.querySelector(".boot__bar span");
let bootProgress = 0;

function bootStep(name, detail) {
  const el = bootSteps[name];
  if (!el) return;
  el.classList.add("is-ok");
  el.querySelector("i").textContent = detail ?? "ok";
  bootProgress += 25;
  bootCount.textContent = String(bootProgress).padStart(3, "0");
  bootBar.style.width = `${bootProgress}%`;
}
function finishBoot() {
  boot.classList.add("is-done");
  scrambles.filter((el) => el.closest(".hero")).forEach((el, index) => setTimeout(() => scramble(el, 1100), 200 + index * 260));
}
const skip = () => finishBoot();
addEventListener("keydown", skip, { once: true });
boot.addEventListener("pointerdown", skip, { once: true });

async function startMotion() {
  if (motionQuery.matches) {
    scene?.pause();
    cancelAnimationFrame(loop);
    stage.classList.remove("is-live");
    return;
  }
  try {
    const { startScene } = await import("./scene.js");
    if (motionQuery.matches) return;
    scene ??= startScene(canvas, { compact });
    scene.resume();
    stage.classList.add("is-live");
    hud.count.textContent = scene.count.toLocaleString("en");
    cancelAnimationFrame(loop);
    lastFrame = performance.now();
    loop = requestAnimationFrame(tick);
    canvas.addEventListener("scene:frame", (event) => {
      frameAvg = frameAvg * 0.95 + event.detail.dt * 1000 * 0.05;
      hud.frame.textContent = `${frameAvg.toFixed(1)} ms`;
    });
    canvas.addEventListener("scene:lost", () => { stage.classList.remove("is-live"); cancelAnimationFrame(loop); }, { once: true });
    return `ok · ${scene.count.toLocaleString("en")} particles`;
  } catch (error) {
    stage.classList.remove("is-live");
    return `static poster (${error instanceof Error ? error.message : "WebGL unavailable"})`;
  }
}

(async () => {
  if (motionQuery.matches) {
    boot.classList.add("is-done");
    return;
  }
  bootSteps.policy.classList.add("is-running");
  bootStep("policy");
  const keys = fetch("/.well-known/signalward-keys.json").then((r) => r.json()).then((set) => set.keys?.[0]?.kid ?? "none").catch(() => "unavailable");
  bootSteps.keys.classList.add("is-running");
  bootStep("keys", await keys);
  bootSteps.fonts.classList.add("is-running");
  await Promise.race([document.fonts.ready, new Promise((resolve) => setTimeout(resolve, 1500))]);
  bootStep("fonts", document.fonts.check("16px 'Mona Sans'") ? "ok" : "fallback");
  bootSteps.scene.classList.add("is-running");
  bootStep("scene", await startMotion());
  setTimeout(finishBoot, 450);
})();

motionQuery.addEventListener("change", () => {
  if (motionQuery.matches) {
    startMotion();
    root.classList.remove("reveal-ready");
  } else {
    startMotion();
  }
});
document.addEventListener("visibilitychange", () => {
  if (!scene) return;
  if (document.hidden) cancelAnimationFrame(loop);
  else if (!motionQuery.matches) { lastFrame = performance.now(); loop = requestAnimationFrame(tick); }
});
