/* Shared client runtime: DOM helper, API client with strict error mapping, toasts, header chrome,
   theme, page transitions and reveal motion. Every server value is rendered as text, never HTML. */

export function h(tag, props = {}, ...children) {
  const el = document.createElementNS(tag === "svg" || props.svg ? "http://www.w3.org/2000/svg" : "http://www.w3.org/1999/xhtml", tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false || key === "svg") continue;
    if (key === "class") el.setAttribute("class", value);
    else if (key === "text") el.textContent = value;
    else if (key === "dataset") Object.assign(el.dataset, value);
    else if (key === "css") for (const [prop, v] of Object.entries(value)) el.style.setProperty(prop, v);
    else if (key.startsWith("on") && typeof value === "function") el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return el;
}
export const $ = (selector, root = document) => root.querySelector(selector);
export const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
export const reducedMotion = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

/* ---------------------------------------------------------------- API client */

export class ApiError extends Error {
  constructor({ status = 0, code = "ERROR", message = "Request failed.", field, requestId, retryAfter } = {}) {
    super(message);
    Object.assign(this, { status, code, field, requestId, retryAfter });
  }
}

export async function api(path, { method = "GET", body, timeout = 45_000, auth = "redirect" } = {}) {
  let response;
  try {
    response = await fetch(path, {
      method,
      credentials: "same-origin",
      headers: body === undefined ? { Accept: "application/json" } : { "Content-Type": "application/json", Accept: "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      signal: AbortSignal.timeout(timeout),
    });
  } catch (error) {
    if (error?.name === "TimeoutError") throw new ApiError({ code: "TIMEOUT", message: "The server took too long to answer. Try again." });
    throw new ApiError({ code: "NETWORK_ERROR", message: "Can't reach SignalWard. Check your connection and that the server is running." });
  }
  let data = null;
  try {
    data = await response.json();
  } catch {
    if (!response.ok) throw new ApiError({ status: response.status, code: "BAD_RESPONSE", message: `The server returned an unexpected response (${response.status}).` });
  }
  if (!response.ok) {
    const error = new ApiError({ status: response.status, ...(data?.error ?? {}), retryAfter: Number(response.headers.get("Retry-After")) || undefined });
    if (response.status === 401 && auth === "redirect") {
      toast("info", "Session ended", "Sign in again to continue.");
      setTimeout(() => navigate(`/auth?next=${encodeURIComponent(location.pathname + location.search + location.hash)}`), 900);
    }
    throw error;
  }
  return data;
}

const TITLES = {
  NETWORK_ERROR: "Connection problem", TIMEOUT: "Request timed out", BAD_RESPONSE: "Unexpected response", RATE_LIMITED: "Slow down",
  AUTH_INVALID_CREDENTIALS: "Sign-in failed", AUTH_EMAIL_TAKEN: "Email already registered", AUTH_WEAK_PASSWORD: "Choose a stronger password",
  AUTH_EMAIL_NOT_CONFIRMED: "Confirm your email", AUTH_SESSION_EXPIRED: "Session ended", AUTH_REQUIRED: "Sign in required",
  AUTH_UNAVAILABLE: "Sign-in service unavailable", AUTH_LOCKED: "Account temporarily locked", AUTH_RECOVERY_UNAVAILABLE: "Reset unavailable",
  AUTH_SIGNUP_DISABLED: "Sign-up closed", AUTH_SAME_PASSWORD: "Same password", DATABASE_NOT_MIGRATED: "Database not set up",
  DATABASE_UNAVAILABLE: "Database unavailable", DATABASE_ERROR: "Database error", PAYLOAD_TOO_LARGE: "Too large to scan",
  CROSS_ORIGIN: "Request blocked", INTERNAL: "Something went wrong", NOT_FOUND: "Not found", URL_INVALID: "Check the link",
  UNSUPPORTED_SCHEME: "Unsupported link", HOST_NOT_PUBLIC: "Private address", NO_FILES: "Nothing selected",
  FIELD_REQUIRED: "Missing information", FIELD_INVALID: "Check your input", FIELD_TOO_LONG: "Too long", FIELD_TOO_SHORT: "Too short",
};

export function severityOf(error) {
  if (!(error instanceof ApiError)) return "error";
  if (error.status === 0 || error.status >= 500 || error.status === 401 || error.status === 403) return "error";
  return "warning";
}

/** Show an error inline on the matching form field when possible, otherwise as a toast. */
export function reportError(error, form) {
  const apiError = error instanceof ApiError ? error : new ApiError({ code: "CLIENT_ERROR", message: error?.message || "Something went wrong in the browser." });
  if (apiError.status === 401 && apiError.code === "AUTH_REQUIRED") return;
  const input = form && apiError.field ? form.querySelector(`[name="${CSS.escape(apiError.field)}"]`) : null;
  if (input) {
    setFieldError(input, apiError.message);
    input.focus();
    return;
  }
  toast(severityOf(apiError), TITLES[apiError.code] ?? "Request failed", apiError.message, apiError.requestId);
}

export function setFieldError(input, message) {
  const field = input.closest(".field");
  input.setAttribute("aria-invalid", "true");
  let note = field?.querySelector(".field__error");
  if (!note && field) {
    note = h("p", { class: "field__error", id: `${input.name || "field"}-error`, role: "alert" });
    field.append(note);
    input.setAttribute("aria-describedby", note.id);
  }
  if (note) note.textContent = message;
}

export function clearErrors(form) {
  for (const input of $$("[aria-invalid]", form)) input.removeAttribute("aria-invalid");
  for (const note of $$(".field__error", form)) note.remove();
}
document.addEventListener("input", (event) => {
  const input = event.target;
  if (input?.getAttribute?.("aria-invalid") === "true") {
    input.removeAttribute("aria-invalid");
    input.closest(".field")?.querySelector(".field__error")?.remove();
  }
});

/* ---------------------------------------------------------------- Toasts */

let toastHost;
const ICON = { error: "!", warning: "!", success: "✓", info: "i" };
export function toast(kind, title, message, requestId) {
  toastHost ??= document.body.appendChild(h("div", { class: "toasts", "aria-live": "polite" }));
  const close = () => {
    item.classList.add("is-leaving");
    setTimeout(() => item.remove(), 350);
  };
  const item = h("div", { class: `toast toast--${kind}`, role: kind === "error" ? "alert" : "status" },
    h("span", { class: "toast__icon", "aria-hidden": "true", text: ICON[kind] ?? "i" }),
    h("b", { text: title }),
    h("button", { class: "toast__close", type: "button", "aria-label": "Dismiss", text: "×", onclick: close }),
    message ? h("p", { text: message }) : null,
    requestId ? h("small", { text: `Ref ${requestId}` }) : null);
  toastHost.append(item);
  while (toastHost.children.length > 4) toastHost.firstElementChild.remove();
  setTimeout(close, kind === "error" ? 9000 : 5500);
  return item;
}

addEventListener("unhandledrejection", (event) => {
  if (event.reason instanceof ApiError) {
    reportError(event.reason);
    event.preventDefault();
  }
});

/* ---------------------------------------------------------------- Theme */

export function setTheme(theme) {
  document.documentElement.dataset.theme = theme;
  try { localStorage.setItem("sw-theme", theme); } catch {}
  for (const meta of $$('meta[name="theme-color"]')) meta.content = theme === "dark" ? "#07080b" : "#e9eaef";
  dispatchEvent(new CustomEvent("themechange", { detail: theme }));
}
export const currentTheme = () => document.documentElement.dataset.theme ?? "light";

/* ---------------------------------------------------------------- Navigation curtain */

const curtain = document.body.appendChild(h("div", { class: "curtain", "aria-hidden": "true" }));
export function navigate(href) {
  if (reducedMotion()) return void (location.href = href);
  try { sessionStorage.setItem("sw-transition", "1"); } catch {}
  curtain.classList.remove("is-revealing");
  void curtain.offsetWidth;
  curtain.classList.add("is-covering");
  setTimeout(() => (location.href = href), 560);
}
function revealPage() {
  if (document.documentElement.dataset.transition !== "in") return;
  requestAnimationFrame(() => {
    curtain.classList.add("is-revealing");
    delete document.documentElement.dataset.transition;
    setTimeout(() => curtain.classList.remove("is-revealing"), 760);
  });
}
addEventListener("pageshow", (event) => {
  if (event.persisted) curtain.classList.remove("is-covering", "is-revealing");
});
document.addEventListener("click", (event) => {
  const link = event.target.closest?.("a[href]");
  if (!link || event.defaultPrevented || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  if (link.target || link.hasAttribute("download") || link.dataset.noTransition !== undefined) return;
  const url = new URL(link.href, location.href);
  if (url.origin !== location.origin || url.pathname.startsWith("/api/") || url.pathname.startsWith("/.well-known/")) return;
  if (url.pathname === location.pathname && url.search === location.search) return;
  event.preventDefault();
  navigate(url.href);
});

/* ---------------------------------------------------------------- Header, menu, account */

const SUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>';
const MOON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';

function parseSvg(markup, className) {
  const svg = new DOMParser().parseFromString(markup.replace("<svg ", '<svg xmlns="http://www.w3.org/2000/svg" '), "image/svg+xml").documentElement;
  svg.setAttribute("class", className);
  svg.setAttribute("aria-hidden", "true");
  return document.importNode(svg, true);
}

let mePromise;
/** Current account, or null when signed out. Never redirects. */
export function getMe() {
  mePromise ??= api("/api/me", { auth: "silent" }).catch((error) => {
    if (error.status === 401) return null;
    throw error;
  });
  return mePromise;
}

export function avatar(profile, size = "") {
  const initials = (profile?.displayName || profile?.email || "?").split(/\s+/).map((part) => part[0]).join("").slice(0, 2).toUpperCase();
  return h("span", { class: `avatar ${size}`, css: { "--h": String(profile?.avatarHue ?? 250) }, "aria-hidden": "true", text: initials });
}

export async function signOut() {
  try {
    await api("/api/auth/signout", { method: "POST", body: {}, auth: "silent" });
  } catch (error) {
    reportError(error);
    return;
  }
  navigate("/");
}

function buildMenu(header) {
  const button = $("[data-menu]", header);
  if (!button) return;
  const here = location.pathname;
  const links = [["/", "Observatory"], ["/scan", "Console"], ["/account", "Profile"], ["/verify", "Verifier"], ["/#threats", "Threat model"]];
  const account = h("div", { class: "menu__card" }, h("div", { class: "skeleton", css: { height: "2.6rem" } }));
  const quick = h("form", { class: "menu__card menu__card--accent", action: "/scan", method: "get" },
    h("p", { text: "Check a suspicious link without opening it." }),
    h("label", { class: "field" }, h("span", { class: "sr-only", text: "Link" }), h("input", { name: "url", placeholder: "paste a link", autocomplete: "off", spellcheck: "false", required: true, maxlength: 2048 })));
  quick.addEventListener("submit", (event) => {
    event.preventDefault();
    navigate(`/scan?url=${encodeURIComponent(new FormData(quick).get("url"))}#url`);
  });
  const menu = h("div", { class: "menu", id: "menu", role: "dialog", "aria-label": "Menu", "aria-modal": "false", hidden: true },
    h("nav", { class: "menu__card", "aria-label": "Site" }, h("ul", { class: "menu__links" },
      links.map(([href, label]) => h("li", {}, h("a", { href, text: label, ...(href === here ? { "aria-current": "page" } : {}) }))))),
    account, quick);
  document.body.append(menu);

  const setOpen = (open) => {
    button.setAttribute("aria-expanded", String(open));
    if (open) {
      menu.hidden = false;
      requestAnimationFrame(() => menu.classList.add("is-open"));
      $("a", menu)?.focus({ preventScroll: true });
    } else {
      menu.classList.remove("is-open");
      setTimeout(() => { if (!menu.classList.contains("is-open")) menu.hidden = true; }, 400);
    }
  };
  button.addEventListener("click", () => setOpen(button.getAttribute("aria-expanded") !== "true"));
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && button.getAttribute("aria-expanded") === "true") {
      setOpen(false);
      button.focus();
    }
  });
  document.addEventListener("pointerdown", (event) => {
    if (button.getAttribute("aria-expanded") === "true" && !menu.contains(event.target) && !button.contains(event.target)) setOpen(false);
  });

  getMe().then((me) => {
    if (me) {
      account.replaceChildren(h("div", { class: "menu__account" }, avatar(me.profile),
        h("div", { class: "meta" }, h("b", { text: me.profile.displayName }), h("span", { text: me.user.email })),
        h("button", { class: "pill pill--sm pill--line", type: "button", text: "Sign out", onclick: signOut })));
      const cta = $("[data-cta]", header);
      if (cta && here === "/") cta.firstChild.textContent = "Open console";
    } else {
      account.replaceChildren(h("div", { class: "menu__account" },
        h("div", { class: "meta" }, h("b", { text: "Not signed in" }), h("span", { text: "Your reports stay in your account." })),
        h("a", { class: "pill pill--sm pill--dark", href: `/auth?next=${encodeURIComponent(here)}`, text: "Sign in" })));
      const cta = $("[data-cta]", header);
      if (cta && here === "/") { cta.href = "/auth"; cta.firstChild.textContent = "Sign in"; }
    }
  }).catch(() => account.replaceChildren(h("p", { class: "muted", text: "Account unavailable." })));
}

function initHeader() {
  const header = $("[data-header]");
  if (!header) return;
  const toggle = $("[data-theme-toggle]", header);
  if (toggle) {
    toggle.replaceChildren(parseSvg(MOON, "moon"), parseSvg(SUN, "sun"));
    toggle.addEventListener("click", () => setTheme(currentTheme() === "dark" ? "light" : "dark"));
  }
  buildMenu(header);
  let last = scrollY;
  addEventListener("scroll", () => {
    const y = scrollY;
    header.classList.toggle("is-hidden", y > last && y > 240 && $("[data-menu]")?.getAttribute("aria-expanded") !== "true");
    last = y;
  }, { passive: true });
}

/* ---------------------------------------------------------------- Motion helpers */

function initReveal() {
  if (reducedMotion()) return;
  document.documentElement.classList.add("js-motion");
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) if (entry.isIntersecting) {
      entry.target.classList.add("is-in");
      observer.unobserve(entry.target);
    }
  }, { threshold: 0.15, rootMargin: "0px 0px -8% 0px" });
  for (const el of $$("[data-reveal]")) observer.observe(el);
}

function initMagnetic() {
  if (reducedMotion() || !matchMedia("(pointer: fine)").matches) return;
  for (const el of $$("[data-magnetic]")) {
    el.addEventListener("pointermove", (event) => {
      const rect = el.getBoundingClientRect();
      el.style.transform = `translate(${(event.clientX - rect.left - rect.width / 2) * 0.18}px, ${(event.clientY - rect.top - rect.height / 2) * 0.28}px)`;
    });
    el.addEventListener("pointerleave", () => (el.style.transform = ""));
  }
}

function cssVar(name, fallback) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fallback;
}

/** Canvas cursor trail with a lagging glow dot. Native cursor stays visible for accessibility. */
function initCursor() {
  if (reducedMotion() || !matchMedia("(pointer: fine)").matches) return;
  const canvas = document.body.appendChild(h("canvas", { class: "cursor-fx", "aria-hidden": "true" }));
  const ctx = canvas.getContext("2d");
  let w = 0, h2 = 0, dpr = 1;
  const resize = () => {
    dpr = Math.min(devicePixelRatio || 1, 2);
    w = innerWidth;
    h2 = innerHeight;
    canvas.width = Math.round(w * dpr);
    canvas.height = Math.round(h2 * dpr);
    canvas.style.width = `${w}px`;
    canvas.style.height = `${h2}px`;
  };
  resize();
  addEventListener("resize", resize, { passive: true });

  const trail = [];
  let tx = innerWidth / 2, ty = innerHeight / 2, px = tx, py = ty, visible = false, radius = 5, radiusTarget = 5;
  let color = cssVar("--accent", "#3b2cff");
  addEventListener("themechange", () => (color = cssVar("--accent", "#3b2cff")));
  addEventListener("pointermove", (event) => {
    if (event.pointerType === "touch") return;
    tx = event.clientX;
    ty = event.clientY;
    visible = true;
    const interactive = event.target?.closest?.("a,button,input,textarea,select,summary,label,[role='button'],[data-magnetic]");
    radiusTarget = interactive ? 15 : 5;
  }, { passive: true });
  addEventListener("pointerdown", () => (radiusTarget = Math.max(9, radiusTarget)));
  document.addEventListener("pointerleave", () => (visible = false));

  let raf = 0;
  const frame = () => {
    raf = requestAnimationFrame(frame);
    px += (tx - px) * 0.32;
    py += (ty - py) * 0.32;
    radius += (radiusTarget - radius) * 0.18;
    trail.push({ x: px, y: py });
    if (trail.length > 24) trail.shift();
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h2);
    if (!visible) return;
    ctx.lineCap = "round";
    ctx.lineJoin = "round";
    ctx.strokeStyle = color;
    for (let i = 1; i < trail.length; i++) {
      const t = i / trail.length;
      ctx.globalAlpha = t * 0.45;
      ctx.lineWidth = t * radius * 0.8;
      ctx.beginPath();
      ctx.moveTo(trail[i - 1].x, trail[i - 1].y);
      ctx.lineTo(trail[i].x, trail[i].y);
      ctx.stroke();
    }
    const glow = ctx.createRadialGradient(px, py, 0, px, py, radius * 2.6);
    glow.addColorStop(0, color);
    glow.addColorStop(1, "transparent");
    ctx.globalAlpha = 0.45;
    ctx.fillStyle = glow;
    ctx.beginPath();
    ctx.arc(px, py, radius * 2.6, 0, Math.PI * 2);
    ctx.fill();
    ctx.globalAlpha = 1;
    ctx.fillStyle = color;
    ctx.beginPath();
    ctx.arc(px, py, Math.max(1.5, radius * 0.4), 0, Math.PI * 2);
    ctx.fill();
  };
  frame();
  document.addEventListener("visibilitychange", () => {
    if (document.hidden) {
      cancelAnimationFrame(raf);
      raf = 0;
    } else if (!raf) {
      frame();
    }
  });
}

export function init() {
  initHeader();
  initReveal();
  initMagnetic();
  initCursor();
  revealPage();
}

export const fmtTime = (iso) => new Date(iso).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
export const VERDICT = {
  pass: { label: "Pass", tone: "success" }, block: { label: "Blocked", tone: "danger" }, incomplete: { label: "Incomplete", tone: "warning" },
  low_risk: { label: "Low risk", tone: "success" }, suspicious: { label: "Suspicious", tone: "warning" }, high_risk: { label: "High risk", tone: "danger" },
  inconclusive: { label: "Inconclusive", tone: "warning" },
};
