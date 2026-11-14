import { $, $$, api, clearErrors, currentTheme, getMe, h, init, navigate, reducedMotion, reportError, setFieldError } from "./ui.js";

init();

const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,190}\.[A-Za-z]{2,24}$/;
const params = new URLSearchParams(location.search);
const rawNext = params.get("next") ?? "/scan";
/** Only same-site paths are accepted as a destination, so the page cannot be used as an open redirect. */
const next = /^\/(?!\/)[\w\-./?=&#%]*$/.test(rawNext) && !rawNext.startsWith("/auth") ? rawNext : "/scan";

const TEXT = {
  signin: ["Welcome back", "Sign in"],
  signup: ["Create your account", "Start defending"],
  forgot: ["Account recovery", "Reset your password"],
  reset: ["Account recovery", "Choose a new password"],
  magic: ["Passwordless", "Get a sign-in link"],
  callback: ["One moment", "Signing you in…"],
};
let authMethods = null;
let currentMode = "signin";
function refreshSso() {
  const available = authMethods && ((authMethods.oauth && authMethods.oauth.length) || authMethods.magicLink);
  $("#sso").hidden = !(["signin", "signup"].includes(currentMode) && available);
}
function applyMethods() {
  const oauth = authMethods?.oauth ?? [];
  for (const el of $$("[data-sso]")) el.hidden = !oauth.includes(el.dataset.sso);
  for (const el of $$('[data-go="magic"]')) el.hidden = !authMethods?.magicLink;
  if (authMethods && !authMethods.signup) for (const el of $$('[data-go="signup"]')) el.closest("p")?.setAttribute("hidden", "");
  if (authMethods && !authMethods.recovery) for (const el of $$('[data-go="forgot"]')) el.hidden = true;
}
const notice = $("#auth-notice");
function showNotice(kind, text) {
  notice.hidden = false;
  notice.replaceChildren(h("div", { class: `notice notice--${kind}`, role: kind === "error" ? "alert" : "status", text }));
}
function setMode(mode, { keepNotice = false } = {}) {
  currentMode = mode;
  for (const form of $$("form[data-mode]")) form.hidden = form.dataset.mode !== mode;
  const [eyebrow, title] = TEXT[mode];
  $("#auth-eyebrow").textContent = eyebrow;
  $("#auth-title").textContent = title;
  document.title = `${title} — SignalWard`;
  if (!keepNotice) notice.hidden = true;
  refreshSso();
  $(`form[data-mode="${mode}"] input`)?.focus({ preventScroll: true });
}
// Preserve the destination across the OAuth / magic-link round-trip.
for (const link of $$("[data-sso]")) link.addEventListener("click", () => {
  try { sessionStorage.setItem("sw-next", next); } catch {}
});
for (const button of $$("[data-go]")) button.addEventListener("click", () => {
  setMode(button.dataset.go);
  history.replaceState(null, "", `/auth?mode=${button.dataset.go}${next !== "/scan" ? `&next=${encodeURIComponent(next)}` : ""}`);
});

for (const button of $$("[data-reveal-pw]")) button.addEventListener("click", () => {
  const input = button.previousElementSibling;
  const show = input.type === "password";
  input.type = show ? "text" : "password";
  button.textContent = show ? "Hide" : "Show";
  button.setAttribute("aria-label", show ? "Hide password" : "Show password");
});

function score(password) {
  if (!password) return 0;
  let s = 0;
  if (password.length >= 10) s++;
  if (password.length >= 14) s++;
  if (/[A-Za-z]/.test(password) && /\d/.test(password)) s++;
  if (/[^A-Za-z0-9]/.test(password)) s++;
  return Math.max(1, Math.min(4, s));
}
for (const input of $$('input[autocomplete="new-password"]')) {
  input.addEventListener("input", () => (input.closest(".field").querySelector(".strength").dataset.score = String(score(input.value))));
}
function passwordProblem(password) {
  if (password.length < 10 || !/[A-Za-z]/.test(password) || !/[^A-Za-z]/.test(password)) return "Use at least 10 characters, with letters and a number or symbol.";
  if (password.length > 128) return "Passwords can be at most 128 characters.";
  return null;
}

async function submit(form, run) {
  clearErrors(form);
  const button = $('button[type="submit"]', form);
  button.disabled = true;
  form.classList.add("scanning");
  try {
    await run();
  } catch (error) {
    reportError(error, form);
  } finally {
    button.disabled = false;
    form.classList.remove("scanning");
  }
}

function checkEmail(form) {
  const input = form.elements.email;
  input.value = input.value.trim();
  if (!EMAIL.test(input.value)) {
    setFieldError(input, "Enter a valid email address.");
    input.focus();
    return false;
  }
  return true;
}

$("#form-signin").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (!checkEmail(form)) return;
  if (!form.elements.password.value) return setFieldError(form.elements.password, "Enter your password.");
  submit(form, async () => {
    await api("/api/auth/signin", { method: "POST", body: { email: form.elements.email.value, password: form.elements.password.value }, auth: "silent" });
    navigate(next);
  });
});

$("#form-signup").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const name = form.elements.displayName;
  name.value = name.value.trim();
  if (!name.value) return setFieldError(name, "Tell us what to call you.");
  if (!checkEmail(form)) return;
  const problem = passwordProblem(form.elements.password.value);
  if (problem) return setFieldError(form.elements.password, problem);
  submit(form, async () => {
    const result = await api("/api/auth/signup", { method: "POST", body: { displayName: name.value, email: form.elements.email.value, password: form.elements.password.value }, auth: "silent" });
    if (result.status === "confirm_email") {
      setMode("signin", { keepNotice: true });
      showNotice("success", `Check ${result.email} for a confirmation link, then sign in.`);
      return;
    }
    navigate(next === "/scan" ? "/account" : next);
  });
});

$("#form-forgot").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (!checkEmail(form)) return;
  submit(form, async () => {
    await api("/api/auth/recover", { method: "POST", body: { email: form.elements.email.value }, auth: "silent" });
    setMode("signin", { keepNotice: true });
    showNotice("success", "If an account exists for that email, a reset link is on its way.");
  });
});

$("#form-reset").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const problem = passwordProblem(form.elements.newPassword.value);
  if (problem) return setFieldError(form.elements.newPassword, problem);
  submit(form, async () => {
    await api("/api/me/password", { method: "POST", body: { newPassword: form.elements.newPassword.value } });
    showNotice("success", "Password updated. Taking you to your profile…");
    setTimeout(() => navigate("/account"), 900);
  });
});

$("#form-magic").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  if (!checkEmail(form)) return;
  submit(form, async () => {
    await api("/api/auth/magic-link", { method: "POST", body: { email: form.elements.email.value }, auth: "silent" });
    try { sessionStorage.setItem("sw-next", next); } catch {}
    setMode("signin", { keepNotice: true });
    showNotice("success", `Check ${form.elements.email.value} for a one-time sign-in link.`);
  });
});

/* ---------- Email-link callback (Supabase puts tokens in the URL fragment) ---------- */
async function handleCallback() {
  setMode("callback");
  for (const form of $$("form[data-mode]")) form.hidden = true;
  const fragment = new URLSearchParams(location.hash.slice(1));
  history.replaceState(null, "", "/auth/callback"); // drop tokens from the address bar and history
  if (fragment.get("error")) {
    const expired = fragment.get("error_code") === "otp_expired";
    setMode("signin", { keepNotice: true });
    showNotice("error", expired ? "That link has expired or was already used. Request a new one." : (fragment.get("error_description") ?? "The link could not be used.").slice(0, 200));
    return;
  }
  const accessToken = fragment.get("access_token"), refreshToken = fragment.get("refresh_token");
  if (!accessToken || !refreshToken) {
    setMode("signin", { keepNotice: true });
    showNotice("warning", "This page expects a sign-in link from your email. Sign in below instead.");
    return;
  }
  try {
    await api("/api/auth/callback", { method: "POST", body: { accessToken, refreshToken, expiresAt: Number(fragment.get("expires_at")) || undefined }, auth: "silent" });
  } catch (error) {
    setMode("signin", { keepNotice: true });
    reportError(error);
    return;
  }
  let dest = "/account";
  try {
    dest = sessionStorage.getItem("sw-next") || dest;
    sessionStorage.removeItem("sw-next");
  } catch {}
  if (fragment.get("type") === "recovery") setMode("reset");
  else navigate(dest);
}

/* ---------- Boot ---------- */
async function boot() {
  if (location.pathname === "/auth/callback") return handleCallback();
  const mode = ["signup", "forgot", "magic"].includes(params.get("mode")) ? params.get("mode") : "signin";
  setMode(mode);
  const [me, health] = await Promise.all([getMe().catch(() => null), api("/api/health", { auth: "silent" }).catch(() => null)]);
  if (me) return navigate(next);
  authMethods = health;
  applyMethods();
  refreshSso();
  if (params.has("next")) showNotice("info", "Sign in to continue.");
}
boot();

/* ---------- Art: a particle shield in a rounded card ---------- */
(async () => {
  if (reducedMotion()) return;
  const canvas = $(".auth-art canvas");
  try {
    const { startScene } = await import("./scene.js");
    const scene = startScene(canvas, { compact: true, shape: 5, prisms: false, light: currentTheme() === "light" });
    scene.state.view.h = 0.92;
    scene.resume();
    addEventListener("themechange", (event) => scene.setLight(event.detail === "light"));
    canvas.parentElement.addEventListener("pointermove", (event) => {
      const rect = canvas.getBoundingClientRect();
      scene.pointer(((event.clientX - rect.left) / rect.width) * 2 - 1, 1 - ((event.clientY - rect.top) / rect.height) * 2, true);
    });
    canvas.parentElement.addEventListener("pointerleave", () => scene.pointer(0, 0, false));
  } catch (error) {
    console.warn("Scene unavailable:", error instanceof Error ? error.message : error);
  }
})();
