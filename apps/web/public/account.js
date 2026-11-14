import { $, VERDICT, api, avatar, clearErrors, currentTheme, fmtTime, h, init, reducedMotion, reportError, setFieldError, signOut, toast } from "./ui.js";

init();

const TONE_COLOR = { success: "var(--success)", warning: "var(--warning)", danger: "var(--danger)", info: "var(--accent)" };
const KIND_SHORT = { repository: "GIT", message: "MSG", url: "URL" };
let me = null;

/* ---------- Header card ---------- */
function renderProfile() {
  const { profile, user, session } = me;
  $("#profile-avatar").replaceChildren(avatar(profile, "avatar--xl"));
  $("#profile-name").textContent = profile.displayName;
  $("#profile-line").textContent = [profile.title, profile.organization].filter(Boolean).join(" at ") || user.email;
  $("#profile-meta").replaceChildren(
    h("span", { class: "chip", text: user.email }),
    h("span", { class: "chip", text: `Member since ${new Date(profile.createdAt || user.createdAt).toLocaleDateString([], { month: "short", year: "numeric" })}` }),
    h("span", { class: `chip`, text: user.emailConfirmed ? "Email verified" : "Email not verified" }),
    h("span", { class: "chip", text: session.provider === "supabase" ? "Supabase account" : "Local account" }));
  $("#identity-key").textContent = me.keys.signing;
  const form = $("#profile-form");
  form.elements.displayName.value = profile.displayName;
  form.elements.title.value = profile.title;
  form.elements.organization.value = profile.organization;
  form.elements.avatarHue.value = String(profile.avatarHue);
  $("#hue-avatar").replaceChildren(avatar(profile));
  $("#provider").textContent = session.provider === "supabase" ? "managed by Supabase Auth" : "local account";
  $("#session-kv").replaceChildren(...[
    ["Signed in", fmtTime(session.issuedAt)], ["Session ends", fmtTime(session.expiresAt)],
    ["Indicator key", me.keys.indicator], ["Receipt key", me.keys.signing],
  ].flatMap(([k, v]) => [h("dt", { text: k }), h("dd", { text: v })]));
  // Supabase re-authenticates with the current password when given; local accounts require it.
  $("#current-field").querySelector("span").replaceChildren("Current password", session.provider === "supabase" ? h("em", { text: "recommended" }) : null);
}

/* ---------- Stats ---------- */
function count(el, value) {
  if (reducedMotion()) return void (el.textContent = value.toLocaleString());
  const start = performance.now();
  const step = (now) => {
    const t = Math.min(1, (now - start) / 900);
    el.textContent = Math.round(value * (1 - Math.pow(1 - t, 3))).toLocaleString();
    if (t < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

function donut(byVerdict) {
  const entries = Object.entries(byVerdict).filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((sum, [, n]) => sum + n, 0);
  const r = 52, c = 2 * Math.PI * r;
  let offset = 0;
  const svg = h("svg", { class: "donut", viewBox: "0 0 140 140", role: "img", "aria-label": `${total} reports by verdict` },
    h("circle", { svg: true, cx: 70, cy: 70, r, css: { stroke: "var(--surface-3)" } }),
    ...entries.map(([verdict, n]) => {
      const length = (n / total) * c;
      const arc = h("circle", { svg: true, cx: 70, cy: 70, r, css: { stroke: TONE_COLOR[VERDICT[verdict]?.tone ?? "info"] }, "stroke-dasharray": `${Math.max(0, length - 2)} ${c}`, "stroke-dashoffset": -offset, transform: "rotate(-90 70 70)", "stroke-linecap": "round" });
      offset += length;
      return arc;
    }),
    h("text", { svg: true, x: 70, y: 66, "text-anchor": "middle", "font-size": 26, text: String(total) }),
    h("text", { svg: true, x: 70, y: 86, "text-anchor": "middle", "font-size": 10, css: { fill: "var(--muted)" }, text: "reports" }));
  const legend = h("ul", { class: "legend" }, entries.length
    ? entries.map(([verdict, n]) => h("li", {}, h("i", { css: { background: TONE_COLOR[VERDICT[verdict]?.tone ?? "info"] } }), VERDICT[verdict]?.label ?? verdict, h("b", { text: String(n) })))
    : h("li", { class: "muted", text: "No reports yet." }));
  $("#donut").replaceChildren(svg, legend);
}

function bars(days) {
  const max = Math.max(1, ...days);
  $("#bars").replaceChildren(...days.map((n, index) => h("i", {
    class: n ? "" : "is-zero", title: `${n} scan${n === 1 ? "" : "s"}`,
    css: { height: `${Math.max(3, (n / max) * 100)}%`, "animation-delay": `${index * 18}ms` },
  })));
}

async function loadStats() {
  try {
    const stats = await api("/api/me/stats");
    for (const key of ["total", "threats", "high", "blocked"]) count($(`[data-stat="${key}"]`), stats[key]);
    bars(stats.days);
    donut(stats.byVerdict);
    $("#kind-split").textContent = `${stats.byKind.repository} repo · ${stats.byKind.message} msg · ${stats.byKind.url} link`;
    $("#recent").replaceChildren(...(stats.recent.length ? stats.recent.map((item) => {
      const verdict = VERDICT[item.verdict] ?? { label: item.verdict, tone: "info" };
      return h("div", { class: "list__row" }, h("span", { class: "kind", text: KIND_SHORT[item.kind] }),
        h("div", { css: { "min-width": "0" } }, h("b", { text: item.summary }), h("span", { text: `${fmtTime(item.createdAt)} · ${item.findings} findings` })),
        h("span", { class: `tag tag--${verdict.tone}`, text: verdict.label }));
    }) : [h("div", { class: "empty", css: { "min-height": "10rem" } }, h("b", { text: "No reports yet" }), h("a", { class: "pill pill--dark pill--sm", href: "/scan", text: "Run your first scan" }))]));
  } catch (error) {
    reportError(error);
  }
}

/* ---------- Forms ---------- */
const profileForm = $("#profile-form");
profileForm.elements.avatarHue.addEventListener("input", (event) => {
  $("#hue-avatar").replaceChildren(avatar({ ...me?.profile, avatarHue: Number(event.target.value) }));
});
profileForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearErrors(profileForm);
  const name = profileForm.elements.displayName.value.trim();
  if (!name) return setFieldError(profileForm.elements.displayName, "Your name can't be empty.");
  const button = profileForm.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    const { profile } = await api("/api/me/profile", { method: "PATCH", body: {
      displayName: name, title: profileForm.elements.title.value.trim(), organization: profileForm.elements.organization.value.trim(),
      avatarHue: Number(profileForm.elements.avatarHue.value),
    } });
    me.profile = profile;
    renderProfile();
    toast("success", "Profile saved");
  } catch (error) {
    reportError(error, profileForm);
  } finally {
    button.disabled = false;
  }
});

const passwordForm = $("#password-form");
passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearErrors(passwordForm);
  const current = passwordForm.elements.currentPassword, next = passwordForm.elements.newPassword;
  if (me.session.provider === "local" && !current.value) return setFieldError(current, "Enter your current password.");
  if (next.value.length < 10 || !/[A-Za-z]/.test(next.value) || !/[^A-Za-z]/.test(next.value)) return setFieldError(next, "Use at least 10 characters, with letters and a number or symbol.");
  const button = passwordForm.querySelector('button[type="submit"]');
  button.disabled = true;
  try {
    await api("/api/me/password", { method: "POST", body: { currentPassword: current.value || undefined, newPassword: next.value } });
    passwordForm.reset();
    toast("success", "Password changed", me.session.provider === "local" ? "Other sessions were signed out." : undefined);
  } catch (error) {
    reportError(error, passwordForm);
  } finally {
    button.disabled = false;
  }
});
$("#signout").addEventListener("click", signOut);

const eraseForm = $("#erase-form");
eraseForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  clearErrors(eraseForm);
  if (eraseForm.elements.confirm.value !== "ERASE") return setFieldError(eraseForm.elements.confirm, "Type ERASE in capitals to confirm.");
  try {
    await api("/api/me/erase", { method: "POST", body: { confirm: "ERASE" } });
    eraseForm.reset();
    toast("success", "Data erased", "Reports, indicator history and blocklist were deleted.");
    loadStats();
  } catch (error) {
    reportError(error, eraseForm);
  }
});

/* ---------- Identity card: particle fingerprint ---------- */
async function identityArt() {
  if (reducedMotion()) return;
  const card = $(".identity");
  const canvas = $("canvas", card);
  try {
    const { startScene } = await import("./scene.js");
    const scene = startScene(canvas, { compact: true, shape: 4, prisms: false, light: currentTheme() === "light" });
    scene.state.view.h = 0.8;
    scene.state.view.cy = 0.12;
    scene.resume();
    addEventListener("themechange", (event) => scene.setLight(event.detail === "light"));
    card.addEventListener("pointermove", (event) => {
      const rect = canvas.getBoundingClientRect();
      scene.pointer(((event.clientX - rect.left) / rect.width) * 2 - 1, 1 - ((event.clientY - rect.top) / rect.height) * 2, true);
    });
    card.addEventListener("pointerleave", () => scene.pointer(0, 0, false));
    new IntersectionObserver(([entry]) => (entry.isIntersecting ? scene.resume() : scene.pause())).observe(card);
  } catch (error) {
    console.warn("Scene unavailable:", error instanceof Error ? error.message : error);
  }
}

/* ---------- Boot ---------- */
(async () => {
  try {
    me = await api("/api/me");
  } catch (error) {
    reportError(error);
    return;
  }
  renderProfile();
  loadStats();
  identityArt();
})();
