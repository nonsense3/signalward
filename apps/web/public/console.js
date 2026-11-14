import { fetchTrustedKeys, verifyReceipt } from "./verify.js";

/* ---------- Small DOM helper. Every value is set as text, never parsed as HTML. ---------- */
function h(tag, props = {}, ...children) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") el.className = value;
    else if (key === "text") el.textContent = value;
    else if (key.startsWith("on")) el.addEventListener(key.slice(2), value);
    else el.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) if (child !== null && child !== undefined && child !== false) el.append(child instanceof Node ? child : document.createTextNode(String(child)));
  return el;
}
const $ = (selector) => document.querySelector(selector);

/* ---------- API ---------- */
class ApiError extends Error {
  constructor(status, code, message) { super(message); this.status = status; this.code = code; }
}
async function api(path, { method = "GET", body } = {}, retried = false) {
  const response = await fetch(path, {
    method,
    headers: body === undefined ? {} : { "Content-Type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
    credentials: "same-origin",
  });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401 && !retried) {
    await openSession();
    return api(path, { method, body }, true);
  }
  if (!response.ok) throw new ApiError(response.status, data.error?.code ?? "ERROR", data.error?.message ?? `Request failed (${response.status}).`);
  return data;
}

/* ---------- Session and live events ---------- */
let session = null;
let events = null;
async function openSession() {
  const label = $("#session-label");
  try {
    session = await api("/api/session", { method: "POST", body: {} }, true);
    $("#session").classList.add("is-live");
    const expires = new Date(session.expiresAt);
    label.textContent = `${session.workspace} · expires ${expires.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`;
    renderSession();
    connectEvents();
  } catch (error) {
    $("#session").classList.remove("is-live");
    label.textContent = `No session: ${error.message}`;
  }
}
function renderSession() {
  if (!session) return;
  const rows = [
    ["Workspace", session.workspace], ["Session", session.session], ["Issued", new Date(session.issuedAt).toLocaleString()],
    ["Expires", new Date(session.expiresAt).toLocaleString()], ["Token", "HMAC-SHA-256 · HttpOnly · SameSite=Strict"],
    ["Indicator key", `${session.indicatorKeyVersion} · HKDF per workspace`], ["Signing key", session.signingKeyId],
  ];
  $("#session-details").replaceChildren(...rows.flatMap(([k, v]) => [h("dt", { text: k }), h("dd", { text: v })]));
}
function logEvent(text) {
  const list = $("#events");
  if (list.firstElementChild?.classList.contains("muted")) list.replaceChildren();
  list.prepend(h("li", {}, h("time", { text: new Date().toLocaleTimeString() }), text));
  while (list.children.length > 60) list.lastElementChild.remove();
}
function connectEvents() {
  events?.close();
  events = new EventSource("/api/events");
  events.addEventListener("ready", () => logEvent("Connected to the workspace event stream."));
  events.addEventListener("activity", (message) => {
    const event = JSON.parse(message.data);
    if (event.type === "scan.started") logEvent(`${event.kind} scan started`);
    else if (event.type === "scan.completed") { logEvent(`${event.kind} scan ${event.reportId}: ${event.verdict.replace("_", " ")}, ${event.findings} findings`); refreshHistory(); }
    else if (event.type === "blocklist.added") { logEvent(`Blocked a ${event.indicatorType.replace("_", " ")} indicator`); refreshBlocklist(); }
    else if (event.type === "blocklist.removed") { logEvent("Removed an indicator from the blocklist"); refreshBlocklist(); }
  });
}
$("#end-session").addEventListener("click", async () => {
  if (!confirm("End the session? This erases this workspace's reports, indicator history and blocklist.")) return;
  events?.close();
  await api("/api/session/end", { method: "POST", body: {} }, true).catch(() => {});
  latest = null;
  $("#report").hidden = true;
  $("#history").replaceChildren(h("tr", {}, h("td", { colspan: 5, class: "muted", text: "No reports yet." })));
  $("#blocklist").replaceChildren(h("tr", {}, h("td", { colspan: 5, class: "muted", text: "Nothing blocked." })));
  $("#events").replaceChildren(h("li", { class: "muted", text: "Session ended. Workspace data erased." }));
  await openSession();
});

/* ---------- Tabs ---------- */
const TABS = ["repository", "message", "url", "verify", "activity"];
function showTab(name) {
  const tab = TABS.includes(name) ? name : "repository";
  for (const panel of document.querySelectorAll("[data-panel]")) panel.hidden = panel.dataset.panel !== tab;
  for (const link of document.querySelectorAll("[data-tab]")) {
    if (link.dataset.tab === tab) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  }
  $("#report").hidden = !latest || latest.report.kind !== tab;
  if (tab === "activity") { refreshHistory(); refreshBlocklist(); }
}
addEventListener("hashchange", () => showTab(location.hash.slice(1)));

/* ---------- Report rendering ---------- */
let latest = null;
const VERDICT_LABEL = { pass: "Pass", block: "Block", incomplete: "Incomplete", low_risk: "Low risk", suspicious: "Suspicious", high_risk: "High risk", inconclusive: "Inconclusive" };

function download(name, data) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const link = h("a", { href: url, download: name });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function renderStages(stages) {
  const list = h("ol", { class: "stages", "aria-label": "Scan stages" },
    [...stages, { name: "sign", ms: null, status: "done" }].map((stage) => h("li", { class: stage.status === "skipped" ? "is-skipped" : "" }, h("b", { text: stage.name }), stage.ms === null ? "Ed25519" : `${stage.ms} ms`)));
  [...list.children].forEach((item, index) => setTimeout(() => item.classList.add("is-done"), 120 + index * 140));
  return list;
}

function renderFinding(finding) {
  const location = finding.location ? `${finding.location.path}:${finding.location.line}` : finding.category;
  return h("details", {},
    h("summary", {}, h("span", { class: `sev sev--${finding.severity}`, text: finding.severity }), h("span", { class: "title", text: finding.title }), h("span", { class: "loc", text: location })),
    h("div", { class: "body" },
      h("p", { text: finding.description }),
      h("p", {}, h("strong", { text: "Why it matters. " }), finding.impact),
      h("p", {}, h("strong", { text: "Fix. " }), finding.remediation),
      h("ul", { class: "evidence" }, finding.evidence.map((item) => h("li", {}, h("span", { text: item.label }), item.value))),
      h("p", { class: "muted" }, h("code", { text: `${finding.id} · ${finding.ruleId} · confidence ${finding.confidence}` })),
    ),
  );
}

function renderIndicators(report) {
  if (!report.indicators.length) return null;
  const rows = report.indicators.map((indicator) => {
    const button = h("button", { class: "chip", type: "button", text: indicator.blocked ? "Blocked" : "Block" });
    button.disabled = indicator.blocked;
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        await api("/api/blocklist", { method: "POST", body: { tag: indicator.tag, reportId: report.id } });
        button.textContent = "Blocked";
      } catch (error) {
        button.disabled = false;
        button.textContent = "Retry";
        logEvent(error.message);
      }
    });
    return h("tr", {},
      h("td", { text: indicator.type.replace("_", " ") }), h("td", {}, h("code", { text: indicator.display })),
      h("td", {}, h("code", { text: `${indicator.tag.slice(0, 14)}…` })), h("td", { text: indicator.seenBefore ? `${indicator.seenBefore} earlier` : "first" }), h("td", {}, button));
  });
  return h("div", { class: "box" },
    h("h2", { text: "Indicators (keyed tags, raw values discarded)" }),
    h("div", { class: "table-wrap" }, h("table", {}, h("thead", {}, h("tr", {}, ["Type", "Redacted", "HMAC tag", "Seen", ""].map((t) => h("th", { scope: "col", text: t })))), h("tbody", {}, rows))));
}

function render(stored) {
  latest = stored;
  const { report, receipt } = stored;
  const container = $("#report");
  const counts = report.findings.reduce((acc, f) => ((acc[f.severity] = (acc[f.severity] ?? 0) + 1), acc), {});
  const actions = h("div", { class: "row" },
    h("button", { class: "button", type: "button", text: "Download receipt", onclick: () => download(`${report.id}.receipt.json`, receipt) }),
    h("button", { class: "button", type: "button", text: "Download report", onclick: () => download(`${report.id}.report.json`, report) }),
    h("button", { class: "button button--primary", type: "button", text: "Verify this receipt", onclick: () => { fillVerify(stored); location.hash = "#verify"; runVerify(); } }));

  container.replaceChildren(
    renderStages(report.stages),
    h("div", { class: `verdict v-${report.verdict}` },
      h("span", { class: "verdict__label", text: VERDICT_LABEL[report.verdict] ?? report.verdict }),
      h("p", { class: "verdict__summary", text: report.summary }),
      h("p", { class: "verdict__meta" },
        h("span", { text: report.id }), h("span", { text: report.policyVersion }), h("span", { text: report.complete ? "coverage complete" : "coverage partial" }),
        h("span", { text: Object.entries(counts).map(([k, v]) => `${v} ${k}`).join(" · ") || "no findings" }))),
    h("div", { class: "coverage", "aria-label": "Detector coverage" }, report.coverage.map((item) =>
      h("div", {}, h("b", {}, item.detector, h("span", { class: `status status--${item.status}`, text: item.required ? item.status : `${item.status} · optional` })), h("span", { text: item.detail })))),
    h("div", { class: "box" },
      h("h2", { text: `Findings (${report.findings.length})` }),
      report.findings.length ? h("div", { class: "findings" }, report.findings.map(renderFinding)) : h("p", { class: "note", text: "No findings in the checks that ran." })),
    renderIndicators(report),
    h("div", { class: "box" },
      h("h2", { text: "Mitigation" }),
      h("ul", { class: "mitigations" }, report.mitigations.map((m) => h("li", {}, h("span", { class: `mode mode--${m.mode}`, text: m.mode }), h("b", { text: m.action }), h("span", { text: m.detail }))))),
    h("div", { class: "box receipt" },
      h("h2", { text: "Signed receipt" }),
      h("dl", {},
        h("dt", { text: "Key" }), h("dd", { text: receipt.payload.keyId }),
        h("dt", { text: "Report digest" }), h("dd", { text: receipt.payload.reportDigest }),
        h("dt", { text: "Action" }), h("dd", { text: receipt.payload.action }),
        h("dt", { text: "Issued" }), h("dd", { text: receipt.payload.issuedAt }),
        h("dt", { text: "Signature" }), h("dd", { text: `${receipt.signature.slice(0, 44)}…` })),
      actions),
  );
  container.hidden = false;
  container.scrollIntoView({ behavior: matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
}

function showError(error) {
  const container = $("#report");
  container.replaceChildren(h("p", { class: "error", role: "alert", text: error.message }));
  container.hidden = false;
}

async function runScan(kind, body, frame) {
  frame?.classList.add("is-scanning");
  const buttons = frame ? [...frame.querySelectorAll("button")] : [];
  buttons.forEach((b) => (b.disabled = true));
  try {
    render(await api(`/api/scans/${kind}`, { method: "POST", body }));
  } catch (error) {
    showError(error);
  } finally {
    frame?.classList.remove("is-scanning");
    buttons.forEach((b) => (b.disabled = false));
    $("#scan-repo").disabled = !selection.length;
  }
}

/* ---------- Repository intake ---------- */
const SKIP_DIRS = new Set(["node_modules", ".git", ".hg", ".svn", "dist", "build", ".next", "out", "coverage", "vendor", ".venv", "venv", "__pycache__", ".signalward", ".turbo", ".cache"]);
const BINARY = /\.(png|jpe?g|gif|webp|avif|ico|bmp|tiff?|psd|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|exe|dll|so|dylib|o|a|wasm|woff2?|ttf|otf|eot|mp[34]|mov|avi|webm|ogg|wav|flac|glb|gltf|bin|dat|db|sqlite|lockb)$/i;
const MAX_FILES = 2000, MAX_FILE = 1_000_000, MAX_TOTAL = 12_000_000;
let selection = [];
let selectionLabel = "uploaded files";

function keep(path, size) {
  return !path.split("/").some((part) => SKIP_DIRS.has(part)) && !BINARY.test(path) && size <= MAX_FILE;
}

async function collect(entries) {
  const files = [];
  let total = 0, skipped = 0;
  for (const { path, file } of entries) {
    if (!keep(path, file.size) || files.length >= MAX_FILES || total + file.size > MAX_TOTAL) { skipped++; continue; }
    total += file.size;
    files.push({ path, content: await file.text() });
  }
  return { files, skipped, total };
}

async function setSelection(entries, label) {
  $("#repo-meta").textContent = "Reading files…";
  const { files, skipped, total } = await collect(entries);
  selection = files;
  selectionLabel = label;
  $("#repo-meta").textContent = files.length
    ? `${label}: ${files.length} text files, ${(total / 1024).toFixed(0)} KB${skipped ? `, ${skipped} skipped in the browser` : ""}.`
    : "No scannable text files in the selection.";
  $("#scan-repo").disabled = !files.length;
}

for (const input of [$("#pick-folder"), $("#pick-files")]) {
  input.addEventListener("change", () => {
    const list = [...input.files];
    const root = list[0]?.webkitRelativePath?.split("/")[0];
    setSelection(list.map((file) => ({ path: file.webkitRelativePath ? file.webkitRelativePath.split("/").slice(1).join("/") || file.name : file.name, file })), root || "selected files");
    input.value = "";
  });
}

async function walkEntry(entry, prefix, out) {
  if (out.length > MAX_FILES * 2) return;
  if (entry.isFile) {
    const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
    out.push({ path: `${prefix}${entry.name}`, file });
  } else if (entry.isDirectory && !SKIP_DIRS.has(entry.name)) {
    const reader = entry.createReader();
    let batch;
    do {
      batch = await new Promise((resolve, reject) => reader.readEntries(resolve, reject));
      for (const child of batch) await walkEntry(child, `${prefix}${entry.name}/`, out);
    } while (batch.length);
  }
}

const drop = $("#drop");
drop.addEventListener("dragover", (event) => { event.preventDefault(); drop.classList.add("is-over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("is-over"));
drop.addEventListener("drop", async (event) => {
  event.preventDefault();
  drop.classList.remove("is-over");
  const items = [...event.dataTransfer.items].map((item) => item.webkitGetAsEntry?.()).filter(Boolean);
  const out = [];
  for (const entry of items) await walkEntry(entry, "", out);
  // Strip the dropped folder name so paths are relative to the project root.
  const single = items.length === 1 && items[0].isDirectory ? `${items[0].name}/` : "";
  setSelection(out.map(({ path, file }) => ({ path: single && path.startsWith(single) ? path.slice(single.length) : path, file })), single ? items[0].name : "dropped files");
});

$("#scan-repo").addEventListener("click", () => runScan("repository", { files: selection, label: selectionLabel }, $("#repo-intake")));
for (const button of document.querySelectorAll("[data-repo-sample]")) {
  button.addEventListener("click", () => runScan("repository", { sample: button.dataset.repoSample }, $("#repo-intake")));
}

/* ---------- Message and URL intake ---------- */
$("#message-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  runScan("message", { text: form.get("text"), sender: form.get("sender"), subject: form.get("subject") }, event.currentTarget);
});
for (const button of document.querySelectorAll("[data-message-sample]")) {
  button.addEventListener("click", () => runScan("message", { sample: button.dataset.messageSample }, $("#message-form")));
}
$("#url-form").addEventListener("submit", (event) => {
  event.preventDefault();
  runScan("url", { url: new FormData(event.currentTarget).get("url") }, event.currentTarget);
});
for (const chip of document.querySelectorAll("[data-url-sample]")) {
  chip.addEventListener("click", () => {
    $("#url-form").elements.url.value = chip.dataset.urlSample;
    runScan("url", { url: chip.dataset.urlSample }, $("#url-form"));
  });
}

/* ---------- Verification ---------- */
function fillVerify(stored) {
  $("#verify-receipt").value = JSON.stringify(stored.receipt, null, 2);
  $("#verify-report").value = JSON.stringify(stored.report, null, 2);
}
async function runVerify() {
  const out = $("#verify-result");
  let receipt, report;
  try {
    receipt = JSON.parse($("#verify-receipt").value);
    const reportText = $("#verify-report").value.trim();
    report = reportText ? JSON.parse(reportText) : undefined;
  } catch {
    out.replaceChildren(h("li", { class: "summary fail", text: "The receipt or report is not valid JSON." }));
    return;
  }
  try {
    const keys = await fetchTrustedKeys();
    const result = await verifyReceipt(receipt, keys, report);
    out.replaceChildren(
      h("li", { class: `summary ${result.valid ? "ok" : "fail"}`, text: result.valid ? "Valid: the receipt is authentic and matches the report." : "Invalid: at least one check failed." }),
      ...result.checks.map((check) => h("li", {}, h("span", { class: check.ok ? "ok" : "fail", text: check.ok ? "✓" : "✕", "aria-label": check.ok ? "passed" : "failed" }), h("b", { text: check.check }), h("span", { text: check.detail }))),
    );
  } catch (error) {
    out.replaceChildren(h("li", { class: "summary fail", text: error.message }));
  }
}
$("#verify-run").addEventListener("click", runVerify);
$("#verify-latest").addEventListener("click", () => {
  if (!latest) { $("#verify-result").replaceChildren(h("li", { class: "summary fail", text: "Run a scan first." })); return; }
  fillVerify(latest);
  runVerify();
});
$("#verify-tamper").addEventListener("click", () => {
  try {
    const receipt = JSON.parse($("#verify-receipt").value);
    const flipped = { pass: "block", block: "pass", incomplete: "pass", low_risk: "high_risk", suspicious: "low_risk", high_risk: "low_risk", inconclusive: "low_risk" };
    receipt.payload.verdict = flipped[receipt.payload.verdict] ?? "pass";
    $("#verify-receipt").value = JSON.stringify(receipt, null, 2);
    runVerify();
  } catch {
    $("#verify-result").replaceChildren(h("li", { class: "summary fail", text: "Load a receipt first." }));
  }
});

/* ---------- Activity ---------- */
async function refreshHistory() {
  try {
    const { reports } = await api("/api/reports");
    const body = $("#history");
    if (!reports.length) { body.replaceChildren(h("tr", {}, h("td", { colspan: 5, class: "muted", text: "No reports yet." }))); return; }
    body.replaceChildren(...reports.map((r) => h("tr", {},
      h("td", {}, h("button", { class: "history-link", type: "button", text: r.id, onclick: async () => {
        const stored = await api(`/api/reports/${encodeURIComponent(r.id)}`);
        location.hash = `#${stored.report.kind}`;
        render(stored);
        showTab(stored.report.kind);
      } })),
      h("td", { text: r.kind }), h("td", {}, h("span", { class: `sev sev--${["block", "high_risk"].includes(r.verdict) ? "high" : ["suspicious", "incomplete", "inconclusive"].includes(r.verdict) ? "medium" : "info"}`, text: VERDICT_LABEL[r.verdict] ?? r.verdict })),
      h("td", { text: String(r.findings) }), h("td", { text: new Date(r.createdAt).toLocaleTimeString() }))));
  } catch { /* the session banner already reports failures */ }
}
async function refreshBlocklist() {
  try {
    const { entries } = await api("/api/blocklist");
    const body = $("#blocklist");
    if (!entries.length) { body.replaceChildren(h("tr", {}, h("td", { colspan: 5, class: "muted", text: "Nothing blocked." }))); return; }
    body.replaceChildren(...entries.map((entry) => h("tr", {},
      h("td", { text: entry.type.replace("_", " ") }), h("td", {}, h("code", { text: entry.display })), h("td", {}, h("code", { text: `${entry.tag.slice(0, 14)}…` })),
      h("td", { text: new Date(entry.addedAt).toLocaleTimeString() }),
      h("td", {}, h("button", { class: "chip", type: "button", text: "Unblock", onclick: () => api("/api/blocklist", { method: "POST", body: { tag: entry.tag, remove: true } }).then(refreshBlocklist) })))));
  } catch { /* ignore */ }
}

/* ---------- Boot ---------- */
showTab(location.hash.slice(1));
openSession();
