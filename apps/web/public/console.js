import { $, $$, ApiError, VERDICT, api, clearErrors, fmtTime, h, init, reportError, setFieldError, toast } from "./ui.js";

init();

const output = $("#output");
const empty = $("#empty");
const results = new Map(); // kind -> stored report shown for that tab
let tab = "repository";

/* ---------- Tabs ---------- */
const TABS = ["repository", "message", "url", "activity"];
function moveInk() {
  const active = $(`[data-tab="${tab}"]`);
  const ink = $(".segmented__ink");
  if (!active || !ink) return;
  ink.style.left = `${active.offsetLeft}px`;
  ink.style.width = `${active.offsetWidth}px`;
}
function showTab(name) {
  tab = TABS.includes(name) ? name : "repository";
  for (const panel of $$("[data-panel]")) panel.hidden = panel.dataset.panel !== tab;
  for (const link of $$("[data-tab]")) link.toggleAttribute("aria-current", link.dataset.tab === tab);
  for (const link of $$("[data-tab]")) if (link.dataset.tab === tab) link.setAttribute("aria-current", "page");
  moveInk();
  $("#result")?.remove();
  empty.hidden = tab === "activity" || results.has(tab);
  if (results.has(tab)) render(results.get(tab), { scroll: false });
  if (tab === "activity") { refreshHistory(); refreshBlocklist(); }
}
addEventListener("hashchange", () => showTab(location.hash.slice(1)));
addEventListener("resize", moveInk);
document.fonts?.ready.then(moveInk);

/* ---------- Rendering ---------- */
const KIND_LABEL = { repository: "Repository scan", message: "Message review", url: "Link check" };
const ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

function download(name, data) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const link = h("a", { href: url, download: name, "data-no-transition": "" });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function findingRow(finding) {
  const location = finding.location ? `${finding.location.path}:${finding.location.line}` : finding.category;
  const title = finding.title.replace(/^Link \d+ \([^)]*\): /, "");
  return h("details", { class: "finding" },
    h("summary", {}, h("span", { class: `tag tag--${finding.severity}`, text: finding.severity }), h("span", { class: "title", text: title }), h("span", { class: "loc", text: location })),
    h("div", { class: "finding__body" },
      h("p", { text: finding.description }),
      h("p", {}, h("strong", { text: "Fix: " }), finding.remediation),
      h("ul", { class: "evidence" }, finding.evidence.slice(0, 3).map((item) => h("li", {}, h("span", { text: item.label }), item.value))),
      h("p", { class: "mono muted", css: { "font-size": ".68rem" }, text: `${finding.id} · ${finding.ruleId}` })));
}

function indicatorChip(indicator, reportId) {
  const button = h("button", { type: "button", text: indicator.blocked ? "Blocked" : "Block", "aria-label": `Block ${indicator.type} ${indicator.display}` });
  button.disabled = indicator.blocked;
  button.addEventListener("click", async () => {
    button.disabled = true;
    try {
      await api("/api/blocklist", { method: "POST", body: { tag: indicator.tag, reportId } });
      button.textContent = "Blocked";
      toast("success", "Indicator blocked", "Future reports that reuse it will be flagged.");
    } catch (error) {
      button.disabled = false;
      reportError(error);
    }
  });
  return h("span", { class: "indicator" }, h("small", { text: indicator.type.replace("_", " ") }), h("code", { text: indicator.display }),
    indicator.seenBefore ? h("small", { text: `×${indicator.seenBefore + 1}` }) : null, button);
}

function threatScenarioRow(scenario, findings) {
  const byId = new Map(findings.map((finding) => [finding.id, finding]));
  const evidence = scenario.findingIds.map((id) => byId.get(id)?.title).filter(Boolean);
  const signalTone = scenario.signal === "high" ? "critical" : scenario.signal === "medium" ? "high" : scenario.signal === "low" ? "medium" : "info";
  return h("details", { class: "finding" },
    h("summary", {}, h("span", { class: `tag tag--${signalTone}`, text: `${scenario.signal} signal` }),
      h("span", { class: "title", text: scenario.attackPath }), h("span", { class: "loc", text: `${scenario.impact} impact` })),
    h("div", { class: "finding__body" },
      h("p", {}, h("strong", { text: "Threat actor: " }), scenario.actor),
      h("p", {}, h("strong", { text: "Target asset: " }), scenario.targetAsset),
      h("p", {}, h("strong", { text: "Preconditions: " }), scenario.preconditions),
      h("p", {}, h("strong", { text: "Controls in this scan: " }), scenario.controls.join("; ")),
      h("p", {}, h("strong", { text: "Residual risk: " }), scenario.residualRisk),
      evidence.length ? h("p", {}, h("strong", { text: "Linked findings: " }), evidence.join("; ")) : null));
}

function render(stored, { scroll = true } = {}) {
  const { report, receipt, brief } = stored;
  results.set(report.kind, stored);
  if (tab !== report.kind) return;
  empty.hidden = true;
  $("#result")?.remove();
  const verdict = VERDICT[report.verdict] ?? { label: report.verdict, tone: "info" };
  const counts = {};
  for (const finding of report.findings) counts[finding.severity] = (counts[finding.severity] ?? 0) + 1;
  const findings = [...report.findings].sort((a, b) => ORDER[a.severity] - ORDER[b.severity]);
  const shown = findings.slice(0, 4);
  const list = h("div", { class: "findings" }, shown.map(findingRow));
  const moreButton = findings.length > shown.length
    ? h("button", { class: "pill pill--line pill--sm more", type: "button", text: `Show all ${findings.length}`, onclick: (event) => { list.replaceChildren(...findings.map(findingRow)); event.currentTarget.remove(); } })
    : null;

  const container = h("div", { class: "stack", id: "result" },
    h("section", { class: `verdict verdict--${verdict.tone}`, "aria-label": "Verdict" },
      h("div", { class: "verdict__top" },
        h("div", {}, h("p", { class: "verdict__label", text: verdict.label }), h("p", { class: "verdict__kind", text: `${KIND_LABEL[report.kind]} · ${fmtTime(report.createdAt)}` })),
        h("div", { class: "counts" }, Object.keys(ORDER).filter((s) => counts[s]).map((s) => h("span", { class: `tag tag--${s}`, text: `${counts[s]} ${s}` })),
          report.findings.length ? null : h("span", { class: "tag tag--success", text: "no findings" }))),
      h("p", { class: "verdict__headline", text: brief?.headline ?? report.summary }),
      brief?.points?.length ? h("ul", { class: "points" }, brief.points.map((point) => h("li", { text: point.text }))) : null,
      h("div", { class: "verdict__foot" },
        h("span", { class: "next", text: brief?.nextStep ?? report.mitigations[0]?.detail ?? "No action needed." }),
        h("div", { class: "stages", "aria-label": "Stages" }, [...report.stages.map((stage) => stage.name), "signed"].map((name, index) => h("span", { css: { "animation-delay": `${index * 90}ms` }, text: name }))))),

    report.findings.length ? h("section", { class: "card", "aria-labelledby": "findings-title" },
      h("div", { class: "card-head" }, h("h3", { id: "findings-title", text: "Findings" }), h("span", { class: "meta", text: `${report.findings.length} total` })),
      list, moreButton) : null,

    report.threatAssessment ? h("section", { class: "card", "aria-labelledby": "threat-model-title" },
      h("div", { class: "card-head" }, h("h3", { id: "threat-model-title", text: "Threat model" }), h("span", { class: "meta", text: report.threatAssessment.method.replace(/-/g, " ") })),
      h("p", { class: "muted", text: report.threatAssessment.scope }),
      h("div", { class: "findings" }, report.threatAssessment.scenarios.map((scenario) => threatScenarioRow(scenario, report.findings))),
      report.threatAssessment.coverageLimitations.length ? h("p", { class: "muted", text: `Coverage limits: ${report.threatAssessment.coverageLimitations.join("; ")}` }) : null) : null,

    report.indicators.length ? h("section", { class: "card", "aria-labelledby": "ind-title" },
      h("div", { class: "card-head" }, h("h3", { id: "ind-title", text: "Indicators" }), h("span", { class: "meta", text: "private tags" })),
      h("div", { class: "indicators" }, report.indicators.filter((item) => item.type !== "amount").map((item) => indicatorChip(item, report.id)))) : null,

    h("section", { class: "card", "aria-labelledby": "receipt-title" },
      h("div", { class: "card-head" }, h("h3", { id: "receipt-title", text: "Signed receipt" }),
        h("div", { class: "coverage" }, report.coverage.map((item) => h("span", { class: `chip ${item.status === "ran" ? "" : `is-${item.status}`}`, title: item.detail }, h("span", { class: "dot" }), item.detector.replace(/_/g, " "))))),
      h("div", { class: "receipt-row" },
        h("dl", {},
          h("dt", { text: "Digest" }), h("dd", { text: receipt.payload.reportDigest }),
          h("dt", { text: "Key" }), h("dd", { text: receipt.payload.keyId }),
          h("dt", { text: "Action" }), h("dd", { text: receipt.payload.action.replace(/_/g, " ") })),
        h("span", { class: "seal", "aria-hidden": "true" })),
      h("div", { class: "row", css: { "margin-top": "1rem" } },
        h("a", { class: "pill pill--dark pill--sm", href: `/verify#${encodeURIComponent(report.id)}`, onclick: () => sessionStorage.setItem("sw-verify", JSON.stringify(stored)) }, "Verify", h("span", { class: "arrow", "aria-hidden": "true" })),
        h("button", { class: "pill pill--line pill--sm", type: "button", text: "Receipt", onclick: () => download(`${report.id}.receipt.json`, receipt) }),
        h("button", { class: "pill pill--line pill--sm", type: "button", text: "Report", onclick: () => download(`${report.id}.report.json`, report) }))));

  output.prepend(container);
  if (scroll && container.getBoundingClientRect().top > innerHeight * 0.6) container.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function runScan(kind, body, frame) {
  if (frame) clearErrors(frame);
  frame?.classList.add("scanning");
  const buttons = frame ? $$("button", frame) : [];
  buttons.forEach((button) => (button.disabled = true));
  try {
    render(await api(`/api/scans/${kind}`, { method: "POST", body, timeout: 90_000 }));
  } catch (error) {
    reportError(error, frame?.tagName === "FORM" ? frame : undefined);
  } finally {
    frame?.classList.remove("scanning");
    buttons.forEach((button) => (button.disabled = false));
    $("#scan-repo").disabled = !selection.length;
  }
}

/* ---------- Repository intake ---------- */
const SKIP_DIRS = new Set(["node_modules", ".git", ".hg", ".svn", "dist", "build", ".next", "out", "coverage", "vendor", ".venv", "venv", "__pycache__", ".signalward", ".turbo", ".cache"]);
const BINARY = /\.(png|jpe?g|gif|webp|avif|ico|bmp|tiff?|psd|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|exe|dll|so|dylib|o|a|wasm|woff2?|ttf|otf|eot|mp[34]|mov|avi|webm|ogg|wav|flac|glb|gltf|bin|dat|db|sqlite|lockb)$/i;
const MAX_FILES = 2000, MAX_FILE = 1_000_000, MAX_TOTAL = 12_000_000;
let selection = [];
let selectionLabel = "uploaded files";

async function setSelection(entries, label) {
  $("#repo-meta").textContent = "Reading files…";
  const files = [];
  let total = 0, skipped = 0;
  for (const { path, file } of entries) {
    const keep = !path.split("/").some((part) => SKIP_DIRS.has(part)) && !BINARY.test(path) && file.size <= MAX_FILE;
    if (!keep || files.length >= MAX_FILES || total + file.size > MAX_TOTAL) { skipped++; continue; }
    total += file.size;
    try {
      files.push({ path, content: await file.text() });
    } catch {
      skipped++;
    }
  }
  selection = files;
  selectionLabel = label;
  $("#repo-meta").textContent = files.length
    ? `${label} · ${files.length} files · ${(total / 1024).toFixed(0)} KB${skipped ? ` · ${skipped} skipped` : ""}`
    : "No readable text files in that selection.";
  $("#scan-repo").disabled = !files.length;
  if (!files.length && entries.length) toast("warning", "Nothing to scan", "Every file was skipped as binary, too large or build output.");
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
  if (entry.isFile) out.push({ path: `${prefix}${entry.name}`, file: await new Promise((resolve, reject) => entry.file(resolve, reject)) });
  else if (entry.isDirectory && !SKIP_DIRS.has(entry.name)) {
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
  try {
    const items = [...event.dataTransfer.items].map((item) => item.webkitGetAsEntry?.()).filter(Boolean);
    const out = [];
    for (const entry of items) await walkEntry(entry, "", out);
    const single = items.length === 1 && items[0].isDirectory ? `${items[0].name}/` : "";
    await setSelection(out.map(({ path, file }) => ({ path: single && path.startsWith(single) ? path.slice(single.length) : path, file })), single ? items[0].name : "dropped files");
  } catch {
    toast("error", "Couldn't read the drop", "Your browser blocked access to those files. Use Choose folder instead.");
  }
});
$("#scan-repo").addEventListener("click", () => runScan("repository", { files: selection, label: selectionLabel }, $('[data-panel="repository"]')));
for (const button of $$("[data-repo-sample]")) button.addEventListener("click", () => runScan("repository", { sample: button.dataset.repoSample }, $('[data-panel="repository"]')));

/* ---------- Message and link intake ---------- */
$("#message-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const text = form.elements.text.value.trim();
  if (!text) return setFieldError(form.elements.text, "Paste the message you want to check.");
  runScan("message", { text, sender: form.elements.sender.value.trim(), subject: form.elements.subject.value.trim() }, form);
});
for (const button of $$("[data-message-sample]")) button.addEventListener("click", () => runScan("message", { sample: button.dataset.messageSample }, $("#message-form")));
$("#url-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const url = form.elements.url.value.trim();
  if (!url) return setFieldError(form.elements.url, "Enter a link or domain.");
  runScan("url", { url }, form);
});
for (const chip of $$("[data-url-sample]")) chip.addEventListener("click", () => {
  $("#url-form").elements.url.value = chip.dataset.urlSample;
  runScan("url", { url: chip.dataset.urlSample }, $("#url-form"));
});

/* ---------- Activity ---------- */
const KIND_SHORT = { repository: "GIT", message: "MSG", url: "URL" };
async function refreshHistory() {
  const host = $("#history");
  host.replaceChildren(h("div", { class: "skeleton", css: { height: "3rem" } }));
  try {
    const { reports } = await api("/api/reports");
    if (!reports.length) return host.replaceChildren(h("p", { class: "muted", text: "No reports yet." }));
    host.replaceChildren(...reports.slice(0, 12).map((item) => {
      const verdict = VERDICT[item.verdict] ?? { label: item.verdict, tone: "info" };
      return h("div", { class: "list__row" },
        h("span", { class: "kind", text: KIND_SHORT[item.kind] }),
        h("button", { class: "link", type: "button", onclick: () => openReport(item.id) }, h("b", { text: item.summary }), h("span", { text: `${fmtTime(item.createdAt)} · ${item.findings} findings` })),
        h("span", { class: `tag tag--${verdict.tone}`, text: verdict.label }));
    }));
  } catch (error) {
    host.replaceChildren(h("p", { class: "muted", text: "Reports could not be loaded." }));
    reportError(error);
  }
}
async function openReport(id) {
  try {
    const stored = await api(`/api/reports/${encodeURIComponent(id)}`);
    results.set(stored.report.kind, stored);
    location.hash = `#${stored.report.kind}`;
  } catch (error) {
    reportError(error);
  }
}
async function refreshBlocklist() {
  const host = $("#blocklist");
  try {
    const { entries } = await api("/api/blocklist");
    if (!entries.length) return host.replaceChildren(h("p", { class: "muted", text: "Nothing blocked yet." }));
    host.replaceChildren(...entries.map((entry) => h("div", { class: "list__row" },
      h("span", { class: "kind", text: entry.type.slice(0, 3).toUpperCase() }),
      h("div", {}, h("b", {}, h("code", { text: entry.display })), h("span", { text: `added ${fmtTime(entry.addedAt)}` })),
      h("button", { class: "pill pill--line pill--sm", type: "button", text: "Unblock", onclick: async () => {
        try { await api("/api/blocklist", { method: "DELETE", body: { tag: entry.tag } }); refreshBlocklist(); } catch (error) { reportError(error); }
      } }))));
  } catch (error) {
    reportError(error);
  }
}

function logEvent(text) {
  const list = $("#events");
  if (list.firstElementChild?.classList.contains("muted")) list.replaceChildren();
  list.prepend(h("li", {}, h("time", { text: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" }) }), text));
  while (list.children.length > 50) list.lastElementChild.remove();
}
function connectEvents() {
  const source = new EventSource("/api/events");
  source.addEventListener("ready", () => { $("#live").classList.remove("is-off"); $("#events-state").textContent = "live"; });
  source.addEventListener("activity", (message) => {
    const event = JSON.parse(message.data);
    if (event.type === "scan.started") logEvent(`${KIND_LABEL[event.kind] ?? event.kind} started`);
    else if (event.type === "scan.completed") { logEvent(`${KIND_LABEL[event.kind]}: ${VERDICT[event.verdict]?.label ?? event.verdict}, ${event.findings} findings`); if (tab === "activity") refreshHistory(); }
    else if (event.type === "blocklist.added") { logEvent(`Blocked a ${event.indicatorType.replace("_", " ")}`); if (tab === "activity") refreshBlocklist(); }
    else if (event.type === "blocklist.removed") logEvent("Removed an indicator from the blocklist");
    else if (event.type === "data.erased") logEvent("Account data erased");
  });
  source.addEventListener("error", () => { $("#live").classList.add("is-off"); $("#events-state").textContent = "reconnecting…"; });
}

/* ---------- Boot ---------- */
showTab(location.hash.slice(1));
connectEvents();
const prefill = new URLSearchParams(location.search).get("url");
if (prefill) {
  history.replaceState(null, "", "/scan#url");
  showTab("url");
  $("#url-form").elements.url.value = prefill.slice(0, 2048);
  runScan("url", { url: prefill.slice(0, 2048) }, $("#url-form"));
}
export { ApiError };
