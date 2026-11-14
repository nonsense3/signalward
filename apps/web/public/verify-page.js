import { $, h, init, reportError, setFieldError, clearErrors, toast } from "./ui.js";
import { fetchTrustedKeys, verifyReceipt } from "./verify.js";

init();

const form = $("#verify-form");
const out = $("#verify-result");
let keys = [];

async function loadKeys() {
  try {
    keys = await fetchTrustedKeys();
    $("#keys").replaceChildren(...keys.map((key) => h("div", { class: "list__row" }, h("span", { class: "kind", text: "ED" }),
      h("div", {}, h("b", { text: key.kid }), h("span", { text: key.createdAt ? `since ${new Date(key.createdAt).toLocaleDateString()}` : "configured key" })), h("span", { class: "tag tag--success", text: "trusted" }))));
  } catch {
    $("#keys").replaceChildren(h("p", { class: "notice notice--error", text: "The trusted key set could not be loaded, so signatures cannot be checked." }));
  }
}

function parse(name) {
  const input = form.elements[name];
  const text = input.value.trim();
  if (!text) return undefined;
  try {
    return JSON.parse(text);
  } catch {
    setFieldError(input, `This is not valid JSON. ${name === "receipt" ? "Paste the whole receipt file." : "Paste the whole report file."}`);
    throw new Error("invalid json");
  }
}

async function run() {
  clearErrors(form);
  let receipt, report;
  try {
    receipt = parse("receipt");
    report = parse("report");
  } catch {
    return;
  }
  if (!receipt) return setFieldError(form.elements.receipt, "Paste a receipt to verify.");
  if (!keys.length) await loadKeys();
  try {
    const result = await verifyReceipt(receipt, keys, report);
    $("#verify-empty").hidden = true;
    out.hidden = false;
    out.className = `verify-result verdict verdict--${result.valid ? "success" : "danger"}`;
    out.replaceChildren(
      h("div", { class: "verdict__top" }, h("div", {}, h("p", { class: "verdict__label", text: result.valid ? "Authentic" : "Not valid" }),
        h("p", { class: "verdict__kind", text: receipt?.payload?.reportId ?? "unknown report" }))),
      h("p", { class: "verdict__headline", text: result.valid ? "The signature is genuine and the report matches it." : "At least one check failed. Do not rely on this report." }),
      h("ol", { class: "checks" }, result.checks.map((check, index) => h("li", { class: check.ok ? "ok" : "fail", css: { "animation-delay": `${index * 80}ms` } },
        h("span", { class: "mark", "aria-label": check.ok ? "passed" : "failed", text: check.ok ? "✓" : "✕" }), h("b", { text: check.check.replace("_", " ") }), h("span", { text: check.detail })))));
  } catch (error) {
    reportError(error);
  }
}

form.addEventListener("submit", (event) => {
  event.preventDefault();
  run();
});

$("#tamper").addEventListener("click", () => {
  try {
    const receipt = JSON.parse(form.elements.receipt.value);
    const flipped = { pass: "block", block: "pass", incomplete: "pass", low_risk: "high_risk", suspicious: "low_risk", high_risk: "low_risk", inconclusive: "low_risk" };
    receipt.payload.verdict = flipped[receipt.payload.verdict] ?? "pass";
    form.elements.receipt.value = JSON.stringify(receipt, null, 2);
    toast("info", "Verdict changed", `The receipt now claims "${receipt.payload.verdict.replace("_", " ")}". Verification should fail.`);
    run();
  } catch {
    setFieldError(form.elements.receipt, "Load a receipt first.");
  }
});

$("#files").addEventListener("change", async (event) => {
  for (const file of event.target.files) {
    if (file.size > 2_000_000) { toast("warning", "File too large", `${file.name} is over 2 MB.`); continue; }
    try {
      const data = JSON.parse(await file.text());
      if (data?.schema === "signalward.receipt/v1") form.elements.receipt.value = JSON.stringify(data, null, 2);
      else if (data?.schema === "signalward.report/v1") form.elements.report.value = JSON.stringify(data, null, 2);
      else toast("warning", "Unrecognised file", `${file.name} is not a SignalWard receipt or report.`);
    } catch {
      toast("warning", "Unreadable file", `${file.name} is not valid JSON.`);
    }
  }
  event.target.value = "";
  if (form.elements.receipt.value) run();
});

loadKeys();
const handoff = sessionStorage.getItem("sw-verify");
if (handoff) {
  sessionStorage.removeItem("sw-verify");
  try {
    const stored = JSON.parse(handoff);
    form.elements.receipt.value = JSON.stringify(stored.receipt, null, 2);
    form.elements.report.value = JSON.stringify(stored.report, null, 2);
    run();
  } catch { /* ignore a corrupt handoff */ }
}
