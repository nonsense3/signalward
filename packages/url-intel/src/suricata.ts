import type { Finding, Severity } from "../../contracts/src/index.ts";
import { finding } from "../../fraud-scan/src/rules.ts";

export type SuricataAlertEvent = {
  timestamp?: string;
  event_type?: string;
  src_ip?: string;
  src_port?: number;
  dest_ip?: string;
  dest_port?: number;
  proto?: string;
  alert?: { signature?: string; signature_id?: number; category?: string; severity?: number; action?: string };
};

const safeText = (value: unknown, limit: number) => typeof value === "string"
  ? value.replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\p{Cf}/gu, "").replace(/\s+/g, " ").trim().slice(0, limit)
  : "";

/** Convert one genuine Suricata EVE alert to an evidence-linked finding; other EVE records are ignored. */
export function suricataAlertFinding(value: unknown): Finding | null {
  if (!value || typeof value !== "object") return null;
  const event = value as SuricataAlertEvent;
  if (event.event_type !== "alert" || !event.alert || typeof event.alert !== "object") return null;
  const signature = safeText(event.alert.signature, 180);
  const sid = Number(event.alert.signature_id);
  const priority = Number(event.alert.severity);
  if (!signature || !Number.isSafeInteger(sid) || sid < 1 || !Number.isInteger(priority) || priority < 1 || priority > 4) return null;
  const severity: Severity = priority === 1 ? "high" : priority === 2 ? "medium" : priority === 3 ? "low" : "info";
  const srcIp = safeText(event.src_ip, 64);
  const destIp = safeText(event.dest_ip, 64);
  const srcPort = Number.isInteger(event.src_port) && event.src_port! >= 0 && event.src_port! <= 65535 ? event.src_port : null;
  const destPort = Number.isInteger(event.dest_port) && event.dest_port! >= 0 && event.dest_port! <= 65535 ? event.dest_port : null;
  const timestamp = typeof event.timestamp === "string" && Number.isFinite(Date.parse(event.timestamp)) ? event.timestamp.slice(0, 40) : "unknown";
  const category = safeText(event.alert.category, 100) || "Uncategorized";
  const sensorAction = typeof event.alert.action === "string" && ["allowed", "blocked"].includes(event.alert.action.toLowerCase())
    ? event.alert.action.toLowerCase()
    : "unknown";
  const protocol = safeText(event.proto, 24).toLowerCase() || "unknown";
  const source = `${srcIp || "unknown"}${srcPort === null ? "" : `:${srcPort}`}`;
  const destination = `${destIp || "unknown"}${destPort === null ? "" : `:${destPort}`}`;
  return finding({
    ruleId: "network.suricata_alert",
    category: "intelligence",
    severity,
    confidence: priority <= 2 ? "high" : "medium",
    title: `Suricata: ${signature}`,
    description: `Suricata emitted signature SID ${sid} (${category}) for ${protocol} traffic. SignalWard did not capture or inspect packet payloads.`,
    impact: "The configured network sensor matched its enabled detection rules; validate the alert in the sensor and surrounding logs.",
    remediation: "Review the SID, affected endpoints, and surrounding events. Apply containment only after validating the alert.",
    evidence: [
      { label: "Suricata SID", value: String(sid) },
      { label: "Priority", value: String(priority) },
      { label: "Sensor action", value: sensorAction },
      { label: "Category", value: category },
      { label: "Flow", value: `${source} → ${destination} (${protocol})` },
      { label: "Observed at", value: timestamp },
    ],
  });
}
