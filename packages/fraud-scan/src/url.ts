import { domainToUnicode } from "node:url";
import { RESERVED_TLDS, splitDomain } from "./domains.ts";

export type UrlEvidence = {
  input: string;
  normalized: string;
  scheme: string;
  hostname: string;
  unicodeHostname: string;
  registrableDomain: string | null;
  publicSuffix: string | null;
  subdomain: string | null;
  port: number | null;
  isIp: boolean;
  isPrivateIp: boolean;
  hadUserinfo: boolean;
  path: string;
  query: string;
};

export type NormalizeResult = { ok: true; value: UrlEvidence } | { ok: false; code: "URL_INVALID" | "UNSUPPORTED_SCHEME" | "HOST_NOT_PUBLIC"; message: string };

/** Undo common defanging so analysts can paste `hxxps://evil[.]com`. */
export function refang(input: string): string {
  return input.replace(/^hxxp/i, "http").replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]/gi, ".").replace(/\[:\]/g, ":");
}

const PRIVATE_V4 = /^(10\.|127\.|0\.|192\.168\.|169\.254\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/;

/** Normalise a URL or bare domain without contacting it. SignalWard never fetches submitted links. */
export function normalizeTarget(rawInput: string): NormalizeResult {
  let input = refang(String(rawInput).trim()).replace(/^<|>$/g, "").replace(/^["']|["']$/g, "");
  if (!input) return { ok: false, code: "URL_INVALID", message: "Enter a URL or domain." };
  if (/\s/.test(input)) return { ok: false, code: "URL_INVALID", message: "A URL cannot contain spaces." };
  if (input.length > 2048) return { ok: false, code: "URL_INVALID", message: "The URL is longer than 2048 characters." };

  const scheme = /^([a-z][a-z0-9+\-.]*):/i.exec(input)?.[1]?.toLowerCase();
  const looksLikeHostPort = /^[^/:]+:\d+(\/|$)/.test(input) && !input.includes("://");
  if (scheme && !looksLikeHostPort) {
    if (scheme !== "http" && scheme !== "https") return { ok: false, code: "UNSUPPORTED_SCHEME", message: "Only HTTP and HTTPS links can be analysed." };
    if (!/^https?:\/\//i.test(input)) input = input.replace(/^(https?):\/*/i, "$1://");
  } else {
    input = `https://${input.replace(/^\/+/, "")}`;
  }

  let url: URL;
  try {
    url = new URL(input);
  } catch {
    return { ok: false, code: "URL_INVALID", message: "This does not look like a valid URL or domain." };
  }
  const hadUserinfo = Boolean(url.username || url.password);
  url.username = "";
  url.password = "";
  url.hash = "";
  const hostname = url.hostname.replace(/\.$/, "").toLowerCase().replace(/^\[|\]$/g, "");
  if (!hostname) return { ok: false, code: "URL_INVALID", message: "The URL has no host name." };

  const isIpV4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(hostname);
  const isIp = isIpV4 || hostname.includes(":");
  const tld = hostname.split(".").pop() ?? "";
  if (!isIp && (RESERVED_TLDS.has(tld) || !hostname.includes(".") || !/^[a-z]{2,24}$|^xn--[a-z0-9-]{2,59}$/.test(tld))) {
    return { ok: false, code: "HOST_NOT_PUBLIC", message: "Only public internet domains can be analysed. Local and reserved names are refused." };
  }
  const parts = isIp ? { registrableDomain: null, publicSuffix: null, subdomain: null } : splitDomain(hostname);
  if (!isIp && !parts.registrableDomain) return { ok: false, code: "URL_INVALID", message: "The host is a public suffix, not a website." };

  return {
    ok: true,
    value: {
      input: String(rawInput).trim().slice(0, 2048),
      normalized: url.toString(),
      scheme: url.protocol.replace(":", ""),
      hostname,
      unicodeHostname: isIp ? hostname : domainToUnicode(hostname) || hostname,
      ...parts,
      port: url.port ? Number(url.port) : null,
      isIp,
      isPrivateIp: (isIpV4 && PRIVATE_V4.test(hostname)) || hostname === "::1" || /^f[cd]/i.test(hostname) || /^fe80/i.test(hostname),
      hadUserinfo,
      path: url.pathname,
      query: url.search,
    },
  };
}

export function registrableLabel(u: Pick<UrlEvidence, "registrableDomain" | "publicSuffix">): string {
  if (!u.registrableDomain) return "";
  if (!u.publicSuffix) return u.registrableDomain;
  return u.registrableDomain.slice(0, -(u.publicSuffix.length + 1));
}
