/**
 * Domain reference data. Brand, shortener, hosting and TLD lists are adapted from Veriq's analysis package
 * (MIT, same authors). They are detection aids, not allowlists: an unlisted domain is not assumed malicious.
 */

export type Brand = { name: string; tokens: string[]; domains: string[] };

export const BRANDS: Brand[] = [
  { name: "PayPal", tokens: ["paypal"], domains: ["paypal.com", "paypal.me", "paypalobjects.com"] },
  { name: "Google", tokens: ["google", "gmail"], domains: ["google.com", "gmail.com", "google.co.in", "googleusercontent.com", "gstatic.com", "googleapis.com", "youtube.com", "goo.gl", "g.co", "android.com"] },
  { name: "Microsoft", tokens: ["microsoft", "outlook", "office365", "onedrive", "hotmail", "sharepoint"], domains: ["microsoft.com", "live.com", "outlook.com", "office.com", "office365.com", "microsoftonline.com", "hotmail.com", "sharepoint.com", "onedrive.com", "msn.com", "azure.com", "bing.com"] },
  { name: "Apple", tokens: ["apple", "icloud", "itunes"], domains: ["apple.com", "icloud.com", "apple.co", "itunes.com", "me.com"] },
  { name: "Amazon", tokens: ["amazon"], domains: ["amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazonaws.com", "amazon.jobs"] },
  { name: "Meta / Facebook", tokens: ["facebook", "instagram", "whatsapp", "messenger"], domains: ["facebook.com", "fb.com", "instagram.com", "whatsapp.com", "whatsapp.net", "messenger.com", "meta.com"] },
  { name: "Netflix", tokens: ["netflix"], domains: ["netflix.com"] },
  { name: "LinkedIn", tokens: ["linkedin"], domains: ["linkedin.com", "lnkd.in"] },
  { name: "GitHub", tokens: ["github"], domains: ["github.com", "githubusercontent.com", "githubassets.com"] },
  { name: "Dropbox", tokens: ["dropbox"], domains: ["dropbox.com", "dropboxusercontent.com"] },
  { name: "DHL", tokens: ["dhl"], domains: ["dhl.com", "dhl.de", "dhl.co.in"] },
  { name: "FedEx", tokens: ["fedex"], domains: ["fedex.com"] },
  { name: "India Post", tokens: ["indiapost"], domains: ["indiapost.gov.in"] },
  { name: "State Bank of India", tokens: ["sbi", "onlinesbi", "yonosbi"], domains: ["onlinesbi.sbi", "sbi.co.in", "onlinesbi.com", "sbicard.com", "sbi.bank.in"] },
  { name: "HDFC Bank", tokens: ["hdfc", "hdfcbank"], domains: ["hdfcbank.com", "hdfc.com", "hdfc.bank.in"] },
  { name: "ICICI Bank", tokens: ["icici", "icicibank"], domains: ["icicibank.com", "icici.bank.in"] },
  { name: "Axis Bank", tokens: ["axisbank"], domains: ["axisbank.com", "axis.bank.in"] },
  { name: "Paytm", tokens: ["paytm"], domains: ["paytm.com", "paytm.in"] },
  { name: "PhonePe", tokens: ["phonepe"], domains: ["phonepe.com"] },
  { name: "NPCI / UPI", tokens: ["npci", "bhim"], domains: ["npci.org.in", "bhimupi.org.in"] },
  { name: "Income Tax Department (India)", tokens: ["incometax", "efiling"], domains: ["incometax.gov.in", "incometaxindia.gov.in"] },
  { name: "UIDAI / Aadhaar", tokens: ["uidai", "aadhaar", "aadhar"], domains: ["uidai.gov.in"] },
  { name: "Binance", tokens: ["binance"], domains: ["binance.com"] },
  { name: "Coinbase", tokens: ["coinbase"], domains: ["coinbase.com"] },
  { name: "MetaMask", tokens: ["metamask"], domains: ["metamask.io"] },
  { name: "Chase", tokens: ["chase", "jpmorgan"], domains: ["chase.com", "jpmorgan.com", "jpmorganchase.com"] },
  { name: "Wells Fargo", tokens: ["wellsfargo"], domains: ["wellsfargo.com"] },
  { name: "Bank of America", tokens: ["bankofamerica"], domains: ["bankofamerica.com", "bofa.com"] },
  { name: "HSBC", tokens: ["hsbc"], domains: ["hsbc.com", "hsbc.co.in", "hsbc.co.uk"] },
  { name: "DocuSign", tokens: ["docusign"], domains: ["docusign.com", "docusign.net"] },
  { name: "Steam", tokens: ["steampowered", "steamcommunity"], domains: ["steampowered.com", "steamcommunity.com"] },
];

export const AUTHORITY_TERMS = ["police", "cyber cell", "cyber crime", "customs", "income tax department", "reserve bank", "rbi", "trai", "cbi", "enforcement directorate", "narcotics", "court", "irs", "hmrc"];

export const URL_SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly", "rb.gy", "s.id", "shorturl.at", "ow.ly", "buff.ly", "tiny.cc", "rebrand.ly", "t.ly", "v.gd", "bl.ink", "qrco.de", "short.gy", "clck.ru"]);

/** Platforms where anyone can publish under a shared parent. Treated as public suffixes for ownership. */
export const SHARED_HOSTING_SUFFIXES = ["000webhostapp.com", "weebly.com", "wixsite.com", "netlify.app", "vercel.app", "pages.dev", "workers.dev", "github.io", "firebaseapp.com", "web.app", "glitch.me", "ngrok-free.app", "ngrok.io", "trycloudflare.com", "duckdns.org", "blogspot.com", "godaddysites.com", "webflow.io", "framer.website", "replit.app", "onrender.com", "herokuapp.com", "azurewebsites.net", "appspot.com", "r2.dev", "ipfs.io", "carrd.co"];

const MULTI_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "ltd.uk", "plc.uk",
  "co.in", "net.in", "org.in", "gov.in", "ac.in", "nic.in", "bank.in", "firm.in", "gen.in", "ind.in", "edu.in", "res.in",
  "com.au", "net.au", "org.au", "gov.au", "edu.au", "co.nz", "org.nz", "govt.nz", "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
  "com.br", "gov.br", "com.cn", "gov.cn", "com.mx", "gob.mx", "co.za", "gov.za", "com.sg", "gov.sg", "com.my", "co.id", "go.id",
  "com.tr", "gov.tr", "com.ar", "co.kr", "go.kr", "com.hk", "gov.hk", "com.pk", "gov.pk", "com.bd", "gov.bd", "com.ng", "gov.ng",
  "co.ke", "com.ph", "gov.ph", "com.vn", "com.tw", "gov.tw", "co.th", "go.th", "com.sa", "gov.sa", "com.eg", "com.ua", "gov.ua",
  ...SHARED_HOSTING_SUFFIXES,
]);

/** TLDs accepted when a bare domain appears in prose without a scheme. Keeps "report.pdf" out of the link list. */
export const PROSE_TLDS = new Set(("com net org info biz io co ai app dev me us uk in au ca de fr es it nl ru cn jp br mx za sg my id tr ar kr hk pk bd ng ke ph vn tw th sa ae qa eg ua il " +
  "xyz top tk ml ga cf gq pw shop store online site live support help link click club vip win bid loan work today services finance money bank " +
  "pro tech cloud digital ws su to cc tv gov edu eu ch se no dk fi pl cz pt gr ie be at hu ro nz lk np cyou icu rest monster buzz sbs cfd lol quest bond fit kim zip mov page sbi").split(" "));

export const RESERVED_TLDS = new Set(["localhost", "local", "internal", "lan", "home", "corp", "test", "invalid", "example", "intranet", "private", "arpa"]);

export const HIGH_ABUSE_TLDS = new Set(["zip", "mov", "xyz", "top", "tk", "ml", "ga", "cf", "gq", "cyou", "icu", "click", "link", "rest", "monster", "buzz", "sbs", "cfd", "lol", "quest", "bond", "shop", "online", "site", "live", "support", "help", "work", "fit", "kim", "loan", "win", "bid"]);

export function splitDomain(hostname: string): { registrableDomain: string | null; publicSuffix: string | null; subdomain: string | null } {
  const labels = hostname.split(".").filter(Boolean);
  if (labels.length < 2) return { registrableDomain: null, publicSuffix: labels[0] ?? null, subdomain: null };
  for (const size of [3, 2]) {
    if (labels.length > size && MULTI_LABEL_SUFFIXES.has(labels.slice(-size).join("."))) {
      return { registrableDomain: labels.slice(-(size + 1)).join("."), publicSuffix: labels.slice(-size).join("."), subdomain: labels.slice(0, -(size + 1)).join(".") || null };
    }
    if (labels.length === size && MULTI_LABEL_SUFFIXES.has(labels.join("."))) return { registrableDomain: null, publicSuffix: labels.join("."), subdomain: null };
  }
  return { registrableDomain: labels.slice(-2).join("."), publicSuffix: labels.at(-1) ?? null, subdomain: labels.slice(0, -2).join(".") || null };
}

export function isOfficialDomain(brand: Brand, registrableDomain: string | null, hostname?: string): boolean {
  const candidates = [registrableDomain, hostname].filter((value): value is string => Boolean(value));
  return brand.domains.some((domain) => candidates.some((candidate) => candidate === domain || candidate.endsWith(`.${domain}`)));
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function findBrandMentions(text: string): Brand[] {
  const lower = text.toLowerCase();
  return BRANDS.filter((brand) => {
    const names = [brand.name.toLowerCase().split(" / ")[0] ?? "", ...brand.tokens];
    return names.some((token) => token.length >= 3 && new RegExp(`(^|[^a-z0-9])${escapeRegExp(token)}([^a-z0-9]|$)`).test(lower));
  });
}

export function sharedHostingPlatform(hostname: string): string | null {
  return SHARED_HOSTING_SUFFIXES.find((suffix) => hostname === suffix || hostname.endsWith(`.${suffix}`)) ?? null;
}
