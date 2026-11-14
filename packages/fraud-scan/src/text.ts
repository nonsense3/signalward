/** String utilities for the deterministic rules (adapted from Veriq's analysis package, MIT). */

export function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  if (!a.length) return b.length;
  if (!b.length) return a.length;
  let previous = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i += 1) {
    const current = [i];
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      current[j] = Math.min((current[j - 1] ?? 0) + 1, (previous[j] ?? 0) + 1, (previous[j - 1] ?? 0) + cost);
    }
    previous = current;
  }
  return previous[b.length] ?? 0;
}

/** Characters commonly substituted to imitate Latin letters (homoglyphs and digit swaps). */
const CONFUSABLES: Record<string, string> = {
  "а": "a", "в": "b", "е": "e", "ё": "e", "к": "k", "м": "m", "н": "h", "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x",
  "і": "i", "ј": "j", "ԁ": "d", "ӏ": "l", "ѕ": "s", "ԛ": "q", "ԝ": "w", "ɡ": "g", "һ": "h", "ո": "n", "ս": "u",
  "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w",
  "ı": "i", "ł": "l", "ɩ": "i", "ɑ": "a", "ø": "o", "ö": "o", "ó": "o", "ò": "o", "ô": "o", "õ": "o", "á": "a", "à": "a",
  "â": "a", "ä": "a", "å": "a", "ã": "a", "é": "e", "è": "e", "ê": "e", "ë": "e", "í": "i", "ì": "i", "î": "i", "ï": "i",
  "ú": "u", "ù": "u", "û": "u", "ü": "u", "ç": "c", "ñ": "n", "ý": "y",
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s",
};

/** Map a label to a comparison skeleton so `paypa1`, `pаypal` (Cyrillic а) and `paypal` collide. */
export function skeleton(value: string): string {
  let output = "";
  for (const char of value.toLowerCase().normalize("NFKC")) output += CONFUSABLES[char] ?? char;
  return output.replace(/rn/g, "m").replace(/vv/g, "w").replace(/[^a-z]/g, "");
}

export function scriptsIn(label: string): Set<string> {
  const scripts = new Set<string>();
  for (const char of label) {
    const code = char.codePointAt(0) ?? 0;
    if ((code >= 0x61 && code <= 0x7a) || (code >= 0x41 && code <= 0x5a) || (code >= 0xc0 && code <= 0x24f)) scripts.add("latin");
    else if (code >= 0x400 && code <= 0x52f) scripts.add("cyrillic");
    else if (code >= 0x370 && code <= 0x3ff) scripts.add("greek");
    else if (code >= 0x530 && code <= 0x58f) scripts.add("armenian");
    else if (!/[0-9\-_.]/.test(char)) scripts.add("other");
  }
  return scripts;
}

export function shannonEntropy(value: string): number {
  if (!value.length) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let bits = 0;
  for (const count of counts.values()) {
    const p = count / value.length;
    bits -= p * Math.log2(p);
  }
  return bits;
}

export function truncate(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}
