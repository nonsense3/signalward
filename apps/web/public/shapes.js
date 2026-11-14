/**
 * Target formations for the particle field. Each shape is a Float32Array of count * 4 values:
 * x, y, z and a flag (1 marks a "finding" particle tinted coral). Shapes are procedural and original.
 * Shape IDs used by the scene: 0 is the procedural spectral stream; 1..N map to SHAPES[id - 1].
 */

export const SHAPE_NAMES = ["radar", "lattice", "knot", "fingerprint", "shield", "receipt", "globe"];

function rng(seed) {
  let state = seed >>> 0;
  return () => ((state = (Math.imul(state, 1664525) + 1013904223) >>> 0) / 4294967296);
}

function fill(count, seed, generator) {
  const out = new Float32Array(count * 4);
  const random = rng(seed);
  for (let i = 0; i < count; i++) {
    // Golden-ratio sequence instead of i / count: every prefix of the particle list samples every part
    // of the shape, so drawing fewer particles (adaptive quality) thins the formation evenly.
    const t = (i * 0.6180339887498949) % 1;
    const [x, y, z, flag = 0] = generator(t, random, i);
    out.set([x, y, z, flag], i * 4);
  }
  return out;
}

const TAU = Math.PI * 2;
const gauss = (random) => (random() + random() + random() - 1.5) * 0.66;

function sphere(random, radius, jitter = 0.02) {
  const u = random() * 2 - 1;
  const a = random() * TAU;
  const s = Math.sqrt(1 - u * u);
  const r = radius + gauss(random) * jitter;
  return [Math.cos(a) * s * r, u * r, Math.sin(a) * s * r];
}

function rotateX([x, y, z], angle) {
  const c = Math.cos(angle), s = Math.sin(angle);
  return [x, y * c - z * s, y * s + z * c];
}

function rotateZ([x, y, z], angle) {
  const c = Math.cos(angle), s = Math.sin(angle);
  return [x * c - y * s, x * s + y * c, z];
}

/** Real-time detection: a sensor sphere with sweep rings and a few flagged contacts. */
function radar(t, random) {
  if (t < 0.52) return sphere(random, 1.02, 0.015);
  if (t < 0.8) {
    const ring = Math.floor(random() * 3);
    const a = random() * TAU;
    const r = 1.32 + ring * 0.13 + gauss(random) * 0.01;
    return rotateZ(rotateX([Math.cos(a) * r, 0, Math.sin(a) * r], 1.2 + ring * 0.32), ring * 0.7);
  }
  if (t < 0.93) return sphere(random, 0.18 + random() * 0.12, 0.05);
  const contact = Math.floor(random() * 3);
  const centers = [[0.62, 0.55, 0.55], [-0.75, 0.2, 0.68], [0.18, -0.82, 0.55]];
  const [cx, cy, cz] = centers[contact];
  return [cx + gauss(random) * 0.06, cy + gauss(random) * 0.06, cz + gauss(random) * 0.06, 1];
}

/** Zero trust: nested gates. Every boundary is drawn; nothing inside is implicitly trusted. */
function lattice(t, random) {
  const sizes = [1.2, 0.82, 0.44];
  const level = t < 0.45 ? 0 : t < 0.78 ? 1 : 2;
  const s = sizes[level];
  const p = [random() < 0.5 ? -s : s, random() < 0.5 ? -s : s, random() < 0.5 ? -s : s];
  // Most particles trace the cube edges; a few gather on the corners as gate nodes.
  const corner = random() < 0.06;
  if (!corner) p[Math.floor(random() * 3)] = (random() * 2 - 1) * s;
  const jitter = corner ? 0.025 : 0.008;
  const spin = level * 0.42;
  const c = Math.cos(spin), q = Math.sin(spin);
  return [p[0] * c - p[2] * q + gauss(random) * jitter, p[1] + gauss(random) * jitter, p[0] * q + p[2] * c + gauss(random) * jitter];
}

/** Privacy-preserving computation: a trefoil knot. Values pass through, their order is kept, contents stay sealed. */
function knot(t, random) {
  const u = random() * TAU;
  const v = random() * TAU;
  const p = 2, q = 3;
  const R = 0.78, r = 0.3, tube = 0.09 + random() * 0.03;
  const point = (a) => [
    (R + r * Math.cos(q * a)) * Math.cos(p * a),
    (R + r * Math.cos(q * a)) * Math.sin(p * a),
    r * Math.sin(q * a),
  ];
  const c = point(u);
  const n = point(u + 0.001);
  const tangent = n.map((value, i) => value - c[i]);
  const length = Math.hypot(...tangent);
  const tn = tangent.map((value) => value / length);
  let normal = [-tn[1], tn[0], 0];
  const nl = Math.hypot(...normal) || 1;
  normal = normal.map((value) => value / nl);
  const binormal = [tn[1] * normal[2] - tn[2] * normal[1], tn[2] * normal[0] - tn[0] * normal[2], tn[0] * normal[1] - tn[1] * normal[0]];
  return c.map((value, i) => (value + (normal[i] * Math.cos(v) + binormal[i] * Math.sin(v)) * tube) * 1.25);
}

/** Identity: a fingerprint of broken concentric ridges on a curved pad. */
function fingerprint(t, random) {
  for (let attempt = 0; attempt < 12; attempt++) {
    const k = 1 + Math.floor(random() * 15);
    const radius = 0.08 + k * 0.072;
    const a = random() * TAU;
    const gap = Math.sin(a * 3 + k * 1.7) + Math.sin(a * 5 - k * 0.9) * 0.5;
    if (gap > 1.05 || (a > 4.2 && a < 4.75 && k > 4)) continue;
    const x = Math.cos(a) * radius * 0.82 + Math.sin(a * 2 + k) * 0.015;
    const y = Math.sin(a) * radius * 1.12 + 0.05;
    const z = -0.28 * (x * x + y * y) + gauss(random) * 0.012;
    return [x * 1.05, y * 1.05, z];
  }
  return [gauss(random) * 0.05, gauss(random) * 0.05, 0];
}

function shieldHalfWidth(y) {
  // y runs from 1.0 (top) to -1.15 (tip).
  const t = (1.0 - y) / 2.15;
  if (t < 0.46) return 0.95;
  return 0.95 * Math.pow(Math.cos(((t - 0.46) / 0.54) * Math.PI * 0.5), 0.85);
}

/** Fraud prevention: a shield with matching indicators converging on one flagged point. */
function shield(t, random) {
  if (t < 0.4) {
    // Outline.
    const side = random() < 0.5 ? -1 : 1;
    if (random() < 0.3) {
      const x = (random() * 2 - 1) * 0.95;
      return [x, 1.0 - 0.1 * (1 - (x / 0.95) ** 2) + gauss(random) * 0.008, gauss(random) * 0.02];
    }
    const y = 1.0 - random() * 2.15;
    return [side * shieldHalfWidth(y) + gauss(random) * 0.008, y, gauss(random) * 0.02];
  }
  if (t < 0.9) {
    // Interior surface, slightly domed, inset from the outline.
    for (let attempt = 0; attempt < 20; attempt++) {
      const y = 0.9 - random() * 1.95;
      const x = (random() * 2 - 1) * 0.86;
      if (Math.abs(x) > shieldHalfWidth(y) * 0.88) continue;
      const grid = Math.abs(Math.sin(x * 18)) < 0.18 || Math.abs(Math.sin(y * 18)) < 0.18;
      if (!grid && random() < 0.7) continue;
      return [x, y, 0.22 * Math.cos(x * 1.6) * Math.cos(y * 0.75) + gauss(random) * 0.01];
    }
    return [0, 0, 0.2];
  }
  // Flagged indicators: tight coral cluster in front of the shield.
  return [0.22 + gauss(random) * 0.07, 0.12 + gauss(random) * 0.07, 0.42 + gauss(random) * 0.05, 1];
}

/** Verification: a signed evidence receipt with text rows and a seal. */
function receipt(t, random) {
  const w = 0.82, h = 1.12;
  if (t < 0.3) {
    const edge = random() * 4;
    const q = (edge % 1) * 2 - 1;
    const p = edge < 1 ? [q * w, h] : edge < 2 ? [w, -q * h] : edge < 3 ? [-q * w, -h] : [-w, q * h];
    // Torn receipt bottom edge.
    if (edge >= 2 && edge < 3) p[1] += Math.abs(Math.sin(q * 22)) * 0.04;
    return [p[0], p[1], gauss(random) * 0.01];
  }
  if (t < 0.75) {
    const row = Math.floor(random() * 11);
    const lengths = [0.9, 0.55, 0.75, 0.8, 0.4, 0.85, 0.6, 0.7, 0.35, 0.5, 0.65];
    const x = -w * 0.78 + random() * w * 1.56 * lengths[row];
    return [x, h * 0.78 - row * 0.15, gauss(random) * 0.006];
  }
  if (t < 0.93) {
    const a = random() * TAU;
    const r = 0.24 + (random() < 0.6 ? 0 : 0.06);
    return [0.4 + Math.cos(a) * r, -0.74 + Math.sin(a) * r, 0.02];
  }
  // Check mark inside the seal.
  const s = random();
  const p = s < 0.35 ? [0.29 + s / 0.35 * 0.08, -0.74 - s / 0.35 * 0.08] : [0.37 + (s - 0.35) / 0.65 * 0.16, -0.82 + (s - 0.35) / 0.65 * 0.2];
  return [p[0], p[1], 0.03];
}

/** Console and network: a globe of latitude and longitude lines. */
function globe(t, random) {
  const r = 1.05;
  if (t < 0.5) {
    const lat = (Math.floor(random() * 9) - 4) * 0.33;
    const a = random() * TAU;
    return [Math.cos(a) * Math.cos(lat) * r, Math.sin(lat) * r, Math.sin(a) * Math.cos(lat) * r];
  }
  if (t < 0.95) {
    const lon = Math.floor(random() * 12) * (Math.PI / 12);
    const a = random() * TAU;
    return [Math.cos(lon) * Math.cos(a) * r, Math.sin(a) * r, Math.sin(lon) * Math.cos(a) * r];
  }
  return sphere(random, 0.12, 0.04);
}

const GENERATORS = [radar, lattice, knot, fingerprint, shield, receipt, globe];

export function buildShapes(count) {
  return GENERATORS.map((generator, index) => fill(count, 101 + index * 7919, generator));
}
