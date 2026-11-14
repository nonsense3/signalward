import { buildShapes } from "./shapes.js";

/*
 * SignalWard observatory scene. WebGL2, no libraries.
 * - GPGPU particles: positions and velocities live in float textures and are integrated on the GPU
 *   (curl-noise flow, damped pointer forces along the camera ray, spring attraction to formations).
 * - Liquid: a stable-fluids solver (advection, vorticity, pressure projection) driven by the pointer and a
 *   slow ambient emitter. Its velocity field refracts the composited scene; its dye tints it.
 * - Glass: three spectrometer prisms in the hero that collapse into one specimen case for the chapters.
 * - Themes: dark mode accumulates emitted light; light mode accumulates absorbance (Beer-Lambert), so
 *   the same particles read as ink on paper.
 */

const NOISE = /* glsl */ `
vec4 permute(vec4 x){ return mod(((x*34.0)+1.0)*x, 289.0); }
vec4 taylorInvSqrt(vec4 r){ return 1.79284291400159 - 0.85373472095314 * r; }
float snoise(vec3 v){
  const vec2 C = vec2(1.0/6.0, 1.0/3.0);
  const vec4 D = vec4(0.0, 0.5, 1.0, 2.0);
  vec3 i = floor(v + dot(v, C.yyy));
  vec3 x0 = v - i + dot(i, C.xxx);
  vec3 g = step(x0.yzx, x0.xyz);
  vec3 l = 1.0 - g;
  vec3 i1 = min(g.xyz, l.zxy);
  vec3 i2 = max(g.xyz, l.zxy);
  vec3 x1 = x0 - i1 + C.xxx;
  vec3 x2 = x0 - i2 + 2.0 * C.xxx;
  vec3 x3 = x0 - 1.0 + 3.0 * C.xxx;
  i = mod(i, 289.0);
  vec4 p = permute(permute(permute(i.z + vec4(0.0, i1.z, i2.z, 1.0)) + i.y + vec4(0.0, i1.y, i2.y, 1.0)) + i.x + vec4(0.0, i1.x, i2.x, 1.0));
  float n_ = 1.0/7.0;
  vec3 ns = n_ * D.wyz - D.xzx;
  vec4 j = p - 49.0 * floor(p * ns.z * ns.z);
  vec4 x_ = floor(j * ns.z);
  vec4 y_ = floor(j - 7.0 * x_);
  vec4 x = x_ * ns.x + ns.yyyy;
  vec4 y = y_ * ns.x + ns.yyyy;
  vec4 h = 1.0 - abs(x) - abs(y);
  vec4 b0 = vec4(x.xy, y.xy);
  vec4 b1 = vec4(x.zw, y.zw);
  vec4 s0 = floor(b0) * 2.0 + 1.0;
  vec4 s1 = floor(b1) * 2.0 + 1.0;
  vec4 sh = -step(h, vec4(0.0));
  vec4 a0 = b0.xzyw + s0.xzyw * sh.xxyy;
  vec4 a1 = b1.xzyw + s1.xzyw * sh.zzww;
  vec3 p0 = vec3(a0.xy, h.x);
  vec3 p1 = vec3(a0.zw, h.y);
  vec3 p2 = vec3(a1.xy, h.z);
  vec3 p3 = vec3(a1.zw, h.w);
  vec4 norm = taylorInvSqrt(vec4(dot(p0,p0), dot(p1,p1), dot(p2,p2), dot(p3,p3)));
  p0 *= norm.x; p1 *= norm.y; p2 *= norm.z; p3 *= norm.w;
  vec4 m = max(0.6 - vec4(dot(x0,x0), dot(x1,x1), dot(x2,x2), dot(x3,x3)), 0.0);
  m = m * m;
  return 42.0 * dot(m*m, vec4(dot(p0,x0), dot(p1,x1), dot(p2,x2), dot(p3,x3)));
}
vec3 noise3(vec3 p){
  return vec3(snoise(p), snoise(p + vec3(31.416, -47.853, 12.793)), snoise(p + vec3(-233.145, -113.408, -185.31)));
}
vec3 curl(vec3 p){
  const float e = 0.1;
  vec3 dx = vec3(e, 0.0, 0.0), dy = vec3(0.0, e, 0.0), dz = vec3(0.0, 0.0, e);
  vec3 px0 = noise3(p - dx), px1 = noise3(p + dx);
  vec3 py0 = noise3(p - dy), py1 = noise3(p + dy);
  vec3 pz0 = noise3(p - dz), pz1 = noise3(p + dz);
  return vec3((py1.z - py0.z) - (pz1.y - pz0.y), (pz1.x - pz0.x) - (px1.z - px0.z), (px1.y - px0.y) - (py1.x - py0.x)) / (2.0 * e);
}
float hash12(vec2 p){ vec3 p3 = fract(vec3(p.xyx) * 0.1031); p3 += dot(p3, p3.yzx + 33.33); return fract((p3.x + p3.y) * p3.z); }
`;

const QUAD_VS = `#version 300 es
in vec2 aPos;
out vec2 vUv;
void main(){ vUv = aPos * 0.5 + 0.5; gl_Position = vec4(aPos, 0.0, 1.0); }`;

const SIM_FS = `#version 300 es
precision highp float;
precision highp sampler2D;
precision highp sampler2DArray;
uniform sampler2D uPos;
uniform sampler2D uVel;
uniform sampler2DArray uShapes;
uniform int uShapeA, uShapeB;
uniform float uMix, uTime, uDt, uEnergy, uIntro;
uniform vec3 uRayO, uRayD, uPointerVel;
uniform float uPointer;
layout(location = 0) out vec4 oPos;
layout(location = 1) out vec4 oVel;
${NOISE}
vec3 stream(vec2 cell, float seed, out float fade){
  float s = fract(seed * 7.13 + uTime * 0.045);
  float x = mix(-3.3, 3.3, s);
  float w = hash12(cell * 1.37 + 4.1) - 0.5;
  float a = hash12(cell * 2.91 + 9.7) * 6.2831;
  float spread = smoothstep(-1.25, 0.15, x) * (1.0 - smoothstep(0.7, 2.9, x));
  float radius = 0.05 + 0.07 * (1.0 - spread);
  float y = w * spread * 1.15 + sin(x * 1.3 + uTime * 0.5 + w * 3.0) * 0.045;
  float z = w * spread * 0.3 + sin(a) * radius;
  fade = smoothstep(3.3, 2.6, abs(x));
  return vec3(x, y + cos(a) * radius, z);
}
vec3 targetFor(int id, ivec2 cell, float seed, out float fade, out float flag){
  fade = 1.0;
  flag = 0.0;
  if (id == 0) return stream(vec2(cell), seed, fade);
  vec4 t = texelFetch(uShapes, ivec3(cell, id - 1), 0);
  flag = t.w;
  return t.xyz;
}
void main(){
  ivec2 cell = ivec2(gl_FragCoord.xy);
  vec4 P = texelFetch(uPos, cell, 0);
  vec4 V = texelFetch(uVel, cell, 0);
  float seed = hash12(vec2(cell) + 0.5);
  float fadeA, fadeB, flagA, flagB;
  vec3 tA = targetFor(uShapeA, cell, seed, fadeA, flagA);
  vec3 tB = targetFor(uShapeB, cell, seed, fadeB, flagB);
  float m = smoothstep(seed * 0.45, seed * 0.45 + 0.55, uMix);
  vec3 target = mix(tA, tB, m);
  float fade = mix(fadeA, fadeB, m);
  vec3 pos = P.xyz;
  vec3 vel = V.xyz;
  float streaming = (uShapeA == 0 ? 1.0 - m : 0.0) + (uShapeB == 0 ? m : 0.0);
  if (streaming > 0.98 && abs(target.x - pos.x) > 2.0) { pos = target + (vec3(seed, fract(seed * 13.1), fract(seed * 71.7)) - 0.5) * 0.1; vel *= 0.0; }
  float stiffness = mix(3.6, 7.6, seed) * (1.0 - uIntro * 0.8);
  vec3 force = (target - pos) * stiffness;
  // Steady by default: gentle flow, with turbulence rising only during morphs, scroll and the intro.
  force += curl(pos * 0.8 + vec3(0.0, 0.0, uTime * 0.06)) * (0.07 + uEnergy * 0.7 + streaming * 0.22 + uIntro * 2.2);
  vec3 toP = pos - uRayO;
  vec3 d = pos - (uRayO + uRayD * dot(toP, uRayD));
  float influence = exp(-dot(d, d) * 5.0) * uPointer;
  force += normalize(d + 1e-5) * influence * 6.0 + cross(uRayD, d) * influence * 9.0 + uPointerVel * influence * 14.0;
  vel += force * uDt;
  vel *= pow(0.05, uDt);
  pos += vel * uDt;
  oPos = vec4(pos, fade);
  oVel = vec4(vel, mix(flagA, flagB, m));
}`;

const POINT_VS = `#version 300 es
precision highp float;
precision highp sampler2D;
uniform sampler2D uPos;
uniform sampler2D uVel;
uniform mat4 uProj, uView;
uniform vec2 uShift;
uniform float uSize, uWidth, uLight;
out vec3 vColor;
out float vAlpha;
void main(){
  int w = int(uWidth);
  ivec2 cell = ivec2(gl_VertexID % w, gl_VertexID / w);
  vec4 P = texelFetch(uPos, cell, 0);
  vec4 V = texelFetch(uVel, cell, 0);
  vec4 mv = uView * vec4(P.xyz, 1.0);
  gl_Position = uProj * mv;
  gl_Position.xy += uShift * gl_Position.w;
  float glow = smoothstep(0.15, 1.8, length(V.xyz));
  gl_PointSize = clamp(uSize * (1.0 + glow * 0.5) / max(-mv.z, 0.1), 1.0, 22.0);
  // Dark: emitted light. Light: absorbance (1 - ink colour), so additive blending darkens toward the ink.
  vec3 emit = mix(mix(vec3(0.32, 0.27, 0.78), vec3(0.61, 0.55, 1.0), smoothstep(0.0, 0.6, glow + 0.35)), vec3(0.96, 0.95, 0.93), smoothstep(0.45, 1.0, glow));
  emit = mix(emit, vec3(1.0, 0.47, 0.4), V.w);
  vec3 ink = mix(vec3(0.23, 0.17, 1.0), vec3(0.05, 0.04, 0.2), smoothstep(0.5, 1.0, glow));
  ink = mix(ink, vec3(0.92, 0.25, 0.25), V.w);
  vColor = mix(emit, (1.0 - ink) * 0.55, uLight);
  vAlpha = P.w * (0.5 + glow * 0.6 + V.w * 0.6);
}`;

const POINT_FS = `#version 300 es
precision highp float;
in vec3 vColor;
in float vAlpha;
out vec4 outColor;
void main(){
  vec2 c = gl_PointCoord - 0.5;
  outColor = vec4(vColor * exp(-dot(c, c) * 14.0) * vAlpha, 1.0);
}`;

const GLASS_VS = `#version 300 es
precision highp float;
in vec3 aPos;
in vec3 aNormal;
uniform mat4 uProj, uView, uModel;
uniform vec2 uShift;
out vec3 vNormal;
out vec3 vWorld;
void main(){
  vec4 world = uModel * vec4(aPos, 1.0);
  vWorld = world.xyz;
  vNormal = mat3(uModel) * aNormal;
  gl_Position = uProj * uView * world;
  gl_Position.xy += uShift * gl_Position.w;
}`;

const GLASS_FS = `#version 300 es
precision highp float;
in vec3 vNormal;
in vec3 vWorld;
uniform vec3 uEye;
uniform float uOpacity, uLine, uTime, uLight;
out vec4 outColor;
void main(){
  if (uLine > 0.5) { outColor = vec4(mix(vec3(0.2), vec3(0.16, 0.15, 0.1), uLight) * uOpacity, 1.0); return; }
  vec3 n = normalize(vNormal);
  vec3 v = normalize(uEye - vWorld);
  float fres = pow(1.0 - abs(dot(n, v)), 2.6);
  float film = 0.5 + 0.5 * sin(dot(n, v) * 9.0 + uTime * 0.4);
  // Thin-film dispersion: the hue drifts across the face with the viewing angle.
  vec3 tint = mix(vec3(0.45, 0.4, 0.95), vec3(0.75, 0.7, 1.0), film);
  vec3 emitted = tint * fres * 0.42 + vec3(0.07, 0.07, 0.11) * 0.35;
  vec3 absorbed = (1.0 - mix(vec3(0.35, 0.3, 1.0), vec3(0.7, 0.68, 1.0), film)) * fres * 0.5 + vec3(0.025);
  outColor = vec4(mix(emitted, absorbed, uLight) * uOpacity, 1.0);
}`;

const COMPOSITE_FS = `#version 300 es
precision highp float;
precision highp sampler2D;
in vec2 vUv;
uniform sampler2D uScene;
uniform sampler2D uFlow;
uniform sampler2D uDye;
uniform float uTime, uAberration, uDisplace, uLight, uFlowStrength;
uniform vec2 uResolution, uFlowTexel, uCenter;
out vec4 outColor;
${NOISE}
void main(){
  vec2 flow = texture(uFlow, vUv).xy * uFlowTexel;
  vec2 uv = vUv - flow * uFlowStrength;
  float band = snoise(vec3(uv.y * 6.0, uTime * 0.9, 0.0));
  uv.x += band * uDisplace * 0.018;
  vec2 dir = uv - uCenter;
  float amount = uAberration * (0.0015 + dot(dir, dir) * 0.03) + min(length(flow) * uFlowStrength, 0.01) * 0.15;
  vec3 col;
  col.r = texture(uScene, uv + dir * amount).r;
  col.g = texture(uScene, uv).g;
  col.b = texture(uScene, uv - dir * amount).b;
  vec3 dye = texture(uDye, uv).rgb;
  vec2 p = vUv - uCenter;
  float vignette = smoothstep(0.0, 0.9, length(p * vec2(1.2, 1.0)));
  vec3 grain = vec3(hash12(vUv * uResolution + fract(uTime) * 91.0) - 0.5);
  vec3 dark = mix(vec3(0.075, 0.07, 0.115), vec3(0.035, 0.036, 0.05), vignette) + (1.0 - exp(-col * 1.15)) + min(dye, vec3(1.0)) * 0.35 + grain * 0.035;
  vec3 paper = mix(vec3(0.965, 0.968, 0.98), vec3(0.875, 0.882, 0.915), vignette);
  vec3 light = paper * exp(-(col * 1.4 + min(dye, vec3(1.2)) * 0.45)) + grain * 0.02;
  outColor = vec4(mix(dark, light, uLight), 1.0);
}`;

/* ---------- Fluid solver (after Stam, "Stable Fluids") ---------- */
const FLUID_BASE = `#version 300 es
precision highp float;
precision highp sampler2D;
in vec2 vUv;
uniform vec2 uTexel;
out vec4 outColor;
`;
const ADVECT_FS = `${FLUID_BASE}
uniform sampler2D uVelocity, uSource;
uniform float uDt, uDissipation;
void main(){
  vec2 coord = vUv - uDt * texture(uVelocity, vUv).xy * uTexel;
  outColor = texture(uSource, coord) / (1.0 + uDissipation * uDt);
}`;
const SPLAT_FS = `${FLUID_BASE}
uniform sampler2D uTarget;
uniform vec2 uPoint;
uniform vec3 uColor;
uniform float uRadius, uAspect;
void main(){
  vec2 p = vUv - uPoint;
  p.x *= uAspect;
  outColor = vec4(texture(uTarget, vUv).xyz + exp(-dot(p, p) / uRadius) * uColor, 1.0);
}`;
const NEIGHBORS = `
  vec2 L = vUv - vec2(uTexel.x, 0.0), R = vUv + vec2(uTexel.x, 0.0), T = vUv + vec2(0.0, uTexel.y), B = vUv - vec2(0.0, uTexel.y);`;
const CURL_FS = `${FLUID_BASE}
uniform sampler2D uVelocity;
void main(){${NEIGHBORS}
  float c = texture(uVelocity, R).y - texture(uVelocity, L).y - texture(uVelocity, T).x + texture(uVelocity, B).x;
  outColor = vec4(0.5 * c, 0.0, 0.0, 1.0);
}`;
const VORTICITY_FS = `${FLUID_BASE}
uniform sampler2D uVelocity, uCurl;
uniform float uCurlStrength, uDt;
void main(){${NEIGHBORS}
  float l = texture(uCurl, L).x, r = texture(uCurl, R).x, t = texture(uCurl, T).x, b = texture(uCurl, B).x, c = texture(uCurl, vUv).x;
  vec2 force = 0.5 * vec2(abs(t) - abs(b), abs(r) - abs(l));
  force /= length(force) + 0.0001;
  force *= uCurlStrength * c;
  force.y *= -1.0;
  vec2 vel = texture(uVelocity, vUv).xy + force * uDt;
  outColor = vec4(clamp(vel, -1000.0, 1000.0), 0.0, 1.0);
}`;
const DIVERGENCE_FS = `${FLUID_BASE}
uniform sampler2D uVelocity;
void main(){${NEIGHBORS}
  float l = texture(uVelocity, L).x, r = texture(uVelocity, R).x, t = texture(uVelocity, T).y, b = texture(uVelocity, B).y;
  vec2 c = texture(uVelocity, vUv).xy;
  if (L.x < 0.0) l = -c.x;
  if (R.x > 1.0) r = -c.x;
  if (T.y > 1.0) t = -c.y;
  if (B.y < 0.0) b = -c.y;
  outColor = vec4(0.5 * (r - l + t - b), 0.0, 0.0, 1.0);
}`;
const CLEAR_FS = `${FLUID_BASE}
uniform sampler2D uTexture;
uniform float uValue;
void main(){ outColor = uValue * texture(uTexture, vUv); }`;
const PRESSURE_FS = `${FLUID_BASE}
uniform sampler2D uPressure, uDivergence;
void main(){${NEIGHBORS}
  float p = texture(uPressure, L).x + texture(uPressure, R).x + texture(uPressure, B).x + texture(uPressure, T).x;
  outColor = vec4((p - texture(uDivergence, vUv).x) * 0.25, 0.0, 0.0, 1.0);
}`;
const GRADIENT_FS = `${FLUID_BASE}
uniform sampler2D uPressure, uVelocity;
void main(){${NEIGHBORS}
  vec2 vel = texture(uVelocity, vUv).xy - vec2(texture(uPressure, R).x - texture(uPressure, L).x, texture(uPressure, T).x - texture(uPressure, B).x);
  outColor = vec4(vel, 0.0, 1.0);
}`;

function compile(gl, type, source) {
  const shader = gl.createShader(type);
  gl.shaderSource(shader, source);
  gl.compileShader(shader);
  if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(shader) ?? "shader compile failed");
  return shader;
}
function program(gl, vs, fs) {
  const p = gl.createProgram();
  gl.attachShader(p, compile(gl, gl.VERTEX_SHADER, vs));
  gl.attachShader(p, compile(gl, gl.FRAGMENT_SHADER, fs));
  gl.bindAttribLocation(p, 0, "aPos");
  gl.linkProgram(p);
  if (!gl.getProgramParameter(p, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(p) ?? "program link failed");
  const u = {};
  for (let i = 0; i < gl.getProgramParameter(p, gl.ACTIVE_UNIFORMS); i++) {
    const info = gl.getActiveUniform(p, i);
    u[info.name.replace(/\[0\]$/, "")] = gl.getUniformLocation(p, info.name);
  }
  return { p, u };
}

function perspective(fovy, aspect, near, far) {
  const f = 1 / Math.tan(fovy / 2), nf = 1 / (near - far);
  return new Float32Array([f / aspect, 0, 0, 0, 0, f, 0, 0, 0, 0, (far + near) * nf, -1, 0, 0, 2 * far * near * nf, 0]);
}
const sub = (a, b) => [a[0] - b[0], a[1] - b[1], a[2] - b[2]];
const cross = (a, b) => [a[1] * b[2] - a[2] * b[1], a[2] * b[0] - a[0] * b[2], a[0] * b[1] - a[1] * b[0]];
const norm = (a) => { const l = Math.hypot(a[0], a[1], a[2]) || 1; return [a[0] / l, a[1] / l, a[2] / l]; };
const dot = (a, b) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2];
function lookAt(eye, target, up) {
  const z = norm(sub(eye, target)), x = norm(cross(up, z)), y = cross(z, x);
  return { m: new Float32Array([x[0], y[0], z[0], 0, x[1], y[1], z[1], 0, x[2], y[2], z[2], 0, -dot(x, eye), -dot(y, eye), -dot(z, eye), 1]), x, y, z };
}
function model(tx, ty, tz, rotY, scale) {
  const c = Math.cos(rotY) * scale, s = Math.sin(rotY) * scale;
  return new Float32Array([c, 0, -s, 0, 0, scale, 0, 0, s, 0, c, 0, tx, ty, tz, 1]);
}

function prismMesh() {
  const r = 0.42, h = 1.0;
  const tri = [90, 210, 330].map((deg) => [Math.cos((deg * Math.PI) / 180) * r, Math.sin((deg * Math.PI) / 180) * r]);
  const faces = [], edges = [];
  const push = (list, p, n) => list.push(p[0], p[1], p[2], n[0], n[1], n[2]);
  for (let i = 0; i < 3; i++) {
    const a = tri[i], b = tri[(i + 1) % 3];
    const n = norm([(a[0] + b[0]) / 2, 0, (a[1] + b[1]) / 2]);
    const quad = [[a[0], -h, a[1]], [b[0], -h, b[1]], [b[0], h, b[1]], [a[0], h, a[1]]];
    for (const k of [0, 1, 2, 0, 2, 3]) push(faces, quad[k], n);
    for (const [p, q] of [[0, 1], [1, 2], [2, 3], [3, 0]]) { push(edges, quad[p], n); push(edges, quad[q], n); }
  }
  for (const y of [-h, h]) for (const p of tri) push(faces, [p[0], y, p[1]], [0, Math.sign(y), 0]);
  return { faces: new Float32Array(faces), edges: new Float32Array(edges) };
}
function boxMesh() {
  const faces = [], edges = [];
  const push = (list, p, n) => list.push(p[0], p[1], p[2], n[0], n[1], n[2]);
  for (const [a, b, c] of [[0, 1, 2], [1, 2, 0], [2, 0, 1]]) {
    for (const sign of [-1, 1]) {
      const n = [0, 0, 0]; n[a] = sign;
      const corner = (u, v) => { const p = [0, 0, 0]; p[a] = sign; p[b] = u; p[c] = v; return p; };
      const quad = [corner(-1, -1), corner(1, -1), corner(1, 1), corner(-1, 1)];
      for (const k of [0, 1, 2, 0, 2, 3]) push(faces, quad[k], n);
      for (const [p, q] of [[0, 1], [1, 2], [2, 3], [3, 0]]) { push(edges, quad[p], n); push(edges, quad[q], n); }
    }
  }
  return { faces: new Float32Array(faces), edges: new Float32Array(edges) };
}

function texture(gl, w, h, internal, format, type, data, filter) {
  const t = gl.createTexture();
  gl.bindTexture(gl.TEXTURE_2D, t);
  gl.texImage2D(gl.TEXTURE_2D, 0, internal, w, h, 0, format, type, data);
  for (const [k, v] of [[gl.TEXTURE_MIN_FILTER, filter], [gl.TEXTURE_MAG_FILTER, filter], [gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE], [gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE]]) gl.texParameteri(gl.TEXTURE_2D, k, v);
  return t;
}
function target(gl, w, h, filter) {
  const tex = texture(gl, w, h, gl.RGBA16F, gl.RGBA, gl.HALF_FLOAT, null, filter);
  const fb = gl.createFramebuffer();
  gl.bindFramebuffer(gl.FRAMEBUFFER, fb);
  gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, tex, 0);
  gl.viewport(0, 0, w, h);
  gl.clearColor(0, 0, 0, 1);
  gl.clear(gl.COLOR_BUFFER_BIT);
  return { tex, fb, w, h };
}
function doubleTarget(gl, w, h, filter) {
  let read = target(gl, w, h, filter), write = target(gl, w, h, filter);
  return { get read() { return read; }, get write() { return write; }, swap() { [read, write] = [write, read]; }, w, h };
}

/**
 * @param {HTMLCanvasElement} canvas
 * @param {{ compact?: boolean, shape?: number, prisms?: boolean, light?: boolean, fluid?: boolean }} options
 */
export function startScene(canvas, { compact = false, shape = 0, prisms = true, light = false, fluid = true } = {}) {
  const gl = canvas.getContext("webgl2", { alpha: false, antialias: false, depth: false, powerPreference: "high-performance", preserveDrawingBuffer: false });
  if (!gl) throw new Error("WebGL2 unavailable");
  if (!gl.getExtension("EXT_color_buffer_float")) throw new Error("Float render targets unavailable");
  gl.getExtension("OES_texture_float_linear");

  const SIZE = compact ? 64 : 128;
  const COUNT = SIZE * SIZE;

  const sim = program(gl, QUAD_VS, SIM_FS);
  const points = program(gl, POINT_VS, POINT_FS);
  const glass = program(gl, GLASS_VS, GLASS_FS);
  const composite = program(gl, QUAD_VS, COMPOSITE_FS);
  const fp = {
    advect: program(gl, QUAD_VS, ADVECT_FS), splat: program(gl, QUAD_VS, SPLAT_FS), curl: program(gl, QUAD_VS, CURL_FS),
    vorticity: program(gl, QUAD_VS, VORTICITY_FS), divergence: program(gl, QUAD_VS, DIVERGENCE_FS), clear: program(gl, QUAD_VS, CLEAR_FS),
    pressure: program(gl, QUAD_VS, PRESSURE_FS), gradient: program(gl, QUAD_VS, GRADIENT_FS),
  };

  const quadVao = gl.createVertexArray();
  gl.bindVertexArray(quadVao);
  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  gl.enableVertexAttribArray(0);
  gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);

  function meshVao(data) {
    const vao = gl.createVertexArray();
    gl.bindVertexArray(vao);
    gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer());
    gl.bufferData(gl.ARRAY_BUFFER, data, gl.STATIC_DRAW);
    const pos = gl.getAttribLocation(glass.p, "aPos"), nrm = gl.getAttribLocation(glass.p, "aNormal");
    gl.enableVertexAttribArray(pos);
    gl.vertexAttribPointer(pos, 3, gl.FLOAT, false, 24, 0);
    if (nrm >= 0) { gl.enableVertexAttribArray(nrm); gl.vertexAttribPointer(nrm, 3, gl.FLOAT, false, 24, 12); }
    return { vao, count: data.length / 6 };
  }
  const prism = prismMesh(), box = boxMesh();
  const prismFaces = meshVao(prism.faces), prismEdges = meshVao(prism.edges);
  const boxFaces = meshVao(box.faces), boxEdges = meshVao(box.edges);
  const emptyVao = gl.createVertexArray();

  // Particle state.
  const initial = new Float32Array(COUNT * 4);
  let seed = 7;
  const random = () => ((seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 4294967296);
  for (let i = 0; i < COUNT; i++) {
    const u = random() * 2 - 1, a = random() * Math.PI * 2, r = 2.5 + random() * 3.5, s = Math.sqrt(1 - u * u);
    initial.set([Math.cos(a) * s * r, u * r, Math.sin(a) * s * r, 1], i * 4);
  }
  function simTarget() {
    const pos = texture(gl, SIZE, SIZE, gl.RGBA32F, gl.RGBA, gl.FLOAT, initial, gl.NEAREST);
    const vel = texture(gl, SIZE, SIZE, gl.RGBA32F, gl.RGBA, gl.FLOAT, new Float32Array(COUNT * 4), gl.NEAREST);
    const fb = gl.createFramebuffer();
    gl.bindFramebuffer(gl.FRAMEBUFFER, fb);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, pos, 0);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT1, gl.TEXTURE_2D, vel, 0);
    if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE) throw new Error("Simulation framebuffer incomplete");
    return { fb, pos, vel };
  }
  let read = simTarget(), write = simTarget();

  const shapes = buildShapes(COUNT);
  const shapeTex = gl.createTexture();
  gl.bindTexture(gl.TEXTURE_2D_ARRAY, shapeTex);
  gl.texImage3D(gl.TEXTURE_2D_ARRAY, 0, gl.RGBA32F, SIZE, SIZE, shapes.length, 0, gl.RGBA, gl.FLOAT, null);
  shapes.forEach((data, layer) => gl.texSubImage3D(gl.TEXTURE_2D_ARRAY, 0, 0, 0, layer, SIZE, SIZE, 1, gl.RGBA, gl.FLOAT, data));
  gl.texParameteri(gl.TEXTURE_2D_ARRAY, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
  gl.texParameteri(gl.TEXTURE_2D_ARRAY, gl.TEXTURE_MAG_FILTER, gl.NEAREST);

  // Fluid fields, sized to the canvas aspect on first frame.
  let fluidState = null;
  function fluidFields(aspect) {
    const simH = compact ? 64 : 112, dyeH = compact ? 160 : 256;
    const simW = Math.max(16, Math.round(simH * aspect)), dyeW = Math.max(16, Math.round(dyeH * aspect));
    if (fluidState && fluidState.simW === simW && fluidState.dyeW === dyeW) return fluidState;
    fluidState = {
      simW, simH, dyeW, dyeH,
      velocity: doubleTarget(gl, simW, simH, gl.LINEAR), dye: doubleTarget(gl, dyeW, dyeH, gl.LINEAR),
      pressure: doubleTarget(gl, simW, simH, gl.NEAREST), divergence: target(gl, simW, simH, gl.NEAREST), curl: target(gl, simW, simH, gl.NEAREST),
    };
    return fluidState;
  }
  const blankFlow = target(gl, 4, 4, gl.NEAREST);

  let scene = null;
  function sceneTarget(w, h) {
    if (scene && scene.w === w && scene.h === h) return scene;
    if (scene) { gl.deleteTexture(scene.tex); gl.deleteFramebuffer(scene.fb); }
    scene = target(gl, w, h, gl.LINEAR);
    return scene;
  }

  const state = {
    shapeA: shape, shapeB: shape, mix: 0,
    caseBlend: prisms ? 0 : 0, prismBlend: prisms ? 1 : 0,
    energy: 0, aberration: 0, intro: 1,
    light: light ? 1 : 0, lightTarget: light ? 1 : 0,
    /** Where the scene sits: NDC centre and height fraction of the canvas, plus an optional CSS-px clip. */
    view: { cx: 0, cy: 0, h: 1 }, clip: null,
    pointer: { x: 0, y: 0, vx: 0, vy: 0, active: 0, target: 0, moved: false, dx: 0, dy: 0 },
  };
  const cam = { angle: 0.38, height: 0.35, radius: 13 };
  let running = false, frame = 0, last = 0, lost = false, time = 0;
  let dprCap = compact ? 1 : 1.5;
  const frameTimes = [];
  let drawCount = COUNT;
  let fluidOn = fluid;

  function adapt(dt) {
    frameTimes.push(dt);
    if (frameTimes.length < 90) return;
    const average = frameTimes.reduce((a, b) => a + b, 0) / frameTimes.length;
    frameTimes.length = 0;
    if (average > 0.026 && dprCap > 1) dprCap = 1;
    else if (average > 0.034 && fluidOn && !compact) fluidOn = false;
    else if (average > 0.034 && drawCount > COUNT / 4) drawCount = Math.floor(drawCount / 2);
  }

  function pass(prog, out, uniforms) {
    gl.useProgram(prog.p);
    let unit = 0;
    for (const [name, value] of Object.entries(uniforms)) {
      const loc = prog.u[name];
      if (loc === undefined) continue;
      if (value && value.tex) { gl.activeTexture(gl.TEXTURE0 + unit); gl.bindTexture(gl.TEXTURE_2D, value.tex); gl.uniform1i(loc, unit++); }
      else if (Array.isArray(value)) (value.length === 2 ? gl.uniform2fv : gl.uniform3fv).call(gl, loc, value);
      else gl.uniform1f(loc, value);
    }
    gl.bindFramebuffer(gl.FRAMEBUFFER, out ? out.fb : null);
    if (out) gl.viewport(0, 0, out.w, out.h);
    gl.bindVertexArray(quadVao);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
  }

  function splat(f, x, y, fx, fy, color, radius) {
    const aspect = f.simW / f.simH;
    pass(fp.splat, f.velocity.write, { uTarget: f.velocity.read, uPoint: [x, y], uColor: [fx, fy, 0], uRadius: radius, uAspect: aspect, uTexel: [1 / f.simW, 1 / f.simH] });
    f.velocity.swap();
    pass(fp.splat, f.dye.write, { uTarget: f.dye.read, uPoint: [x, y], uColor: color, uRadius: radius, uAspect: aspect, uTexel: [1 / f.dyeW, 1 / f.dyeH] });
    f.dye.swap();
  }

  function stepFluid(f, dt) {
    const texel = [1 / f.simW, 1 / f.simH];
    const lightMix = state.light;
    const dyeColor = (k) => [
      (0.17 * (1 - lightMix) + 0.55 * lightMix) * k,
      (0.14 * (1 - lightMix) + 0.6 * lightMix) * k,
      (0.4 * (1 - lightMix) + 0.0 * lightMix) * k,
    ];
    const p = state.pointer;
    if (p.moved) {
      const strength = Math.min(1, Math.hypot(p.dx, p.dy) * 40);
      splat(f, (p.x + 1) / 2, (p.y + 1) / 2, p.dx * 5200, p.dy * 5200, dyeColor(0.12 + strength * 0.3), 0.0022);
      p.moved = false; p.dx = 0; p.dy = 0;
    }
    // Ambient emitter: a slow Lissajous current so the liquid keeps moving without input.
    const v = state.view;
    const ax = 0.5 + v.cx * 0.5 + Math.sin(time * 0.31) * 0.22 * v.h, ay = 0.5 + v.cy * 0.5 + Math.sin(time * 0.43 + 1.3) * 0.2 * v.h;
    splat(f, ax, ay, Math.cos(time * 0.31) * 140, Math.cos(time * 0.43 + 1.3) * 140, dyeColor(0.006), 0.004);

    pass(fp.curl, f.curl, { uVelocity: f.velocity.read, uTexel: texel });
    pass(fp.vorticity, f.velocity.write, { uVelocity: f.velocity.read, uCurl: f.curl, uCurlStrength: 12, uDt: dt, uTexel: texel });
    f.velocity.swap();
    pass(fp.divergence, f.divergence, { uVelocity: f.velocity.read, uTexel: texel });
    pass(fp.clear, f.pressure.write, { uTexture: f.pressure.read, uValue: 0.8, uTexel: texel });
    f.pressure.swap();
    for (let i = 0; i < (compact ? 12 : 18); i++) {
      pass(fp.pressure, f.pressure.write, { uPressure: f.pressure.read, uDivergence: f.divergence, uTexel: texel });
      f.pressure.swap();
    }
    pass(fp.gradient, f.velocity.write, { uPressure: f.pressure.read, uVelocity: f.velocity.read, uTexel: texel });
    f.velocity.swap();
    pass(fp.advect, f.velocity.write, { uVelocity: f.velocity.read, uSource: f.velocity.read, uDt: dt, uDissipation: 0.6, uTexel: texel });
    f.velocity.swap();
    pass(fp.advect, f.dye.write, { uVelocity: f.velocity.read, uSource: f.dye.read, uDt: dt, uDissipation: 1.1, uTexel: texel });
    f.dye.swap();
  }

  function render(now) {
    frame = 0;
    const dt = Math.min(0.05, last ? (now - last) / 1000 : 0.016);
    last = now;
    time += dt;
    adapt(dt);

    const width = canvas.clientWidth, height = canvas.clientHeight;
    if (!width || !height) { schedule(); return; }
    const dpr = Math.min(devicePixelRatio || 1, dprCap);
    const pw = Math.round(width * dpr), ph = Math.round(height * dpr);
    if (canvas.width !== pw || canvas.height !== ph) { canvas.width = pw; canvas.height = ph; }
    const st = sceneTarget(pw, ph);

    state.intro = Math.max(0, state.intro - dt * 0.55);
    state.light += (state.lightTarget - state.light) * Math.min(1, dt * 5);
    const p = state.pointer;
    p.active += (p.target - p.active) * Math.min(1, dt * 4);
    const v = state.view;

    // Camera: dolly in after boot, orbit with morphs and pointer. Smaller viewports pull the camera back.
    const narrow = (width * Math.max(v.h, 0.2)) / (height * Math.max(v.h, 0.2)) < 0.95;
    const radiusGoal = ((narrow ? 7.6 : 6.0) + state.caseBlend * 1.4) / Math.max(0.35, v.h);
    cam.radius += (radiusGoal + state.intro * 7 - cam.radius) * Math.min(1, dt * 2.2);
    cam.angle += (0.38 + state.mix * 0.18 + state.caseBlend * 0.25 + p.x * 0.12 + time * 0.012 - cam.angle) * Math.min(1, dt * 2.5);
    cam.height += (0.35 + p.y * 0.22 - cam.height) * Math.min(1, dt * 2.5);
    const eye = [Math.sin(cam.angle) * cam.radius, cam.height, Math.cos(cam.angle) * cam.radius];
    const view = lookAt(eye, [0, 0, 0], [0, 1, 0]);
    const fov = 0.62, aspect = pw / ph;
    const proj = perspective(fov, aspect, 0.1, 80);
    const shift = [v.cx, v.cy];

    const tanHalf = Math.tan(fov / 2);
    const ndcX = p.x - shift[0], ndcY = p.y - shift[1];
    const rayD = norm([0, 1, 2].map((i) => -view.z[i] + view.x[i] * ndcX * tanHalf * aspect + view.y[i] * ndcY * tanHalf));
    const pv = [0, 1, 2].map((i) => view.x[i] * p.vx + view.y[i] * p.vy);
    p.vx *= Math.pow(0.02, dt); p.vy *= Math.pow(0.02, dt);

    // Scissor to the visible card on the page so hidden pixels cost nothing.
    const clip = state.clip;
    const scissor = clip ? [Math.max(0, Math.floor(clip.x * dpr)), Math.max(0, Math.floor((height - clip.y - clip.h) * dpr)), Math.ceil(clip.w * dpr) + 2, Math.ceil(clip.h * dpr) + 2] : null;
    if (scissor && (scissor[2] <= 2 || scissor[3] <= 2 || clip.y > height || clip.y + clip.h < 0)) { schedule(); return; }

    // 1. Particles.
    gl.disable(gl.BLEND);
    gl.disable(gl.SCISSOR_TEST);
    gl.bindFramebuffer(gl.FRAMEBUFFER, write.fb);
    gl.drawBuffers([gl.COLOR_ATTACHMENT0, gl.COLOR_ATTACHMENT1]);
    gl.viewport(0, 0, SIZE, SIZE);
    gl.useProgram(sim.p);
    gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, read.pos); gl.uniform1i(sim.u.uPos, 0);
    gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, read.vel); gl.uniform1i(sim.u.uVel, 1);
    gl.activeTexture(gl.TEXTURE2); gl.bindTexture(gl.TEXTURE_2D_ARRAY, shapeTex); gl.uniform1i(sim.u.uShapes, 2);
    gl.uniform1i(sim.u.uShapeA, state.shapeA);
    gl.uniform1i(sim.u.uShapeB, state.shapeB);
    gl.uniform1f(sim.u.uMix, state.mix);
    gl.uniform1f(sim.u.uTime, time);
    gl.uniform1f(sim.u.uDt, dt);
    gl.uniform1f(sim.u.uEnergy, state.energy);
    gl.uniform1f(sim.u.uIntro, state.intro);
    gl.uniform3fv(sim.u.uRayO, eye);
    gl.uniform3fv(sim.u.uRayD, rayD);
    gl.uniform3fv(sim.u.uPointerVel, pv);
    gl.uniform1f(sim.u.uPointer, p.active);
    gl.bindVertexArray(quadVao);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    [read, write] = [write, read];

    // 2. Liquid.
    const f = fluidOn ? fluidFields(aspect) : null;
    if (f) stepFluid(f, dt);

    // 3. Scene into the HDR target.
    gl.bindFramebuffer(gl.FRAMEBUFFER, st.fb);
    gl.drawBuffers([gl.COLOR_ATTACHMENT0]);
    gl.viewport(0, 0, pw, ph);
    if (scissor) { gl.enable(gl.SCISSOR_TEST); gl.scissor(...scissor); }
    gl.clearColor(0, 0, 0, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.enable(gl.BLEND);
    gl.blendFunc(gl.ONE, gl.ONE);

    gl.useProgram(glass.p);
    gl.uniformMatrix4fv(glass.u.uProj, false, proj);
    gl.uniformMatrix4fv(glass.u.uView, false, view.m);
    gl.uniform2fv(glass.u.uShift, shift);
    gl.uniform3fv(glass.u.uEye, eye);
    gl.uniform1f(glass.u.uTime, time);
    gl.uniform1f(glass.u.uLight, state.light);
    const drawMesh = (faces, edges, m, opacity) => {
      gl.uniformMatrix4fv(glass.u.uModel, false, m);
      gl.uniform1f(glass.u.uOpacity, opacity);
      gl.uniform1f(glass.u.uLine, 0);
      gl.bindVertexArray(faces.vao); gl.drawArrays(gl.TRIANGLES, 0, faces.count);
      gl.uniform1f(glass.u.uLine, 1);
      gl.bindVertexArray(edges.vao); gl.drawArrays(gl.LINES, 0, edges.count);
    };
    const prismOpacity = state.prismBlend * (1 - state.intro * 0.8);
    if (prismOpacity > 0.01) {
      const spread = 0.94 * state.prismBlend;
      for (const k of [-1, 0, 1]) drawMesh(prismFaces, prismEdges, model(k * spread, k * 0.06, k * -0.12, 0.35 + k * 0.42 + time * 0.07, 1), prismOpacity);
    }
    if (state.caseBlend > 0.01) drawMesh(boxFaces, boxEdges, model(0, 0, 0, time * 0.05 + 0.6, 1.3 + (1 - state.caseBlend) * 0.35), state.caseBlend * 0.45);

    gl.useProgram(points.p);
    gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, read.pos); gl.uniform1i(points.u.uPos, 0);
    gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, read.vel); gl.uniform1i(points.u.uVel, 1);
    gl.uniformMatrix4fv(points.u.uProj, false, proj);
    gl.uniformMatrix4fv(points.u.uView, false, view.m);
    gl.uniform2fv(points.u.uShift, shift);
    gl.uniform1f(points.u.uSize, (compact ? 24 : 26) * (ph / 900));
    gl.uniform1f(points.u.uWidth, SIZE);
    gl.uniform1f(points.u.uLight, state.light);
    gl.bindVertexArray(emptyVao);
    gl.drawArrays(gl.POINTS, 0, drawCount);

    // 4. Composite.
    gl.disable(gl.BLEND);
    pass(composite, null, {
      uScene: st, uFlow: f ? f.velocity.read : blankFlow, uDye: f ? f.dye.read : blankFlow,
      uTime: time, uAberration: state.aberration + state.intro * 2.5, uDisplace: Math.min(1, state.energy * 0.8 + state.intro * 0.6),
      uLight: state.light, uFlowStrength: f ? 0.012 : 0, uResolution: [pw, ph], uFlowTexel: f ? [1 / f.simW, 1 / f.simH] : [0, 0],
      uCenter: [0.5 + v.cx * 0.5, 0.5 + v.cy * 0.5],
    });
    gl.viewport(0, 0, pw, ph);
    gl.disable(gl.SCISSOR_TEST);

    canvas.dispatchEvent(new CustomEvent("scene:frame", { detail: { dt } }));
    schedule();
  }

  function schedule() {
    if (!running || lost || document.hidden) {
      if (frame) cancelAnimationFrame(frame);
      frame = 0;
      last = 0;
    } else if (!frame) {
      frame = requestAnimationFrame(render);
    }
  }

  canvas.addEventListener("webglcontextlost", (event) => { event.preventDefault(); lost = true; schedule(); canvas.dispatchEvent(new Event("scene:lost")); });
  document.addEventListener("visibilitychange", schedule);

  return {
    state,
    count: COUNT,
    resume() { running = true; schedule(); },
    pause() { running = false; schedule(); },
    // Snap, not fade: the page colours change in one frame and the canvas must match them.
    setLight(on) { state.lightTarget = state.light = on ? 1 : 0; schedule(); },
    /** Pointer in canvas NDC (-1..1). */
    pointer(x, y, active) {
      const p = state.pointer;
      const dx = x - p.x, dy = y - p.y;
      p.vx = Math.max(-4, Math.min(4, p.vx + dx * 3));
      p.vy = Math.max(-4, Math.min(4, p.vy + dy * 3));
      if (active && Math.hypot(dx, dy) < 0.5) { p.dx += dx / 2; p.dy += dy / 2; p.moved = true; }
      p.x = x; p.y = y; p.target = active ? 1 : 0;
    },
  };
}
