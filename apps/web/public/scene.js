import { buildShapes } from "./shapes.js";

/*
 * SignalWard observatory scene. WebGL2, no libraries.
 * - GPGPU particles: positions and velocities live in float textures and are integrated on the GPU each frame
 *   (curl-noise flow, damped pointer forces along the camera ray, spring attraction to target formations).
 * - Glass: three spectrometer prisms in the hero that collapse into one specimen case for the chapters.
 * - Composite: HDR accumulation, chromatic aberration and displacement driven by scroll and morph energy.
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
// Divergence-free flow: curl of a noise potential, by central differences.
vec3 curl(vec3 p){
  const float e = 0.1;
  vec3 dx = vec3(e, 0.0, 0.0), dy = vec3(0.0, e, 0.0), dz = vec3(0.0, 0.0, e);
  vec3 px0 = noise3(p - dx), px1 = noise3(p + dx);
  vec3 py0 = noise3(p - dy), py1 = noise3(p + dy);
  vec3 pz0 = noise3(p - dz), pz1 = noise3(p + dz);
  float x = (py1.z - py0.z) - (pz1.y - pz0.y);
  float y = (pz1.x - pz0.x) - (px1.z - px0.z);
  float z = (px1.y - px0.y) - (py1.x - py0.x);
  return vec3(x, y, z) / (2.0 * e);
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
// Spectral stream: a beam enters, separates through the prisms by "wavelength", then converges.
vec3 stream(vec2 cell, float seed, out float fade){
  float s = fract(seed * 7.13 + uTime * 0.045);
  float x = mix(-3.3, 3.3, s);
  float w = hash12(cell * 1.37 + 4.1) - 0.5;
  float a = hash12(cell * 2.91 + 9.7) * 6.2831;
  float spread = smoothstep(-1.25, 0.15, x) * (1.0 - smoothstep(0.7, 2.9, x));
  float radius = 0.05 + 0.07 * (1.0 - spread);
  float y = w * spread * 1.6 + sin(x * 1.3 + uTime * 0.6 + w * 3.0) * 0.06;
  float z = w * spread * 0.35 + sin(a) * radius;
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
  // Stagger the morph per particle so formations dissolve and assemble instead of sliding.
  float m = smoothstep(seed * 0.45, seed * 0.45 + 0.55, uMix);
  vec3 target = mix(tA, tB, m);
  float fade = mix(fadeA, fadeB, m);

  vec3 pos = P.xyz;
  vec3 vel = V.xyz;
  float streaming = (uShapeA == 0 ? 1.0 - m : 0.0) + (uShapeB == 0 ? m : 0.0);
  // Recycle stream particles that wrapped to the other end instead of flying back across the scene.
  if (streaming > 0.98 && abs(target.x - pos.x) > 2.0) { pos = target + (vec3(seed, fract(seed * 13.1), fract(seed * 71.7)) - 0.5) * 0.1; vel *= 0.0; }

  float stiffness = mix(2.2, 5.5, seed) * (1.0 - uIntro * 0.85);
  vec3 force = (target - pos) * stiffness;
  float turbulence = 0.18 + uEnergy * 1.4 + streaming * 0.35 + uIntro * 2.5;
  force += curl(pos * 0.85 + vec3(0.0, 0.0, uTime * 0.08)) * turbulence;

  // Pointer: repel from the camera ray and swirl around it, plus a push along the pointer motion.
  vec3 toP = pos - uRayO;
  vec3 closest = uRayO + uRayD * dot(toP, uRayD);
  vec3 d = pos - closest;
  float dist2 = dot(d, d);
  float influence = exp(-dist2 * 5.0) * uPointer;
  force += normalize(d + 1e-5) * influence * 6.0 + cross(uRayD, d) * influence * 9.0 + uPointerVel * influence * 14.0;

  vel += force * uDt;
  vel *= pow(0.12, uDt);
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
uniform float uSize, uWidth;
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
  float speed = length(V.xyz);
  float glow = smoothstep(0.15, 2.2, speed);
  gl_PointSize = clamp(uSize * (1.0 + glow * 0.8) / max(-mv.z, 0.1), 1.0, 24.0);
  vec3 deep = vec3(0.32, 0.27, 0.78);
  vec3 violet = vec3(0.61, 0.55, 1.0);
  vec3 white = vec3(0.96, 0.95, 0.93);
  vec3 color = mix(mix(deep, violet, smoothstep(0.0, 0.6, glow + 0.35)), white, smoothstep(0.45, 1.0, glow));
  color = mix(color, vec3(1.0, 0.47, 0.4), V.w);
  vColor = color;
  vAlpha = P.w * (0.5 + glow * 0.6 + V.w * 0.6);
}`;

const POINT_FS = `#version 300 es
precision highp float;
in vec3 vColor;
in float vAlpha;
out vec4 outColor;
void main(){
  vec2 c = gl_PointCoord - 0.5;
  float d = dot(c, c);
  float disc = exp(-d * 14.0);
  outColor = vec4(vColor * disc * vAlpha, 1.0);
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
uniform float uOpacity, uLine, uTime;
out vec4 outColor;
void main(){
  if (uLine > 0.5) { outColor = vec4(vec3(0.96, 0.95, 0.93) * 0.2 * uOpacity, 1.0); return; }
  vec3 n = normalize(vNormal);
  vec3 v = normalize(uEye - vWorld);
  float fres = pow(1.0 - abs(dot(n, v)), 2.6);
  // Thin-film tint: hue drifts with the viewing angle, kept inside the violet range.
  float film = 0.5 + 0.5 * sin(dot(n, v) * 9.0 + uTime * 0.4);
  vec3 tint = mix(vec3(0.45, 0.4, 0.95), vec3(0.75, 0.7, 1.0), film);
  vec3 color = tint * fres * 0.42 + vec3(0.07, 0.07, 0.11) * 0.35;
  outColor = vec4(color * uOpacity, 1.0);
}`;

const COMPOSITE_FS = `#version 300 es
precision highp float;
precision highp sampler2D;
in vec2 vUv;
uniform sampler2D uScene;
uniform float uTime, uAberration, uDisplace;
uniform vec2 uResolution;
out vec4 outColor;
${NOISE}
void main(){
  vec2 uv = vUv;
  // Scene transitions: a brief directional tear plus fine displacement while formations morph.
  float band = snoise(vec3(uv.y * 6.0, uTime * 0.9, 0.0));
  uv.x += band * uDisplace * 0.018;
  uv += (vec2(snoise(vec3(uv * 9.0, uTime)), snoise(vec3(uv * 9.0 + 7.0, uTime))) ) * uDisplace * 0.004;
  vec2 dir = uv - 0.5;
  float amount = uAberration * (0.0015 + dot(dir, dir) * 0.03);
  vec3 col;
  col.r = texture(uScene, uv + dir * amount).r;
  col.g = texture(uScene, uv).g;
  col.b = texture(uScene, uv - dir * amount).b;
  col = 1.0 - exp(-col * 1.15);
  vec2 p = vUv - vec2(0.62, 0.5);
  vec3 bg = mix(vec3(0.075, 0.07, 0.115), vec3(0.039, 0.04, 0.055), smoothstep(0.0, 0.9, length(p * vec2(1.2, 1.0))));
  col += bg;
  col *= 1.0 - smoothstep(0.55, 1.25, length(vUv - 0.5)) * 0.65;
  col += (hash12(vUv * uResolution + fract(uTime) * 91.0) - 0.5) * 0.035;
  outColor = vec4(col, 1.0);
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
  gl.linkProgram(p);
  if (!gl.getProgramParameter(p, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(p) ?? "program link failed");
  const uniforms = {};
  const count = gl.getProgramParameter(p, gl.ACTIVE_UNIFORMS);
  for (let i = 0; i < count; i++) {
    const info = gl.getActiveUniform(p, i);
    uniforms[info.name.replace(/\[0\]$/, "")] = gl.getUniformLocation(p, info.name);
  }
  return { p, u: uniforms };
}

// Column-major 4x4 helpers.
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
  const faces = [];
  const edges = [];
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
  const faces = [];
  const edges = [];
  const push = (list, p, n) => list.push(p[0], p[1], p[2], n[0], n[1], n[2]);
  const axes = [[0, 1, 2], [1, 2, 0], [2, 0, 1]];
  for (const [a, b, c] of axes) {
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

function floatTexture(gl, w, h, data) {
  const t = gl.createTexture();
  gl.bindTexture(gl.TEXTURE_2D, t);
  gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA32F, w, h, 0, gl.RGBA, gl.FLOAT, data);
  for (const [k, v] of [[gl.TEXTURE_MIN_FILTER, gl.NEAREST], [gl.TEXTURE_MAG_FILTER, gl.NEAREST], [gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE], [gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE]]) gl.texParameteri(gl.TEXTURE_2D, k, v);
  return t;
}

export function startScene(canvas, { compact = false } = {}) {
  const gl = canvas.getContext("webgl2", { alpha: false, antialias: false, depth: false, powerPreference: "high-performance" });
  if (!gl) throw new Error("WebGL2 unavailable");
  if (!gl.getExtension("EXT_color_buffer_float")) throw new Error("Float render targets unavailable");

  const SIZE = compact ? 64 : 128;
  const COUNT = SIZE * SIZE;

  const sim = program(gl, QUAD_VS, SIM_FS);
  const points = program(gl, POINT_VS, POINT_FS);
  const glass = program(gl, GLASS_VS, GLASS_FS);
  const composite = program(gl, QUAD_VS, COMPOSITE_FS);

  const quadVao = gl.createVertexArray();
  gl.bindVertexArray(quadVao);
  const quadBuffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, quadBuffer);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  for (const prog of [sim, composite]) {
    const loc = gl.getAttribLocation(prog.p, "aPos");
    if (loc >= 0) { gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0); }
  }

  function meshVao(data) {
    const vao = gl.createVertexArray();
    gl.bindVertexArray(vao);
    const buffer = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
    gl.bufferData(gl.ARRAY_BUFFER, data, gl.STATIC_DRAW);
    const pos = gl.getAttribLocation(glass.p, "aPos");
    const nrm = gl.getAttribLocation(glass.p, "aNormal");
    gl.enableVertexAttribArray(pos);
    gl.vertexAttribPointer(pos, 3, gl.FLOAT, false, 24, 0);
    if (nrm >= 0) { gl.enableVertexAttribArray(nrm); gl.vertexAttribPointer(nrm, 3, gl.FLOAT, false, 24, 12); }
    return { vao, count: data.length / 6 };
  }
  const prism = prismMesh();
  const box = boxMesh();
  const prismFaces = meshVao(prism.faces), prismEdges = meshVao(prism.edges);
  const boxFaces = meshVao(box.faces), boxEdges = meshVao(box.edges);
  const emptyVao = gl.createVertexArray();

  // Initial positions: a loose cloud far from the camera so the intro can pull it in.
  const initial = new Float32Array(COUNT * 4);
  let seed = 7;
  const random = () => ((seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0) / 4294967296);
  for (let i = 0; i < COUNT; i++) {
    const u = random() * 2 - 1, a = random() * Math.PI * 2, r = 2.5 + random() * 3.5, s = Math.sqrt(1 - u * u);
    initial.set([Math.cos(a) * s * r, u * r, Math.sin(a) * s * r, 1], i * 4);
  }
  const zero = new Float32Array(COUNT * 4);

  function simTarget(pos, vel) {
    const fb = gl.createFramebuffer();
    gl.bindFramebuffer(gl.FRAMEBUFFER, fb);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, pos, 0);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT1, gl.TEXTURE_2D, vel, 0);
    if (gl.checkFramebufferStatus(gl.FRAMEBUFFER) !== gl.FRAMEBUFFER_COMPLETE) throw new Error("Simulation framebuffer incomplete");
    return { fb, pos, vel };
  }
  let read = simTarget(floatTexture(gl, SIZE, SIZE, initial), floatTexture(gl, SIZE, SIZE, zero));
  let write = simTarget(floatTexture(gl, SIZE, SIZE, initial), floatTexture(gl, SIZE, SIZE, zero));

  const shapes = buildShapes(COUNT);
  const shapeTex = gl.createTexture();
  gl.bindTexture(gl.TEXTURE_2D_ARRAY, shapeTex);
  gl.texImage3D(gl.TEXTURE_2D_ARRAY, 0, gl.RGBA32F, SIZE, SIZE, shapes.length, 0, gl.RGBA, gl.FLOAT, null);
  shapes.forEach((data, layer) => gl.texSubImage3D(gl.TEXTURE_2D_ARRAY, 0, 0, 0, layer, SIZE, SIZE, 1, gl.RGBA, gl.FLOAT, data));
  gl.texParameteri(gl.TEXTURE_2D_ARRAY, gl.TEXTURE_MIN_FILTER, gl.NEAREST);
  gl.texParameteri(gl.TEXTURE_2D_ARRAY, gl.TEXTURE_MAG_FILTER, gl.NEAREST);

  // HDR scene target.
  const sceneTex = gl.createTexture();
  const sceneFb = gl.createFramebuffer();
  let targetW = 0, targetH = 0;
  function resizeTarget(w, h) {
    if (w === targetW && h === targetH) return;
    targetW = w; targetH = h;
    gl.bindTexture(gl.TEXTURE_2D, sceneTex);
    gl.texImage2D(gl.TEXTURE_2D, 0, gl.RGBA16F, w, h, 0, gl.RGBA, gl.HALF_FLOAT, null);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
    gl.texParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
    gl.bindFramebuffer(gl.FRAMEBUFFER, sceneFb);
    gl.framebufferTexture2D(gl.FRAMEBUFFER, gl.COLOR_ATTACHMENT0, gl.TEXTURE_2D, sceneTex, 0);
  }

  // State driven by the page.
  const state = {
    shapeA: 0, shapeB: 0, mix: 0,
    caseBlend: 0, prismBlend: 1,
    energy: 0, aberration: 0,
    intro: 1,
    pointer: { x: 0, y: 0, vx: 0, vy: 0, active: 0, target: 0 },
  };
  let cam = { angle: 0.38, height: 0.35, radius: 13 };
  let running = false, frame = 0, last = 0, lost = false, time = 0;
  let dprCap = compact ? 1 : 1.5;
  const frameTimes = [];
  let drawCount = COUNT;

  function adapt(dt) {
    frameTimes.push(dt);
    if (frameTimes.length < 90) return;
    const average = frameTimes.reduce((a, b) => a + b, 0) / frameTimes.length;
    frameTimes.length = 0;
    if (average > 0.026 && dprCap > 1) dprCap = 1;
    else if (average > 0.034 && drawCount > COUNT / 4) drawCount = Math.floor(drawCount / 2);
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
    resizeTarget(pw, ph);

    const narrow = width / height < 0.95;
    state.intro = Math.max(0, state.intro - dt * 0.55);
    const p = state.pointer;
    p.active += (p.target - p.active) * Math.min(1, dt * 4);

    // Camera: dolly in after boot, orbit with scroll and pointer parallax.
    const radiusGoal = (narrow ? 7.6 : 6.0) + state.caseBlend * 1.4;
    cam.radius += (radiusGoal + state.intro * 7 - cam.radius) * Math.min(1, dt * 2.2);
    cam.angle += (0.38 + state.mix * 0.18 + state.caseBlend * 0.25 + p.x * 0.12 + time * 0.012 - cam.angle) * Math.min(1, dt * 2.5);
    cam.height += (0.35 + p.y * 0.22 - cam.height) * Math.min(1, dt * 2.5);
    const eye = [Math.sin(cam.angle) * cam.radius, cam.height, Math.cos(cam.angle) * cam.radius];
    const view = lookAt(eye, [0, 0, 0], [0, 1, 0]);
    const fov = 0.62;
    const aspect = pw / ph;
    const proj = perspective(fov, aspect, 0.1, 60);
    const shift = narrow ? [0, 0.32] : [0.36, 0.0];

    // Pointer ray through the shifted projection.
    const tanHalf = Math.tan(fov / 2);
    const ndcX = p.x - shift[0], ndcY = p.y - shift[1];
    const rayD = norm([
      -view.z[0] + view.x[0] * ndcX * tanHalf * aspect + view.y[0] * ndcY * tanHalf,
      -view.z[1] + view.x[1] * ndcX * tanHalf * aspect + view.y[1] * ndcY * tanHalf,
      -view.z[2] + view.x[2] * ndcX * tanHalf * aspect + view.y[2] * ndcY * tanHalf,
    ]);
    const pv = [view.x[0] * p.vx + view.y[0] * p.vy, view.x[1] * p.vx + view.y[1] * p.vy, view.x[2] * p.vx + view.y[2] * p.vy];
    p.vx *= Math.pow(0.02, dt); p.vy *= Math.pow(0.02, dt);

    // 1. Simulate.
    gl.disable(gl.BLEND);
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

    // 2. Scene into the HDR target, additive.
    gl.bindFramebuffer(gl.FRAMEBUFFER, sceneFb);
    gl.drawBuffers([gl.COLOR_ATTACHMENT0]);
    gl.viewport(0, 0, pw, ph);
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
    const prismOpacity = state.prismBlend * (1 - state.intro * 0.8);
    if (prismOpacity > 0.01) {
      const spread = 0.94 * state.prismBlend;
      [-1, 0, 1].forEach((k) => {
        const m = model(k * spread, k * 0.06, k * -0.12, 0.35 + k * 0.42 + time * 0.07, 1);
        gl.uniformMatrix4fv(glass.u.uModel, false, m);
        gl.uniform1f(glass.u.uOpacity, prismOpacity);
        gl.uniform1f(glass.u.uLine, 0);
        gl.bindVertexArray(prismFaces.vao); gl.drawArrays(gl.TRIANGLES, 0, prismFaces.count);
        gl.uniform1f(glass.u.uLine, 1);
        gl.bindVertexArray(prismEdges.vao); gl.drawArrays(gl.LINES, 0, prismEdges.count);
      });
    }
    if (state.caseBlend > 0.01) {
      const m = model(0, 0, 0, time * 0.05 + 0.6, 1.3 + (1 - state.caseBlend) * 0.35);
      gl.uniformMatrix4fv(glass.u.uModel, false, m);
      gl.uniform1f(glass.u.uOpacity, state.caseBlend * 0.45);
      gl.uniform1f(glass.u.uLine, 0);
      gl.bindVertexArray(boxFaces.vao); gl.drawArrays(gl.TRIANGLES, 0, boxFaces.count);
      gl.uniform1f(glass.u.uLine, 1);
      gl.bindVertexArray(boxEdges.vao); gl.drawArrays(gl.LINES, 0, boxEdges.count);
    }

    gl.useProgram(points.p);
    gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, read.pos); gl.uniform1i(points.u.uPos, 0);
    gl.activeTexture(gl.TEXTURE1); gl.bindTexture(gl.TEXTURE_2D, read.vel); gl.uniform1i(points.u.uVel, 1);
    gl.uniformMatrix4fv(points.u.uProj, false, proj);
    gl.uniformMatrix4fv(points.u.uView, false, view.m);
    gl.uniform2fv(points.u.uShift, shift);
    gl.uniform1f(points.u.uSize, (compact ? 24 : 26) * (ph / 900));
    gl.uniform1f(points.u.uWidth, SIZE);
    gl.bindVertexArray(emptyVao);
    gl.drawArrays(gl.POINTS, 0, drawCount);

    // 3. Composite to screen.
    gl.disable(gl.BLEND);
    gl.bindFramebuffer(gl.FRAMEBUFFER, null);
    gl.viewport(0, 0, pw, ph);
    gl.useProgram(composite.p);
    gl.activeTexture(gl.TEXTURE0); gl.bindTexture(gl.TEXTURE_2D, sceneTex); gl.uniform1i(composite.u.uScene, 0);
    gl.uniform1f(composite.u.uTime, time);
    gl.uniform1f(composite.u.uAberration, state.aberration + state.intro * 2.5);
    gl.uniform1f(composite.u.uDisplace, Math.min(1, state.energy * 0.8 + state.intro * 0.6));
    gl.uniform2f(composite.u.uResolution, pw, ph);
    gl.bindVertexArray(quadVao);
    gl.drawArrays(gl.TRIANGLES, 0, 3);

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
    pointer(x, y, active) {
      const p = state.pointer;
      p.vx += (x - p.x) * 3; p.vy += (y - p.y) * 3;
      p.vx = Math.max(-4, Math.min(4, p.vx)); p.vy = Math.max(-4, Math.min(4, p.vy));
      p.x = x; p.y = y; p.target = active ? 1 : 0;
    },
  };
}
