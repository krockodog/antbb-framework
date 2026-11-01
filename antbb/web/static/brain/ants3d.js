// 3D Neural-City Overlay. Does NOT touch engine.js / generators.js.
// Layout (1600×1000 fit): majestic Red Queen on throne + kneeling scout (center),
// organic red city below; Blue left, Yellow right. All faces toward camera.
import * as THREE from "three";
import { GLTFLoader } from "three/addons/loaders/GLTFLoader.js";
import { MeshoptDecoder } from "three/addons/libs/meshopt_decoder.module.js";
import { CSS2DRenderer, CSS2DObject } from "three/addons/renderers/CSS2DRenderer.js";

const M = "/static/brain/models/";
const TEAM = { red: 0xff3b3b, blue: 0x3b8bff, yellow: 0xffd23b };
const MODEL = {
  queen_red: "queen.glb", queen_blue: "queen_blue.glb", queen_yellow: "queen_yellow.glb",
  spear: "spartan_spear.glb", shield: "spartan_shield.glb", scout: "archer.glb", worker: "worker.glb",
};
const YELLOW = [
  ["triage", "re-triage", "Triage-Soldat", "scout"],
  ["pe", "pe-exe-re", "PE-Windows-Soldat", "shield"],
  ["dotnet", "dotnet-re", ".NET-Soldat", "shield"],
  ["android", "apk-android-re", "Android-Soldat", "shield"],
  ["elf", "elf-macho-re", "ELF-Soldat", "shield"],
  ["hex", "hex-firmware-re", "Firmware-Soldat", "shield"],
  ["carve", "re-triage", "Carving-Soldat", "worker"],
  ["dos", "dos-mz-16bit-re", "DOS-Soldat", "shield"],
  ["dynamic", "dynamic-lab-re", "Dynamic-Lab-Soldat", "spear"],
].map(([name, skill, title, role]) => ({ name, skills: [skill], title, role }));

function roleOf(s) {
  const ph = (s.blue_phases || s.phases || []);
  const pbs = s.playbooks || [];
  if (ph.includes("recon") || ph.includes("watch")) return "scout";
  if (ph.includes("report") || ph.includes("remediate")) return "worker";
  if (pbs.some(p => p.mode === "offensive")) return "spear";
  return "shield";
}
function esc(t) { return String(t ?? "").replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c])); }

function badge(team, s, queen) {
  const d = document.createElement("div");
  d.className = "a3d-badge a3d-" + team + (queen ? " a3d-queen" : "");
  const top = (s.skills || [])[0] || "";
  const all = (s.skills || []).slice(0, 6).join(" · ");
  d.title = all || s.title || s.name;
  if (queen) {
    d.innerHTML = `<b>${esc(s.name)}</b><i>${esc(s.title || "")}</i>` +
      (s.skills || []).slice(0, 2).map(k => `<span>${esc(k)}</span>`).join("");
  } else {
    d.innerHTML = `<b>${esc(s.name)}</b><span>${esc(top)}</span>`;
  }
  return new CSS2DObject(d);
}

/** Recognizable throne: wide dais, tall back with crest, armrests, velvet + gold. */
function buildThrone() {
  const g = new THREE.Group();
  const velvet = new THREE.MeshBasicMaterial({ color: 0x8b1020 });
  const gold = new THREE.MeshBasicMaterial({ color: 0xffd278 });
  const stone = new THREE.MeshBasicMaterial({ color: 0x3a281c });
  // Three wide steps (clearly a dais)
  [[260, 16, 150, 0], [210, 15, 120, 16], [165, 14, 95, 31]].forEach(([w, h, d, y], i) => {
    const step = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), stone);
    step.position.set(0, y + h / 2, 18 - i * 6); g.add(step);
    const lip = new THREE.Mesh(new THREE.BoxGeometry(w + 6, 3.5, d + 6), gold);
    lip.position.set(0, y + h, 18 - i * 6); g.add(lip);
  });
  const seatY = 45;
  const seat = new THREE.Mesh(new THREE.BoxGeometry(120, 16, 78), velvet);
  seat.position.set(0, seatY, 8); g.add(seat);
  // Tall backrest + gold frame
  const back = new THREE.Mesh(new THREE.BoxGeometry(130, 175, 16), velvet);
  back.position.set(0, seatY + 88, -34); g.add(back);
  const frame = new THREE.Mesh(new THREE.BoxGeometry(140, 185, 5), gold);
  frame.position.set(0, seatY + 88, -43); g.add(frame);
  // Crest / crown finial (makes throne unmistakable)
  const crest = new THREE.Mesh(new THREE.ConeGeometry(22, 36, 5), gold);
  crest.position.set(0, seatY + 190, -34); g.add(crest);
  const orb = new THREE.Mesh(new THREE.SphereGeometry(10, 16, 12), gold);
  orb.position.set(0, seatY + 210, -34); g.add(orb);
  // Side pillars + armrests
  [-1, 1].forEach(side => {
    const pillar = new THREE.Mesh(new THREE.CylinderGeometry(9, 11, 175, 10), gold);
    pillar.position.set(side * 72, seatY + 70, -28); g.add(pillar);
    const arm = new THREE.Mesh(new THREE.BoxGeometry(18, 26, 78), gold);
    arm.position.set(side * 64, seatY + 18, 8); g.add(arm);
    const banner = new THREE.Mesh(new THREE.PlaneGeometry(28, 90),
      new THREE.MeshBasicMaterial({ color: 0xb01020, side: THREE.DoubleSide, transparent: true, opacity: 0.92 }));
    banner.position.set(side * 95, seatY + 70, -10); g.add(banner);
  });
  // Soft red glow under dais
  const glow = new THREE.Mesh(new THREE.CircleGeometry(180, 48),
    new THREE.MeshBasicMaterial({ color: 0xff3b3b, transparent: true, opacity: 0.14, depthWrite: false }));
  glow.rotation.x = -Math.PI / 2; glow.position.y = 1; g.add(glow);
  g.userData.seatY = seatY + 16;
  return g;
}

/** Organic arc/semicircle positions around a hub (not a spreadsheet grid). */
function arcPositions(n, cx, cy, radius, spread = Math.PI * 0.95, rows = 2) {
  const out = [];
  let left = n, i = 0;
  for (let r = 0; r < rows && left > 0; r++) {
    const take = Math.min(left, Math.ceil(left / (rows - r)));
    const rad = radius + r * 72;
    for (let k = 0; k < take; k++) {
      const t = take === 1 ? 0.5 : k / (take - 1);
      const ang = -spread / 2 + t * spread - Math.PI / 2;
      const jitter = ((i * 17) % 7) - 3;
      out.push({ x: cx + Math.cos(ang) * rad + jitter, y: cy + Math.sin(ang) * rad * 0.55 + r * 8 });
      i++; left--;
    }
  }
  return out;
}

async function main() {
  const canvas = document.createElement("canvas");
  canvas.id = "ants3d-canvas";
  const gl = canvas.getContext("webgl2", { alpha: true, antialias: true })
          || canvas.getContext("webgl",  { alpha: true, antialias: true });
  if (!gl) return;

  const css = document.createElement("style");
  css.textContent = `#ants3d-canvas,#ants3d-labels,#a3d-trails{position:fixed;inset:0;pointer-events:none;z-index:2}
  #a3d-trails{z-index:3}
  .a3d-badge{font:8px/1.15 system-ui,sans-serif;color:#eef;background:rgba(4,8,18,.78);border:1px solid;border-left-width:2px;
   border-radius:3px;padding:1px 4px;max-width:64px;text-align:center;white-space:nowrap;overflow:hidden;
   backdrop-filter:blur(2px);pointer-events:auto;cursor:help;transform:translateY(4px)}
  .a3d-badge b,.a3d-badge span,.a3d-badge i{display:block;overflow:hidden;text-overflow:ellipsis}
  .a3d-badge i{opacity:.7;font-size:8px}.a3d-badge span{font-size:8px;color:#bcd;opacity:.9}
  .a3d-red{border-color:#ff3b3b}.a3d-blue{border-color:#3b8bff}.a3d-yellow{border-color:#ffd23b}
  .a3d-queen{font-size:11px;max-width:150px;border-width:2px;border-left-width:4px;padding:4px 7px;text-align:left}
  .a3d-red.a3d-queen{background:rgba(50,6,6,.9);color:#ffd96b;font-size:12px}
  .ant.queen,.ant-colony .ant{display:none!important}
  .ant-colony canvas.ant-pheromone{opacity:.35}
  /* Keep Zeitraffer from eating the bottom clusters */
  #brain-tl-bar{max-width:260px!important;max-height:110px!important;transform:scale(.85);transform-origin:bottom left;opacity:.78!important}
  .brain-runs, #brain-runs, .runs-panel, [class*="zeitraffer"], #runs-panel,
  .runs-dock, #brain-run-panel, .zeitraffer{
    max-height:100px!important; max-width:280px!important;
    bottom:6px!important; left:6px!important; opacity:.75; transform:scale(.92); transform-origin:bottom left}`;
  document.head.appendChild(css);

  const renderer = new THREE.WebGLRenderer({ canvas, context: gl, alpha: true, antialias: true });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  const labels = new CSS2DRenderer(); labels.domElement.id = "ants3d-labels";
  const scene = new THREE.Scene();
  scene.add(new THREE.AmbientLight(0xffffff, 1.35));
  scene.add(new THREE.HemisphereLight(0xffffff, 0x334455, 1.8));
  const key = new THREE.DirectionalLight(0xffffff, 2.8); key.position.set(200, 500, 900); scene.add(key);
  const fill = new THREE.DirectionalLight(0xaaccff, 0.9); fill.position.set(-400, 200, 400); scene.add(fill);
  const rim = new THREE.DirectionalLight(0xff8866, 0.55); rim.position.set(0, 100, -500); scene.add(rim);

  const cam = new THREE.OrthographicCamera(0, 1, 0, -1, -4000, 4000);
  cam.position.z = 1500;

  let data;
  try { data = await (await fetch("/api/soldiers")).json(); } catch (_) { return; }
  const all = data.soldiers || [];
  const mk = (s) => ({ name: s.name, title: s.specialty, role: roleOf(s),
    skills: [s.skill && s.skill.name, ...(s.playbooks || []).map(p => p.name)].filter(Boolean) });
  const red = all.filter(s => !s.name.startsWith("blue-")).map(mk);
  const blue = all.filter(s => s.name.startsWith("blue-")).map(mk);

  const loader = new GLTFLoader().setMeshoptDecoder(MeshoptDecoder);
  const cache = {};
  const load = (key) => cache[key] ||= loader.loadAsync(M + MODEL[key]).then(g => {
    const o = g.scene;
    const box = new THREE.Box3().setFromObject(o);
    const sz = box.getSize(new THREE.Vector3()), ctr = box.getCenter(new THREE.Vector3());
    o.position.sub(ctr); o.position.y += sz.y / 2;
    // Models authored side-on (+X); rotate so face looks at camera (+Z).
    o.rotation.y = -Math.PI / 2;
    const w = new THREE.Group(); w.add(o);
    w.userData = { h: sz.y, hasSkel: !!o.getObjectByProperty("isSkinnedMesh", true),
      hasAnim: (g.animations || []).length > 0 };
    return w;
  });

  const matCache = new Map();
  function tint(obj, team, pomp) {
    obj.traverse(m => {
      if (!m.isMesh || !m.material) return;
      const mats = Array.isArray(m.material) ? m.material : [m.material];
      const out = mats.map(mt => {
        const key = mt.uuid + ":" + team + ":" + pomp;
        if (matCache.has(key)) return matCache.get(key);
        // MeshBasic keeps albedo readable under software GL
        const b = new THREE.MeshBasicMaterial({
          color: mt.color ? mt.color.clone() : new THREE.Color(0xffffff),
          map: mt.map || null, transparent: !!mt.transparent, opacity: mt.opacity ?? 1,
          side: THREE.DoubleSide,
        });
        if (pomp === "royal") b.color.lerp(new THREE.Color(0xffe0a0), 0.1);
        else b.color.lerp(new THREE.Color(TEAM[team]), 0.14);
        b.userData._basic = true;
        matCache.set(key, b); return b;
      });
      m.material = Array.isArray(m.material) ? out : out[0];
      m.frustumCulled = false;
    });
  }

  // Screen coords: x right, y down from top. World y = -screenY for ortho top=0 bottom=-H.
  const ants = [];
  // Facing: all ants face camera (+Z). Small sway only in tick — never turn away.
  const FACE = -Math.PI / 2; // models authored side-on; -90° → face camera

  async function place(modelKey, team, pomp, x, y, hpx, s, queen, opts = {}) {
    const proto = await load(modelKey);
    const o = proto.clone(true);
    tint(o, team, pomp);
    let k = hpx / proto.userData.h;
    if (opts.kneel) k *= 0.86;
    o.scale.setScalar(k);
    o.position.set(x, -y, opts.z || 0);
    // Inner mesh already faces camera; group only gets tiny faceYaw offset (kneel toward queen)
    o.rotation.y = (opts.faceYaw || 0);
    o.rotation.x = opts.kneel ? 0.72 : 0.06;
    o.rotation.z = opts.kneel ? 0.05 : 0;
    if (opts.kneel) { o.position.y += 18; o.position.z += 40; }
    const l = badge(team, s, queen);
    if (queen) {
      // Place label to the right of the queen so throne + figure stay clear
      l.position.set(55 / k, 40 / k, 20);
      l.center.set(0, 0.5);
    } else {
      l.position.set(0, -20 / k, 0);
      l.center.set(0.5, 0);
    }
    o.add(l);
    scene.add(o);
    ants.push({ obj: o, bob: 0.5 + Math.random() * 0.35, phase: Math.random() * Math.PI * 2,
      baseY: o.position.y, faceYaw: o.rotation.y });
    return { hasSkel: proto.userData.hasSkel, hasAnim: proto.userData.hasAnim };
  }

  const W = Math.min(innerWidth, 1600) || 1600;
  const H = Math.min(innerHeight, 1000) || 1000;
  // Use full viewport for layout math; canvas sized to window
  const VW = innerWidth, VH = innerHeight;
  renderer.setSize(VW, VH); labels.setSize(VW, VH);
  cam.left = 0; cam.right = VW; cam.top = 0; cam.bottom = -VH; cam.updateProjectionMatrix();

  // --- Safe frame inside header (~56px) and Zeitraffer (~130px) ---
  const TOP = 135;         // clear sticky header + title
  const BOTTOM = VH - 140; // clear Zeitraffer
  const cx = VW * 0.5;

  // THRONE — fully visible, majestic, center-upper
  const throne = buildThrone();
  const tScale = 0.55;
  throne.scale.setScalar(tScale);
  // Place so crest is below TOP and seat is around y≈200
  const throneScreenY = TOP + 185; // dais center — fully below header
  throne.position.set(cx, -throneScreenY, -50);
  // Face throne toward camera slightly
  throne.rotation.y = 0;
  scene.add(throne);
  const seatY = throneScreenY - throne.userData.seatY * tScale;

  // RED QUEEN on throne (largest) — fully on screen
  const qH = 135;
  const scoutInfo = { hasSkel: false, hasAnim: false };
  await place("queen_red", "red", "royal", cx, seatY + 4, qH, {
    name: "ROTE KÖNIGIN", title: "Absolute Herrscherin · All and One",
    skills: [`${red.length} Soldaten`, "Oversight-Gate"],
  }, true, { z: 20, faceYaw: 0 });

  // Kneeling scout — face mostly toward camera (slight turn to queen, face still readable)
  await place("scout", "red", "team", cx - 70, throneScreenY + 95, 70, {
    name: "Scout", title: "Kniend vor der Königin", skills: ["recon-master"],
  }, false, { kneel: true, z: 55, faceYaw: 0.35 });

  // RED CITY — organic arcs below throne (not a spreadsheet)
  const redHubY = throneScreenY + 175;
  const redPos = arcPositions(red.length, cx, redHubY, 130, Math.PI * 1.05, 3);
  const jobs = [];
  red.forEach((s, i) => {
    const p = redPos[i] || { x: cx, y: redHubY + i * 40 };
    jobs.push(place(s.role, "red", "team", p.x, p.y, 52, s, false, { z: 5 + (i % 3) }));
  });

  // Side queens — mid height, fully on screen
  const sideY = Math.min(redHubY + 195, BOTTOM - 300);
  const bx = VW * 0.24, yx = VW * 0.78;  // leave room for Zeitraffer bottom-left

  jobs.push(place("queen_blue", "blue", "team", bx, sideY, 105, {
    name: "Blaue Königin", title: "Verteidigung", skills: [`${blue.length} Soldaten`],
  }, true, { faceYaw: 0 }));
  jobs.push(place("queen_yellow", "yellow", "team", yx, sideY, 105, {
    name: "Gelbe Königin", title: "RE · Schmiedin", skills: [`${YELLOW.length} Soldaten`],
  }, true, { faceYaw: 0 }));

  // Blue / Yellow organic clusters (compact, stay above BOTTOM)
  const bluePos = arcPositions(Math.min(blue.length, 8), bx, sideY + 100, 95, Math.PI * 0.85, 2);
  blue.slice(0, 8).forEach((s, i) => {
    const p = bluePos[i];
    jobs.push(place(s.role, "blue", "team", p.x, Math.min(p.y, BOTTOM - 40), 44, s, false));
  });
  const yelPos = arcPositions(YELLOW.length, yx, sideY + 95, 80, Math.PI * 0.85, 2);
  YELLOW.forEach((s, i) => {
    const p = yelPos[i];
    jobs.push(place(s.role, "yellow", "team", p.x, Math.min(p.y, BOTTOM - 40), 44, s, false));
  });
  await Promise.all(jobs);

  // ---- Elegant pheromone trails: thin dotted glowing paths ----
  const trailCv = document.createElement("canvas");
  trailCv.id = "a3d-trails";
  document.body.appendChild(canvas);
  document.body.appendChild(labels.domElement);
  document.body.appendChild(trailCv);
  const tctx = trailCv.getContext("2d");
  function resizeTrails() {
    const dpr = Math.min(devicePixelRatio, 2);
    trailCv.width = Math.floor(innerWidth * dpr);
    trailCv.height = Math.floor(innerHeight * dpr);
    trailCv.style.width = innerWidth + "px";
    trailCv.style.height = innerHeight + "px";
    tctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  }
  resizeTrails();

  // Build wandering paths: queen hubs → soldiers (Bezier), store as particles along path
  const particles = [];
  function addPath(x0, y0, x1, y1, col, n = 20) {
    const mx = (x0 + x1) / 2 + (Math.random() - 0.5) * 60;
    const my = (y0 + y1) / 2 + (Math.random() - 0.5) * 40;
    for (let i = 0; i < n; i++) {
      const t = i / (n - 1);
      const omt = 1 - t;
      const x = omt * omt * x0 + 2 * omt * t * mx + t * t * x1;
      const y = omt * omt * y0 + 2 * omt * t * my + t * t * y1;
      particles.push({
        x, y, col,
        born: performance.now() / 1000 - t * 6,
        life: 7 + Math.random() * 5,
        r: 0.7 + Math.random() * 0.9,
        phase: Math.random() * Math.PI * 2,
      });
    }
  }
  // Red city paths from throne
  redPos.forEach((p, i) => { if (i % 1 === 0) addPath(cx, seatY + 30, p.x, p.y, "255,120,120", 20); });
  // Cross links queen ↔ queens (subtle)
  addPath(cx, seatY, bx, sideY, "56,200,255", 30);
  addPath(cx, seatY, yx, sideY, "255,200,80", 30);
  bluePos.forEach((p, i) => { if (i % 3 === 0) addPath(bx, sideY + 20, p.x, p.y, "80,160,255", 18); });
  yelPos.forEach((p, i) => { if (i % 2 === 0) addPath(yx, sideY + 20, p.x, p.y, "255,210,70", 18); });
  // A few wandering free trails
  for (let i = 0; i < 5; i++) {
    addPath(VW * (0.2 + Math.random() * 0.6), TOP + 80 + Math.random() * 200,
            VW * (0.2 + Math.random() * 0.6), BOTTOM - 60 - Math.random() * 100,
            ["56,224,255", "210,160,90", "176,100,255"][i % 3], 24);
  }

  // No page spacer — scene fits viewport
  const spacer = document.getElementById("ants3d-spacer");
  if (spacer) spacer.remove();

  const clock = new THREE.Clock();
  (function tick() {
    const t = clock.getElapsedTime();
    // No scroll follow needed for fit layout
    ants.forEach(a => {
      // Gentle sway only (±6°), never turn away from camera
      a.obj.rotation.y = a.faceYaw + Math.sin(t * 0.55 + a.phase) * 0.10;
      a.obj.position.y = a.baseY + Math.sin(t * a.bob + a.phase) * 1.2;
    });
    // Fine glowing dotted trails (elegant, not marker blobs)
    const now = performance.now() / 1000;
    tctx.clearRect(0, 0, innerWidth, innerHeight);
    // Group particles into polylines by similar birth streams: draw tiny dots only
    for (const p of particles) {
      let age = now - p.born;
      if (age > p.life) { p.born = now; age = 0; }
      const fade = 1 - age / p.life;
      const twinkle = 0.5 + 0.5 * Math.sin(now * 1.8 + p.phase);
      const a = Math.pow(fade, 1.4) * twinkle * 0.55;
      if (a < 0.04) continue;
      const r = 0.55 + 0.55 * fade; // tiny
      tctx.beginPath();
      tctx.fillStyle = `rgba(${p.col},${(a * 0.35).toFixed(3)})`;
      tctx.arc(p.x, p.y, r * 2.2, 0, Math.PI * 2); tctx.fill();
      tctx.beginPath();
      tctx.fillStyle = `rgba(${p.col},${a.toFixed(3)})`;
      tctx.arc(p.x, p.y, r * 0.7, 0, Math.PI * 2); tctx.fill();
    }
    // Thin connecting strokes along each path segment (every N particles share a path)
    tctx.lineCap = "round";
    for (let i = 0; i < particles.length - 1; i++) {
      const a = particles[i], b = particles[i + 1];
      if (a.col !== b.col) continue;
      const dist = Math.hypot(a.x - b.x, a.y - b.y);
      if (dist > 28 || dist < 2) continue;
      let age = now - a.born; if (age < 0 || age > a.life) continue;
      const fade = 1 - age / a.life;
      const alpha = Math.pow(fade, 1.3) * 0.28;
      if (alpha < 0.03) continue;
      tctx.beginPath();
      tctx.strokeStyle = `rgba(${a.col},${alpha.toFixed(3)})`;
      tctx.lineWidth = 0.7;
      tctx.moveTo(a.x, a.y); tctx.lineTo(b.x, b.y); tctx.stroke();
    }
    renderer.render(scene, cam); labels.render(scene, cam);
    requestAnimationFrame(tick);
  })();

  addEventListener("resize", () => location.reload(), { once: true });
  window.__ants3d = {
    count: ants.length, red: red.length, blue: blue.length, yellow: YELLOW.length,
    scoutKneel: "best-effort (no skeleton — bowed + lowered; face toward camera)",
    facing: "all front-facing toward camera (±6° sway)",
  };
}
main().catch(e => console.warn("[ants3d] Fallback auf 2D-Sprites:", e));
