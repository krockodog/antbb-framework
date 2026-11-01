// 3D-Ameisenvolk-Overlay. Fasst engine.js / generators.js / ants.js NICHT an.
// Layout: Mitte = Rote Königin auf Thron + kniender Scout + rotes Volk.
//         Links = Blaue Königin + blaues Volk. Rechts = Gelbe Königin + gelbes Volk.
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
// Gelbes Volk: echte Registry aus yellow-queen/soldiers (antbb/agents/yellow entfernt seit 8397411).
const YELLOW = [
  ["triage", "re-triage", "Triage-Soldat", "scout"],
  ["pe", "pe-exe-re · packer-unpack-re", "PE-Windows-Soldat", "shield"],
  ["dotnet", "dotnet-re", ".NET-Soldat", "shield"],
  ["android", "apk-android-re", "Android-Soldat", "shield"],
  ["elf", "elf-macho-re", "ELF-Soldat", "shield"],
  ["hex", "hex-firmware-re", "Firmware-/HEX-Soldat", "shield"],
  ["carve", "re-triage", "Carving-Soldat", "worker"],
  ["dos", "dos-mz-16bit-re", "DOS-16-Bit-Soldat", "shield"],
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
  d.innerHTML = `<b>${esc(s.name)}</b><i>${esc(s.title || "")}</i>` +
    (s.skills || []).slice(0, 3).map(k => `<span>${esc(k)}</span>`).join("");
  return new CSS2DObject(d);
}

/** Elegant throne: dais steps + high backrest, red velvet + gold trim. Pure three.js geometry. */
function buildThrone() {
  const g = new THREE.Group();
  const velvet = new THREE.MeshStandardMaterial({ color: 0x6a0a14, roughness: 0.85, metalness: 0.05, roughnessMap: null });
  const gold = new THREE.MeshStandardMaterial({ color: 0xd4a84b, roughness: 0.35, metalness: 0.85,
    emissive: new THREE.Color(0x3a2808), emissiveIntensity: 0.25 });
  const stone = new THREE.MeshStandardMaterial({ color: 0x2a1a14, roughness: 0.9, metalness: 0.15 });
  // Three dais steps
  [[220, 18, 140, 0], [180, 16, 110, 18], [140, 14, 85, 34]].forEach(([w, h, d, y], i) => {
    const step = new THREE.Mesh(new THREE.BoxGeometry(w, h, d), stone);
    step.position.set(0, y + h / 2, 20 - i * 8); g.add(step);
    const trim = new THREE.Mesh(new THREE.BoxGeometry(w + 4, 3, d + 4), gold);
    trim.position.set(0, y + h, 20 - i * 8); g.add(trim);
  });
  // Seat cushion
  const seatY = 48;
  const seat = new THREE.Mesh(new THREE.BoxGeometry(110, 14, 70), velvet);
  seat.position.set(0, seatY, 5); g.add(seat);
  // High backrest
  const back = new THREE.Mesh(new THREE.BoxGeometry(120, 160, 14), velvet);
  back.position.set(0, seatY + 80, -32); g.add(back);
  const backGold = new THREE.Mesh(new THREE.BoxGeometry(126, 166, 4), gold);
  backGold.position.set(0, seatY + 80, -40); g.add(backGold);
  // Finial / crown on top
  const crown = new THREE.Mesh(new THREE.ConeGeometry(18, 28, 6), gold);
  crown.position.set(0, seatY + 170, -32); g.add(crown);
  // Armrests
  [-1, 1].forEach(side => {
    const arm = new THREE.Mesh(new THREE.BoxGeometry(16, 28, 70), gold);
    arm.position.set(side * 58, seatY + 20, 5); g.add(arm);
    const post = new THREE.Mesh(new THREE.CylinderGeometry(7, 9, 70, 10), gold);
    post.position.set(side * 58, seatY - 20, 35); g.add(post);
  });
  // Soft ground glow under throne
  const glow = new THREE.Mesh(new THREE.CircleGeometry(160, 48),
    new THREE.MeshBasicMaterial({ color: 0xff3b3b, transparent: true, opacity: 0.12, depthWrite: false }));
  glow.rotation.x = -Math.PI / 2; glow.position.y = 1; g.add(glow);
  g.userData.seatY = seatY + 14; // queen feet height
  return g;
}

async function main() {
  const canvas = document.createElement("canvas");
  canvas.id = "ants3d-canvas";
  const gl = canvas.getContext("webgl2", { alpha: true, antialias: true })
          || canvas.getContext("webgl",  { alpha: true, antialias: true, preserveDrawingBuffer: true });
  if (!gl) return;
  const css = document.createElement("style");
  css.textContent = `#ants3d-canvas,#ants3d-labels{position:fixed;inset:0;pointer-events:none;z-index:2}
  .a3d-badge{font:10px/1.25 system-ui,sans-serif;color:#fff;background:rgba(5,8,20,.82);border:1px solid;border-left-width:3px;
   border-radius:5px;padding:3px 6px;max-width:112px;text-align:left;white-space:nowrap;overflow:hidden;backdrop-filter:blur(2px)}
  .a3d-badge b,.a3d-badge i,.a3d-badge span{display:block;overflow:hidden;text-overflow:ellipsis}
  .a3d-badge i{opacity:.75;font-size:9px}.a3d-badge span{font-size:9px;color:#cfe}
  .a3d-red{border-color:#ff3b3b}.a3d-blue{border-color:#3b8bff}.a3d-yellow{border-color:#ffd23b}
  .a3d-queen{font-size:12px;max-width:180px;border-width:2px;border-left-width:5px;padding:5px 8px}
  .a3d-red.a3d-queen{background:rgba(60,5,5,.88);color:#ffd96b;font-size:13px}
  .ant.queen{display:none!important}
  /* Keep Zeitraffer from covering badges: push panel up a bit via spacer only */`;
  document.head.appendChild(css);

  const renderer = new THREE.WebGLRenderer({ canvas, context: gl, alpha: true, antialias: true, preserveDrawingBuffer: true });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  const labels = new CSS2DRenderer(); labels.domElement.id = "ants3d-labels";
  const scene = new THREE.Scene();
  // Soft key + rim lighting (no bloom)
  scene.add(new THREE.AmbientLight(0xffffff, 1.2));
  scene.add(new THREE.HemisphereLight(0xffffff, 0x445566, 2.8));
  const key = new THREE.DirectionalLight(0xffffff, 3.5); key.position.set(250, 600, 900); scene.add(key);
  const rimR = new THREE.DirectionalLight(0xff3b3b, 0.7); rimR.position.set(-400, 200, -300); scene.add(rimR);
  const rimB = new THREE.DirectionalLight(0x3b8bff, 0.45); rimB.position.set(-600, 180, 200); scene.add(rimB);
  const rimY = new THREE.DirectionalLight(0xffd23b, 0.45); rimY.position.set(600, 180, 200); scene.add(rimY);

  // Orthographic camera: world y up, screen y down via cam.bottom negative
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
    // Honest: no skeletons / animations in these GLBs → no bone-based kneel.
    const hasSkel = !!o.getObjectByProperty("isSkinnedMesh", true);
    const hasAnim = (g.animations || []).length > 0;
    const box = new THREE.Box3().setFromObject(o);
    const sz = box.getSize(new THREE.Vector3()), ctr = box.getCenter(new THREE.Vector3());
    o.position.sub(ctr); o.position.y += sz.y / 2;
    const w = new THREE.Group(); w.add(o);
    w.userData = { h: sz.y, hasSkel, hasAnim, anims: g.animations || [] };
    return w;
  });

  // Subtle team tint: keep albedo textures, multiply slightly + soft emissive rim. No flat fill.
  const matCache = new Map();
  function tint(obj, team, pomp) {
    obj.traverse(m => {
      if (!m.isMesh || !m.material) return;
      const mats = Array.isArray(m.material) ? m.material : [m.material];
      const out = mats.map(mt => {
        const key = mt.uuid + ":" + team + ":" + pomp;
        if (matCache.has(key)) return matCache.get(key);
        const c = mt.clone();
        // Keep albedo maps; avoid pitch-black PBR (no env map in overlay)
        if ("metalness" in c) c.metalness = Math.min(c.metalness ?? 0, pomp === "royal" ? 0.25 : 0.08);
        if ("roughness" in c) c.roughness = Math.max(c.roughness ?? 0.5, 0.45);
        if (c.color) {
          if (pomp === "royal") c.color = c.color.clone().lerp(new THREE.Color(0xffd27a), 0.08);
          else c.color = c.color.clone().lerp(new THREE.Color(TEAM[team]), 0.16);
        }
        if (!c.emissive) c.emissive = new THREE.Color(0x000000);
        if (pomp === "royal") { c.emissive.setHex(0x3a2808); c.emissiveIntensity = 0.28; }
        else { c.emissive.setHex(TEAM[team]); c.emissiveIntensity = 0.1; }
        c.side = THREE.DoubleSide;
        c.needsUpdate = true;
        matCache.set(key, c); return c;
      });
      m.material = Array.isArray(m.material) ? out : out[0];
    });
  }

  const ants = []; // {obj, bob, turn, baseY}
  async function place(modelKey, team, pomp, x, y, hpx, s, queen, opts = {}) {
    const proto = await load(modelKey);
    const o = proto.clone(true);
    tint(o, team, pomp);
    o.traverse(m => {
      if (!m.isMesh) return;
      m.frustumCulled = false;
      m.matrixAutoUpdate = true;
      const mats = Array.isArray(m.material) ? m.material : [m.material];
      for (const mt of mats) {
        if (!mt) continue;
        mt.side = THREE.DoubleSide;
        if ("metalness" in mt) mt.metalness = Math.min(mt.metalness ?? 0, 0.15);
        if ("roughness" in mt) mt.roughness = Math.max(mt.roughness ?? 0.5, 0.55);
        if (mt.transparent && mt.opacity < 0.05) mt.opacity = 1;
        mt.depthWrite = true; mt.needsUpdate = true;
      }
    });
    const k = hpx / proto.userData.h;
    o.scale.setScalar(k);
    o.updateMatrixWorld(true);
    // World coords: x right, y up. Screen y is flipped by camera.
    o.position.set(x, -y, opts.z || 0);
    o.rotation.y = opts.ry ?? (-0.35 + Math.random() * 0.2);
    o.rotation.x = opts.rx || 0.08;
    o.rotation.z = opts.rz || 0;
    if (opts.kneel) {
      // Best-effort kneel WITHOUT bones/animations (GLBs have none):
      // sink into lower dais step, deep bow, slight lean — honest approx., not a skinned kneel.
      o.position.y += 22;
      o.position.z = (opts.z || 0) + 30;
      o.rotation.x = 0.85;
      o.rotation.z = 0.12;
      o.scale.setScalar(k * 0.88);
    }
    const l = badge(team, s, queen);
    l.position.set(0, queen ? -10 / k : -8 / k, 0);
    l.center.set(0.5, 0);
    o.add(l);
    scene.add(o);
    ants.push({ obj: o, bob: 0.6 + Math.random() * 0.4, turn: 0.25 + Math.random() * 0.2, baseY: o.position.y, phase: Math.random() * Math.PI * 2 });
    return { o, proto, hasSkel: proto.userData.hasSkel, hasAnim: proto.userData.hasAnim };
  }

  function layout() {
    const W = innerWidth, H = innerHeight;
    renderer.setSize(W, H); labels.setSize(W, H);
    cam.left = 0; cam.right = W; cam.top = 0; cam.bottom = -H; cam.updateProjectionMatrix();
  }
  layout();
  const W = innerWidth, H = innerHeight;

  // --- THRONE (center) ---
  const throne = buildThrone();
  // Scale throne so seat height ≈ 70 px on screen
  const throneScale = 0.55;
  throne.scale.setScalar(throneScale);
  const throneX = W * 0.5, throneY = 220;
  throne.position.set(throneX, -throneY, -40);
  scene.add(throne);
  const seatScreenY = throneY - (throne.userData.seatY * throneScale);

  // --- ROTE KÖNIGIN on throne (largest, pompous) ---
  const qH = 200;
  const redQ = await place("queen_red", "red", "royal",
    throneX, seatScreenY - qH * 0.02, qH,
    { name: "ROTE KÖNIGIN", title: "Absolute Herrscherin · All and One",
      skills: [`${red.length} Soldaten`, "Oversight-Gate", "Scope default-deny"] }, true,
    { z: 10, ry: 0.15 });

  // --- KNIENDER SCOUT before throne ---
  const scoutInfo = await place("scout", "red", "team",
    throneX - 55, throneY + 95, 78,
    { name: "Scout", title: "Kniend vor der Königin", skills: ["recon-master", "Späher"] }, false,
    { kneel: true, z: 50, ry: 0.9, rx: 0.55 });

  // --- MIDDLE: red soldiers only ---
  const redTop = throneY + 160;
  const cellW = Math.max(100, Math.min(118, (W * 0.42) / 6));
  const cellH = 118;
  const colsR = Math.min(6, Math.max(4, Math.floor((W * 0.42) / cellW)));
  const jobs = [];
  red.forEach((s, i) => {
    const r = Math.floor(i / colsR), n = Math.min(colsR, red.length - r * colsR), col = i % colsR;
    const x = throneX + (col - (n - 1) / 2) * cellW;
    const y = redTop + r * cellH;
    jobs.push(place(s.role, "red", "team", x, y, 70, s, false, { z: 5 }));
  });
  const redBottom = redTop + Math.ceil(red.length / colsR) * cellH;

  // --- LEFT: Blue Queen + blue people ---
  const sideTop = Math.max(redBottom + 40, H * 0.55);
  const bx = W * 0.22;
  jobs.push(place("queen_blue", "blue", "team", bx, sideTop, 120,
    { name: "Blaue Königin", title: "Verteidigung", skills: [`${blue.length} Soldaten`] }, true, { ry: -0.2 }));
  blue.forEach((s, i) => {
    const cols = 5, r = Math.floor(i / cols), n = Math.min(cols, blue.length - r * cols), col = i % cols;
    jobs.push(place(s.role, "blue", "team",
      bx + (col - (n - 1) / 2) * cellW, sideTop + 100 + r * cellH, 62, s, false));
  });

  // --- RIGHT: Yellow Queen + yellow people ---
  const yx = W * 0.78;
  jobs.push(place("queen_yellow", "yellow", "team", yx, sideTop, 120,
    { name: "Gelbe Königin", title: "Reverse Engineering · Schmiedin", skills: [`${YELLOW.length} Soldaten`] }, true, { ry: 0.25 }));
  YELLOW.forEach((s, i) => {
    const cols = 3, r = Math.floor(i / cols), n = Math.min(cols, YELLOW.length - r * cols), col = i % cols;
    jobs.push(place(s.role, "yellow", "team",
      yx + (col - (n - 1) / 2) * cellW, sideTop + 100 + r * cellH, 62, s, false));
  });

  await Promise.all(jobs);

  const blueRows = Math.ceil(blue.length / 5);
  const yellowRows = Math.ceil(YELLOW.length / 3);
  const fullH = sideTop + 100 + Math.max(blueRows, yellowRows) * cellH + 160;

  // Unlit materials: keep albedo maps readable under software GL (no env map)
    scene.traverse(o=>{
    if(!o.isMesh) return;
    const mats=Array.isArray(o.material)?o.material:[o.material];
    const out=mats.map(mt=>{
      if(!mt || mt.userData._basic) return mt;
      const b=new THREE.MeshBasicMaterial({
        color: mt.color ? mt.color.clone() : new THREE.Color(0xffffff),
        map: mt.map || null,
        transparent: !!mt.transparent,
        opacity: mt.opacity ?? 1,
        side: THREE.DoubleSide,
      });
      b.userData._basic=true;
      return b;
    });
    o.material=Array.isArray(o.material)?out:out[0];
  });
  document.body.appendChild(canvas);
  document.body.appendChild(labels.domElement);
  // Softly fading pheromone / neural-memory trails (own canvas; ants.js trails stay too).
  const trailCv=document.createElement("canvas");
  trailCv.id="a3d-trails";
  trailCv.style.cssText="position:fixed;inset:0;pointer-events:none;z-index:3";
  document.body.appendChild(trailCv);
  const tctx=trailCv.getContext("2d");
  const trailPts=[]; // {x,y,col,born,life}
  function seedTrails(){
    const cols=["56,224,255","210,160,90","176,77,255","255,59,59"];
    const hubs=[[W*0.5, throneY+40],[W*0.22, sideTop+40],[W*0.78, sideTop+40]];
    for(let h=0;h<hubs.length;h++){
      const [hx,hy]=hubs[h];
      for(let a=0;a<10;a++){
        const ang=-Math.PI/2+(a-4.5)*0.18, len=80+a*28;
        const steps=14;
        for(let s=0;s<steps;s++){
          const u=s/(steps-1);
          trailPts.push({
            x: hx+Math.cos(ang)*len*u + Math.sin(u*8)*6,
            y: hy+Math.sin(ang)*len*u*0.35 + u*90,
            col: cols[h%cols.length],
            born: performance.now()/1000 - (1-u)*8,
            life: 10+Math.random()*4,
            w: 1.2+u*2.2
          });
        }
      }
    }
  }
  seedTrails();
  function resizeTrails(){
    const dpr=Math.min(devicePixelRatio,2);
    trailCv.width=Math.floor(innerWidth*dpr); trailCv.height=Math.floor(innerHeight*dpr);
    trailCv.style.width=innerWidth+"px"; trailCv.style.height=innerHeight+"px";
    tctx.setTransform(dpr,0,0,dpr,0,0);
  }
  resizeTrails();

  // Spacer so lower clusters + badges clear the Zeitraffer panel (~140px)
  const spacer = document.createElement("div");
  spacer.id = "ants3d-spacer";
  spacer.style.cssText = `height:${Math.max(0, fullH - H + 160)}px;pointer-events:none`;
  document.body.appendChild(spacer);

  // Soft ground plane under whole scene (subtle)
  const ground = new THREE.Mesh(new THREE.PlaneGeometry(W * 1.4, fullH * 1.2),
    new THREE.MeshBasicMaterial({ color: 0x000000, transparent: true, opacity: 0.0 }));
  ground.position.set(W / 2, -fullH / 2, -80); scene.add(ground);

  const clock = new THREE.Clock();
  let skelNote = { hasSkel: scoutInfo.hasSkel, hasAnim: scoutInfo.hasAnim };
  (function tick() {
    const t = clock.getElapsedTime();
    cam.position.y = -scrollY;
    ants.forEach((a) => {
      if (a.ry0 === undefined) a.ry0 = a.obj.rotation.y;
      // Gentle idle: slow turn + breath bob (no hopping)
      a.obj.rotation.y = a.ry0 + Math.sin(t * a.turn + a.phase) * 0.18;
      a.obj.position.y = a.baseY + Math.sin(t * a.bob + a.phase) * 1.6;
    });
    // Throne crown slow shimmer via slight y bob of whole throne group is too much — skip
    // fading trails
    const now=performance.now()/1000;
    tctx.clearRect(0,0,innerWidth,innerHeight);
    tctx.lineCap="round"; tctx.lineJoin="round";
    // redraw as short segments with age fade
    for(let i=0;i<trailPts.length-1;i++){
      const a=trailPts[i], b=trailPts[i+1];
      if(a.col!==b.col) continue;
      const age=now-a.born; if(age<0||age>a.life) continue;
      const fade=1-age/a.life; const alpha=(0.15+0.55*fade)*fade;
      tctx.beginPath(); tctx.moveTo(a.x, a.y-scrollY); tctx.lineTo(b.x, b.y-scrollY);
      tctx.strokeStyle=`rgba(${a.col},${(alpha*0.45).toFixed(3)})`;
      tctx.lineWidth=a.w*2.2; tctx.stroke();
      tctx.strokeStyle=`rgba(${a.col},${alpha.toFixed(3)})`;
      tctx.lineWidth=a.w; tctx.stroke();
    }
    // respawn faded pts softly
    for(const pt of trailPts){
      if(now-pt.born>pt.life){ pt.born=now; pt.life=10+Math.random()*4; }
    }
    renderer.render(scene, cam); labels.render(scene, cam);
    requestAnimationFrame(tick);
  })();

  addEventListener("resize", () => location.reload(), { once: true });
  window.__ants3d = { 
    count: ants.length, red: red.length, blue: blue.length, yellow: YELLOW.length,
    scoutKneel: "best-effort (no skeleton/animations in GLB — lowered + bowed)",
    hasSkel: skelNote.hasSkel, hasAnim: skelNote.hasAnim,
  };
}
main().catch(e => console.warn("[ants3d] Fallback auf 2D-Sprites:", e));
