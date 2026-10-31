// 3D-Ameisenvolk-Overlay (GLB). Eigener transparenter Canvas über dem Partikel-Gehirn.
// Fasst engine.js / generators.js / ants.js NICHT an. Fällt bei Fehler still auf die 2D-Sprites zurück.
import * as THREE from "three";
import { GLTFLoader } from "three/addons/loaders/GLTFLoader.js";
import { MeshoptDecoder } from "three/addons/libs/meshopt_decoder.module.js";
import { CSS2DRenderer, CSS2DObject } from "three/addons/renderers/CSS2DRenderer.js";

const M = "/static/brain/models/";
const TEAM = { red: 0xff3b3b, blue: 0x3b8bff, yellow: 0xffd23b };
// Gelbes Volk: echte Registry aus yellow-queen/soldiers (__init__.REGISTRY + SoldierResult skill/title_de).
// antbb/agents/yellow existiert seit 8397411 nicht mehr.
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
const MODEL = { queen: "queen.glb", spear: "spartan_spear.glb", shield: "spartan_shield.glb", scout: "archer.glb", worker: "worker.glb" };

function badge(team, s, queen) {
  const d = document.createElement("div");
  d.className = "a3d-badge a3d-" + team + (queen ? " a3d-queen" : "");
  const esc = t => String(t).replace(/[&<>]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
  d.innerHTML = `<b>${esc(s.name)}</b><i>${esc(s.title || "")}</i>` +
    (s.skills || []).slice(0, 3).map(k => `<span>${esc(k)}</span>`).join("");
  return new CSS2DObject(d);
}

async function main() {
  const c = document.createElement("canvas");
  c.id = "ants3d-canvas";
  const gl = c.getContext("webgl2") || c.getContext("webgl");
  if (!gl) return;
  const css = document.createElement("style");
  css.textContent = `#ants3d-canvas,#ants3d-labels{position:fixed;inset:0;pointer-events:none;z-index:2}
  .a3d-badge{font:10px/1.25 system-ui,sans-serif;color:#fff;background:rgba(5,8,20,.78);border:1px solid;border-left-width:3px;
   border-radius:5px;padding:2px 5px;max-width:104px;text-align:left;white-space:nowrap;overflow:hidden}
  .a3d-badge b,.a3d-badge i,.a3d-badge span{display:block;overflow:hidden;text-overflow:ellipsis}
  .a3d-badge i{opacity:.75;font-size:9px}.a3d-badge span{font-size:9px;color:#cfe}
  .a3d-red{border-color:#ff3b3b}.a3d-blue{border-color:#3b8bff}.a3d-yellow{border-color:#ffd23b}
  .a3d-queen{font-size:12px;max-width:160px;border-width:2px;border-left-width:5px}
  .a3d-red.a3d-queen{background:rgba(60,5,5,.85);color:#ffd96b;font-size:14px}`;
  document.head.appendChild(css);

  const renderer = new THREE.WebGLRenderer({ canvas: c, context: gl, alpha: true, antialias: true });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  const labels = new CSS2DRenderer();
  labels.domElement.id = "ants3d-labels";
  const scene = new THREE.Scene();
  scene.add(new THREE.HemisphereLight(0xffffff, 0x223344, 2.2));
  const sun = new THREE.DirectionalLight(0xffffff, 2); sun.position.set(300, 600, 800); scene.add(sun);
  const cam = new THREE.OrthographicCamera(0, 1, 0, 1, -2000, 2000);
  cam.position.z = 1000;

  let data;
  try { data = await (await fetch("/api/soldiers")).json(); } catch (e) { return; }
  const all = data.soldiers || [];
  const mk = (s) => ({ name: s.name, title: s.specialty, role: roleOf(s),
    skills: [s.skill && s.skill.name, ...(s.playbooks || []).map(p => p.name)].filter(Boolean) });
  const red = all.filter(s => !s.name.startsWith("blue-")).map(mk);
  const blue = all.filter(s => s.name.startsWith("blue-")).map(mk);

  const loader = new GLTFLoader().setMeshoptDecoder(MeshoptDecoder);
  const cache = {};
  const load = (role) => cache[role] ||= loader.loadAsync(M + MODEL[role]).then(g => {
    const o = g.scene; const b = new THREE.Box3().setFromObject(o);
    const sz = b.getSize(new THREE.Vector3()), ctr = b.getCenter(new THREE.Vector3());
    o.position.sub(ctr); o.position.y += sz.y / 2;
    const w = new THREE.Group(); w.add(o); w.userData.h = sz.y; return w;
  });
  // Materialien pro Team/Pomp nur einmal klonen; Geometrie bleibt geteilt.
  const matCache = new Map();
  function tint(obj, team, pomp) {
    obj.traverse(m => {
      if (!m.isMesh) return;
      const key = m.material.uuid + team + pomp;
      if (!matCache.has(key)) {
        const mt = m.material.clone();
        if (pomp === "royal") { mt.emissive = new THREE.Color(0x331a00); mt.metalness = Math.max(mt.metalness || 0, .35); }
        else { mt.color = new THREE.Color(0xffffff).lerp(new THREE.Color(TEAM[team]), pomp === "humble" ? .8 : .75);
          mt.emissive = new THREE.Color(TEAM[team]); mt.emissiveIntensity = pomp === "humble" ? .22 : .32; mt.metalness = Math.min(mt.metalness || 0, .1); }
        matCache.set(key, mt);
      }
      m.material = matCache.get(key);
    });
  }
  const ants = [];
  async function place(role, team, pomp, x, y, hpx, s, queen) {
    const proto = await load(role);
    const o = proto.clone(true);
    tint(o, team, pomp);
    const k = hpx / proto.userData.h; o.scale.setScalar(k);
    o.position.set(x, -y, 0); o.rotation.y = -0.5 + Math.random() * .3; o.rotation.x = .12;
    const l = badge(team, s, queen); l.position.set(0, -6 / k, 0); l.center.set(.5, 0); o.add(l);
    scene.add(o); ants.push(o);
  }
  // Layout in Pixeln (orthografisch) → Schilder überlappen nicht.
  function grid(list, team, cx, top, cols, cellW, cellH, hpx) {
    return list.map((s, i) => {
      const r = Math.floor(i / cols), n = Math.min(cols, list.length - r * cols), col = i % cols;
      return place(s.role, team, "team", cx + (col - (n - 1) / 2) * cellW, top + r * cellH, hpx, s, false);
    });
  }
  function layout() {
    const W = innerWidth, H = innerHeight;
    renderer.setSize(W, H); labels.setSize(W, H);
    cam.left = 0; cam.right = W; cam.top = 0; cam.bottom = -H; cam.updateProjectionMatrix();
  }
  layout();
  const W = innerWidth, H = innerHeight;
  const cw = Math.max(108, Math.min(118, W / 14));
  const jobs = [];
  // ROTE KÖNIGIN: absolute Herrscherin, oben Mitte, am größten, volles Gold.
  jobs.push(place("queen", "red", "royal", W / 2, 330, 220, { name: "ROTE KÖNIGIN", title: "Absolute Herrscherin · All and One",
    skills: [`${red.length} Soldaten`, "Oversight-Gate", "Scope default-deny"] }, true));
  jobs.push(...grid(red, "red", W / 2, 450, Math.min(12, Math.floor(W * .9 / cw)), cw, 108, 52));
  const lowTop = 450 + Math.ceil(red.length / Math.min(12, Math.floor(W * .9 / cw))) * 108 + 120;
  // Blaue + Gelbe Königin: kleiner, schlicht, unter der Roten.
  const bx = W * .32, yx = W * .76;
  jobs.push(place("queen", "blue", "humble", bx, lowTop, 110, { name: "Blaue Königin", title: "Verteidigung", skills: [`${blue.length} Soldaten`] }, true));
  jobs.push(place("queen", "yellow", "humble", yx, lowTop, 110, { name: "Gelbe Königin", title: "Reverse Engineering", skills: [`${YELLOW.length} Soldaten`] }, true));
  jobs.push(...grid(blue, "blue", bx, lowTop + 95, 6, cw, 104, 46));
  jobs.push(...grid(YELLOW, "yellow", yx, lowTop + 95, 3, cw, 104, 46));
  await Promise.all(jobs);
  const fullH = lowTop + 95 + Math.ceil(blue.length / 6) * 104 + 40;
  document.body.appendChild(c); document.body.appendChild(labels.domElement);
  // 3D-Königinnen ersetzen die 2D-Königinnen-Sprites (nur ausgeblendet, ants.js unverändert).
  css.textContent += ".ant.queen{display:none!important}";
  // Seite scrollt (overflow-y:auto); Overlay verschiebt sich mit, damit alle Völker erreichbar sind.
  const spacer = document.createElement("div"); spacer.style.height = Math.max(0, fullH - H) + "px"; document.body.appendChild(spacer);
  const clock = new THREE.Clock();
  (function tick() {
    const t = clock.getElapsedTime();
    cam.position.y = -scrollY;
    ants.forEach((o, i) => { o.rotation.y = Math.sin(t * .4 + i) * .5; });
    renderer.render(scene, cam); labels.render(scene, cam);
    requestAnimationFrame(tick);
  })();
  addEventListener("resize", () => location.reload(), { once: true });
  window.__ants3d = { count: ants.length, red: red.length, blue: blue.length, yellow: YELLOW.length };
}
main().catch(e => console.warn("[ants3d] Fallback auf 2D-Sprites:", e));
