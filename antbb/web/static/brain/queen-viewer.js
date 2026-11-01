// Shared lazy 3D model viewer for queen/scout pages. Falls back silently if WebGL fails.
import * as THREE from "three";
import { GLTFLoader } from "three/addons/loaders/GLTFLoader.js";
import { MeshoptDecoder } from "three/addons/libs/meshopt_decoder.module.js";
import { OrbitControls } from "three/addons/controls/OrbitControls.js";

const DEFAULTS = {
  red:    { url: "/static/brain/models/queen.glb",        color: 0xff3b3b, bg: "#140808", h: 280 },
  blue:   { url: "/static/brain/models/queen_blue.glb",   color: 0x3b8bff, bg: "#061018", h: 280 },
  yellow: { url: "/static/brain/models/queen_yellow.glb", color: 0xffd23b, bg: "#141008", h: 280 },
  scout:  { url: "/static/brain/models/archer.glb",       color: 0xff6a3b, bg: "#0a0e14", h: 240 },
};

export async function mountQueenViewer(el, kind = "red", opts = {}) {
  if (!el || el.dataset.qvMounted) return;
  el.dataset.qvMounted = "1";
  const cfg = { ...(DEFAULTS[kind] || DEFAULTS.red), ...opts };
  el.classList.add("qv-host");
  el.style.cssText += `position:relative;min-height:${cfg.h}px;border-radius:14px;overflow:hidden;background:${cfg.bg}`;
  const fallback = document.createElement("div");
  fallback.className = "qv-fallback";
  fallback.textContent = "Lade 3D-Modell…";
  fallback.style.cssText = "position:absolute;inset:0;display:grid;place-items:center;color:#9ab;font:13px system-ui";
  el.appendChild(fallback);

  const canvas = document.createElement("canvas");
  canvas.style.cssText = "position:absolute;inset:0;width:100%;height:100%";
  const gl = canvas.getContext("webgl2", { alpha: true, antialias: true })
          || canvas.getContext("webgl",  { alpha: true, antialias: true });
  if (!gl) { fallback.textContent = "WebGL nicht verfügbar"; return; }
  el.appendChild(canvas);

  const renderer = new THREE.WebGLRenderer({ canvas, context: gl, alpha: true, antialias: true });
  renderer.setPixelRatio(Math.min(devicePixelRatio, 2));
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  const scene = new THREE.Scene();
  scene.add(new THREE.HemisphereLight(0xffffff, 0x223344, 1.6));
  const key = new THREE.DirectionalLight(0xffffff, 2.4); key.position.set(2.2, 4.5, 3.5); scene.add(key);
  const rim = new THREE.DirectionalLight(cfg.color, 1.4); rim.position.set(-3, 2, -2); scene.add(rim);
  const cam = new THREE.PerspectiveCamera(32, 1, 0.05, 80);
  const controls = new OrbitControls(cam, canvas);
  controls.enableDamping = true; controls.autoRotate = true; controls.autoRotateSpeed = 0.7;
  controls.enablePan = false; controls.minDistance = 1.2; controls.maxDistance = 8;

  try {
    const gltf = await new GLTFLoader().setMeshoptDecoder(MeshoptDecoder).loadAsync(cfg.url);
    const root = gltf.scene;
    const box = new THREE.Box3().setFromObject(root);
    const size = box.getSize(new THREE.Vector3());
    const ctr = box.getCenter(new THREE.Vector3());
    root.position.sub(ctr);
    const s = 2.4 / Math.max(size.x, size.y, size.z);
    root.scale.setScalar(s);
    scene.add(root);
    const ground = new THREE.Mesh(
      new THREE.CircleGeometry(1.6, 48),
      new THREE.MeshBasicMaterial({ color: cfg.color, transparent: true, opacity: 0.12 })
    );
    ground.rotation.x = -Math.PI / 2; ground.position.y = -size.y * s / 2; scene.add(ground);
    cam.position.set(0.6, size.y * s * 0.35, 3.6);
    controls.target.set(0, size.y * s * 0.1, 0);
    fallback.remove();
  } catch (e) {
    fallback.textContent = "3D-Modell nicht ladbar";
    console.warn("[queen-viewer]", e);
    return;
  }

  const resize = () => {
    const w = el.clientWidth || 320, h = el.clientHeight || cfg.h;
    renderer.setSize(w, h, false); cam.aspect = w / h; cam.updateProjectionMatrix();
  };
  resize();
  const ro = new ResizeObserver(resize); ro.observe(el);
  (function tick() {
    if (!el.isConnected) { ro.disconnect(); return; }
    controls.update(); renderer.render(scene, cam); requestAnimationFrame(tick);
  })();
}

export function mountWhenVisible(el, kind, opts) {
  if (!el) return;
  const io = new IntersectionObserver((ents) => {
    if (ents.some(e => e.isIntersecting)) { io.disconnect(); mountQueenViewer(el, kind, opts); }
  }, { rootMargin: "80px" });
  io.observe(el);
}
