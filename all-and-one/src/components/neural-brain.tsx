"use client";

import Link from "next/link";
import { useEffect, useMemo, useRef, useState } from "react";

import { AntGlyph } from "@/components/ant-glyph";
import { Badge } from "@/components/ui/badge";
import { Button, buttonVariants } from "@/components/ui/button";
import { api } from "@/lib/api";
import { FOOTER, type QueenId } from "@/lib/brand";
import type { BrainPayload, Soldier } from "@/lib/types";
import { cn } from "cn";

type Kind = "queen" | "soldier" | "swarm";

type AntModel = {
  id: string;
  queen: QueenId;
  kind: Kind;
  label: string | null;
  aria: string;
  soldier: Soldier | null;
};

type Sim = {
  ox: number;
  oy: number;
  heading: number;
  angVel: number;
  speed: number;
  phase: number;
  radius: number;
};

type SceneBag = {
  render: (time: number, focusValue: number, width: number, height: number) => void;
  anchors: () => Record<QueenId, { x: number; y: number }>;
  resize: (width: number, height: number) => void;
  dispose: () => void;
};

const QUEENS: QueenId[] = ["red", "blue", "yellow"];

const QUEEN_NAME: Record<QueenId, string> = {
  red: "Rote Königin",
  blue: "Blaue Königin",
  yellow: "Gelbe Königin",
};

const HUE: Record<QueenId, number> = { red: 0, blue: 1, yellow: 2 };

function buildAnts(payload: BrainPayload | null): AntModel[] {
  const ants: AntModel[] = [];
  for (const queen of QUEENS) {
    const summary = payload?.queens.find((item) => item.queen_id === queen);
    ants.push({
      id: `queen-${queen}`,
      queen,
      kind: "queen",
      label: summary?.name ?? QUEEN_NAME[queen],
      aria: summary?.name ?? QUEEN_NAME[queen],
      soldier: null,
    });
    const troops = summary?.soldiers ?? [];
    for (const troop of troops) {
      ants.push({
        id: `${queen}-${troop.soldier_id}`,
        queen,
        kind: "soldier",
        label: troop.name,
        aria: `${troop.name}, ${troop.role}`,
        soldier: troop,
      });
    }
    for (let index = 0; index < 5; index += 1) {
      ants.push({
        id: `${queen}-schwarm-${index}`,
        queen,
        kind: "swarm",
        label: null,
        aria: "Schwarm",
        soldier: null,
      });
    }
  }
  return ants;
}

function fallbackHomes(width: number, height: number): Record<QueenId, { x: number; y: number }> {
  return {
    red: { x: width * 0.24, y: height * 0.48 },
    blue: { x: width * 0.5, y: height * 0.62 },
    yellow: { x: width * 0.76, y: height * 0.46 },
  };
}

export function NeuralBrain({ focus }: { focus: QueenId | null }) {
  const [payload, setPayload] = useState<BrainPayload | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const hostRef = useRef<HTMLDivElement | null>(null);
  const layerRef = useRef<HTMLDivElement | null>(null);
  const sceneRef = useRef<SceneBag | null>(null);
  const antsRef = useRef<AntModel[]>([]);
  const simsRef = useRef<Map<string, Sim>>(new Map());
  const nodesRef = useRef<Map<string, HTMLButtonElement>>(new Map());
  const focusRef = useRef<QueenId | null>(focus);
  const ants = useMemo(() => buildAnts(payload), [payload]);
  antsRef.current = ants;
  focusRef.current = focus;

  useEffect(() => {
    let alive = true;
    const pull = () => {
      api<BrainPayload>("/api/brain")
        .then((body) => {
          if (!alive) return;
          setPayload(body);
          setError(null);
        })
        .catch((reason: unknown) => {
          if (!alive) return;
          setError(reason instanceof Error ? reason.message : "Die API antwortet nicht.");
        });
    };
    pull();
    const timer = window.setInterval(pull, 4000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setSelectedId(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  useEffect(() => {
    const host = hostRef.current;
    if (!host) return;
    const canvas = document.createElement("canvas");
    canvas.className = "brain-canvas";
    host.prepend(canvas);
    let dead = false;
    let frame = 0;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const clock = { last: performance.now(), time: 0 };

    const ensure = (ant: AntModel): Sim => {
      const existing = simsRef.current.get(ant.id);
      if (existing) return existing;
      const radius = ant.kind === "queen" ? 26 : ant.kind === "soldier" ? 112 : 146;
      const speed = ant.kind === "queen" ? 14 : ant.kind === "soldier" ? 36 + Math.random() * 16 : 48 + Math.random() * 20;
      const angle = Math.random() * Math.PI * 2;
      const dist = Math.random() * radius * 0.5;
      const sim: Sim = {
        ox: Math.cos(angle) * dist,
        oy: Math.sin(angle) * dist,
        heading: Math.random() * Math.PI * 2,
        angVel: 0,
        speed,
        phase: Math.random() * Math.PI * 2,
        radius,
      };
      simsRef.current.set(ant.id, sim);
      return sim;
    };

    const stepAnt = (sim: Sim, dt: number, time: number) => {
      const pace = reduced ? 0.2 : 1;
      const noise = Math.sin(time * 0.35 + sim.phase) * 0.62 + Math.sin(time * 0.17 + sim.phase * 1.8) * 0.38;
      sim.angVel = sim.angVel * 0.9 + noise * 0.85 * pace;
      sim.heading += sim.angVel * dt;
      const dist = Math.hypot(sim.ox, sim.oy);
      if (dist > sim.radius * 0.72) {
        const desired = Math.atan2(-sim.oy, -sim.ox);
        let diff = desired - sim.heading;
        while (diff > Math.PI) diff -= Math.PI * 2;
        while (diff < -Math.PI) diff += Math.PI * 2;
        sim.heading += diff * Math.min(0.08, dt * 1.6) * (dist / sim.radius);
      }
      const step = sim.speed * pace * dt;
      sim.ox += Math.cos(sim.heading) * step;
      sim.oy += Math.sin(sim.heading) * step;
      const next = Math.hypot(sim.ox, sim.oy);
      if (next > sim.radius) {
        const scale = sim.radius / next;
        sim.ox *= scale;
        sim.oy *= scale;
      }
    };

    const tick = (now: number) => {
      if (dead) return;
      const dt = Math.min(0.033, (now - clock.last) / 1000);
      clock.last = now;
      clock.time += dt;
      const layer = layerRef.current;
      const width = layer?.clientWidth ?? host.clientWidth;
      const height = layer?.clientHeight ?? host.clientHeight;
      const focusValue = focusRef.current === null ? -1 : HUE[focusRef.current];
      sceneRef.current?.render(clock.time, focusValue, width, height);
      const homes = sceneRef.current?.anchors() ?? fallbackHomes(width, height);
      for (const ant of antsRef.current) {
        const sim = ensure(ant);
        stepAnt(sim, dt, clock.time);
        const node = nodesRef.current.get(ant.id);
        if (!node) continue;
        const x = homes[ant.queen].x + sim.ox;
        const y = homes[ant.queen].y + sim.oy;
        node.style.transform = `translate3d(${x}px, ${y}px, 0) translate(-50%, -50%)`;
        const glyph = node.querySelector<HTMLElement>(".ant-glyph");
        if (glyph) {
          glyph.style.transform = `rotate(${sim.heading}rad)`;
          glyph.dataset.walking = reduced ? "0" : "1";
        }
      }
      frame = window.requestAnimationFrame(tick);
    };
    frame = window.requestAnimationFrame(tick);

    void (async () => {
      const THREE = await import("three");
      if (dead) return;
      sceneRef.current = createScene(THREE, canvas, host.clientWidth, host.clientHeight);
    })().catch(() => {
      if (!dead) setError("Das Partikelfeld konnte nicht starten.");
    });

    const onResize = () => {
      sceneRef.current?.resize(host.clientWidth, host.clientHeight);
    };
    window.addEventListener("resize", onResize);
    return () => {
      dead = true;
      window.cancelAnimationFrame(frame);
      window.removeEventListener("resize", onResize);
      sceneRef.current?.dispose();
      sceneRef.current = null;
      canvas.remove();
    };
  }, []);

  const selected = ants.find((ant) => ant.id === selectedId) ?? null;
  const summary = selected ? payload?.queens.find((queen) => queen.queen_id === selected.queen) : null;
  const strip =
    payload?.strip ?? "Rot tut Grenzschau · Blau tut Härtelage · Gelb tut Wegerklärung";

  return (
    <div className="brain-root" ref={hostRef} data-focus={focus ?? "all"}>
      <div className="brain-vignette" aria-hidden="true" />
      <div className="brain-ants" ref={layerRef}>
        {ants.map((ant) => (
          <button
            key={ant.id}
            type="button"
            className="ant-token"
            data-kind={ant.kind}
            data-queen={ant.queen}
            data-dim={focus && ant.queen !== focus ? "1" : "0"}
            dir="ltr"
            aria-label={ant.aria}
            ref={(node) => {
              if (node) nodesRef.current.set(ant.id, node);
              else nodesRef.current.delete(ant.id);
            }}
            onClick={() => {
              if (ant.kind !== "swarm") setSelectedId(ant.id);
            }}
          >
            <span className={`ant-glyph ant-glyph-${ant.kind}`}>
              <AntGlyph queen={ant.queen} queenMark={ant.kind === "queen"} />
            </span>
            {ant.label ? (
              <span className="ant-label" dir="ltr">
                {ant.label}
              </span>
            ) : null}
          </button>
        ))}
      </div>
      <div className="brain-chrome">
        <header className="brain-top">
          <div>
            <p className="text-[0.68rem] tracking-[0.22em] text-[var(--gold)] uppercase">Neural Brain</p>
            <p className="brain-strip" role="status">
              {strip}
            </p>
            {error ? <p className="mt-2 text-xs text-[var(--gold)]">Die API antwortet nicht. Der Schwarm bleibt sichtbar.</p> : null}
          </div>
          <div className="flex flex-wrap gap-2">
            <FilterLink current={focus} queen={null} label="Alle" />
            <FilterLink current={focus} queen="red" label="Rot" />
            <FilterLink current={focus} queen="blue" label="Blau" />
            <FilterLink current={focus} queen="yellow" label="Gelb" />
          </div>
        </header>
        <footer className="brain-foot">All and One · Red · Blue · Yellow</footer>
      </div>
      {selected && selected.kind !== "swarm" ? (
        <aside className="brain-detail" data-queen={selected.queen}>
          <div className="flex items-start justify-between gap-3">
            <div>
              <p className="text-[0.68rem] tracking-[0.16em] uppercase opacity-60">
                {selected.kind === "queen" ? "Königin" : "Soldaten"}
              </p>
              <h2 className="font-heading mt-1 text-3xl">{selected.label}</h2>
            </div>
            <Button type="button" variant="ghost" size="sm" onClick={() => setSelectedId(null)}>
              Schließen
            </Button>
          </div>
          {selected.soldier ? (
            <div className="mt-4 space-y-3 text-sm leading-relaxed">
              <p>
                {selected.soldier.role} · Modus {selected.soldier.mode}
              </p>
              <p>{selected.soldier.live_satz}</p>
              <p>
                <span className="opacity-60">Playbooks · </span>
                {selected.soldier.playbook_ids.join(", ")}
              </p>
              <p>Oversight ist für Läufe nötig.</p>
              <Badge variant="outline">{selected.soldier.stub_note}</Badge>
            </div>
          ) : (
            <div className="mt-4 space-y-3 text-sm leading-relaxed">
              <p>{summary?.live_satz ?? "Live-Status wird gelesen."}</p>
              <p>{summary?.strip_teil}</p>
              <p>
                Oversight {summary?.oversight ? "ist gesetzt" : "fehlt"}. Scope{" "}
                {summary ? `${summary.scope.length} Ziele` : "wird gelesen"}.
              </p>
            </div>
          )}
          <Link
            href={selected.queen === "yellow" ? "/yellow" : `/${selected.queen}`}
            className={cn(buttonVariants({ size: "lg" }), "mt-5 inline-flex h-10 px-4")}
          >
            Zur {selected.queen === "red" ? "Roten" : selected.queen === "blue" ? "Blauen" : "Gelben"} Königin
          </Link>
        </aside>
      ) : null}
      <p className="sr-only">{FOOTER}</p>
    </div>
  );
}

function FilterLink({
  current,
  queen,
  label,
}: {
  current: QueenId | null;
  queen: QueenId | null;
  label: string;
}) {
  const active = current === queen;
  const href = queen ? `/brain?queen=${queen}` : "/brain?queen=all";
  return (
    <Link href={href} className={`brain-chip ${active ? "is-on" : ""}`} data-queen={queen ?? "all"}>
      {label}
    </Link>
  );
}

type ThreeModule = typeof import("three");

function createScene(
  THREE: ThreeModule,
  canvas: HTMLCanvasElement,
  width: number,
  height: number,
): SceneBag {
  const renderer = new THREE.WebGLRenderer({ canvas, antialias: false, alpha: false, powerPreference: "high-performance" });
  const dpr = Math.min(window.devicePixelRatio || 1, 1.6);
  renderer.setPixelRatio(dpr);
  renderer.setSize(width, height, false);
  renderer.setClearColor(0x07060c, 1);
  renderer.outputColorSpace = THREE.SRGBColorSpace;
  renderer.toneMapping = THREE.NoToneMapping;

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(42, Math.max(width, 1) / Math.max(height, 1), 0.1, 200);
  camera.position.set(0, 0, 40);

  const cores = {
    red: new THREE.Vector3(-18, 2.2, 0),
    blue: new THREE.Vector3(0, -4.2, 0),
    yellow: new THREE.Vector3(18, 2.8, 0),
  } as const;

  const count = Math.max(9000, Math.min(36000, Math.floor((width * height) / 42)));
  const phases = new Float32Array(count);
  const hues = new Float32Array(count);
  const sizes = new Float32Array(count);
  const positions = new Float32Array(count * 3);
  for (let index = 0; index < count; index += 1) {
    phases[index] = Math.random();
    hues[index] = index % 3;
    sizes[index] = 1.4 + Math.random() * 3.4;
  }
  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute("position", new THREE.BufferAttribute(positions, 3));
  geometry.setAttribute("aPhase", new THREE.BufferAttribute(phases, 1));
  geometry.setAttribute("aHue", new THREE.BufferAttribute(hues, 1));
  geometry.setAttribute("aSize", new THREE.BufferAttribute(sizes, 1));

  const trail = lorenzTexture(THREE);
  const uniforms = {
    uTime: { value: 0 },
    uTrail: { value: trail },
    uFocus: { value: -1 },
  };
  const material = new THREE.ShaderMaterial({
    uniforms,
    transparent: true,
    depthWrite: false,
    blending: THREE.NormalBlending,
    vertexShader: `
      attribute float aPhase;
      attribute float aHue;
      attribute float aSize;
      uniform float uTime;
      uniform sampler2D uTrail;
      uniform float uFocus;
      varying vec3 vColor;
      varying float vAlpha;
      void main() {
        float idx = fract(aPhase + uTime * 0.011);
        vec3 raw = texture2D(uTrail, vec2(idx, 0.5)).rgb;
        vec3 p = (raw * 2.0 - 1.0) * vec3(6.4, 7.2, 4.6);
        float j = fract(sin(aPhase * 91.7) * 43758.5453);
        p += vec3(sin(aPhase * 12.0 + uTime * 0.15), cos(aPhase * 9.0), sin(aPhase * 4.0)) * (0.35 + j * 0.9);
        vec3 shift = vec3(0.0, -4.2, 0.0);
        vec3 col = vec3(0.42, 0.72, 0.82);
        float hue = 1.0;
        if (aHue < 0.5) {
          shift = vec3(-18.0, 2.2, 0.0);
          col = vec3(0.78, 0.16, 0.26);
          hue = 0.0;
        } else if (aHue > 1.5) {
          shift = vec3(18.0, 2.8, 0.0);
          col = vec3(0.9, 0.64, 0.24);
          hue = 2.0;
        }
        float dim = 1.0;
        if (uFocus > -0.5 && abs(hue - uFocus) > 0.25) dim = 0.07;
        vec4 mv = modelViewMatrix * vec4(p + shift, 1.0);
        gl_Position = projectionMatrix * mv;
        gl_PointSize = aSize * (dim < 0.5 ? 0.45 : 1.0) * (260.0 / max(8.0, -mv.z));
        vColor = col;
        vAlpha = dim;
      }
    `,
    fragmentShader: `
      varying vec3 vColor;
      varying float vAlpha;
      void main() {
        vec2 d = gl_PointCoord - vec2(0.5);
        float r = length(d);
        if (r > 0.5) discard;
        float alpha = 1.0 - smoothstep(0.38, 0.5, r);
        gl_FragColor = vec4(vColor, alpha * vAlpha);
      }
    `,
  });
  scene.add(new THREE.Points(geometry, material));

  const projected = new THREE.Vector3();
  const anchorCache: Record<QueenId, { x: number; y: number }> = {
    red: { x: width * 0.24, y: height * 0.48 },
    blue: { x: width * 0.5, y: height * 0.62 },
    yellow: { x: width * 0.76, y: height * 0.46 },
  };

  const resize = (nextWidth: number, nextHeight: number) => {
    if (nextWidth < 2 || nextHeight < 2) return;
    renderer.setSize(nextWidth, nextHeight, false);
    camera.aspect = nextWidth / nextHeight;
    camera.updateProjectionMatrix();
  };
  resize(width, height);

  return {
    resize,
    anchors: () => anchorCache,
    render: (time, focusValue, viewWidth, viewHeight) => {
      uniforms.uTime.value = time;
      uniforms.uFocus.value = focusValue;
      camera.position.x = Math.sin(time * 0.07) * 1.1;
      camera.position.y = Math.sin(time * 0.05) * 0.45;
      camera.position.z = 40;
      camera.lookAt(0, 0, 0);
      renderer.render(scene, camera);
      (Object.keys(cores) as QueenId[]).forEach((queen) => {
        projected.copy(cores[queen]).project(camera);
        anchorCache[queen] = {
          x: (projected.x * 0.5 + 0.5) * viewWidth,
          y: (-projected.y * 0.5 + 0.5) * viewHeight,
        };
      });
    },
    dispose: () => {
      geometry.dispose();
      material.dispose();
      trail.dispose();
      renderer.dispose();
    },
  };
}

function lorenzTexture(THREE: ThreeModule) {
  const size = 2048;
  const data = new Uint8Array(size * 4);
  let x = 0.1;
  let y = 0;
  let z = 0;
  const sigma = 10;
  const rho = 28;
  const beta = 8 / 3;
  const dt = 0.0045;
  for (let step = 0; step < 900; step += 1) {
    const dx = sigma * (y - x);
    const dy = x * (rho - z) - y;
    const dz = x * y - beta * z;
    x += dx * dt;
    y += dy * dt;
    z += dz * dt;
  }
  for (let index = 0; index < size; index += 1) {
    const dx = sigma * (y - x);
    const dy = x * (rho - z) - y;
    const dz = x * y - beta * z;
    x += dx * dt;
    y += dy * dt;
    z += dz * dt;
    data[index * 4] = encode(x / 22);
    data[index * 4 + 1] = encode(y / 30);
    data[index * 4 + 2] = encode((z - 25) / 28);
    data[index * 4 + 3] = 255;
  }
  const texture = new THREE.DataTexture(data, size, 1, THREE.RGBAFormat);
  texture.needsUpdate = true;
  texture.magFilter = THREE.LinearFilter;
  texture.minFilter = THREE.LinearFilter;
  texture.wrapS = THREE.RepeatWrapping;
  texture.colorSpace = THREE.NoColorSpace;
  return texture;
}

function encode(value: number) {
  const clamped = Math.max(-1, Math.min(1, value));
  return Math.round((clamped * 0.5 + 0.5) * 255);
}

