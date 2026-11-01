# Origin of this vendored city

Source: Judith's own Kimi-built 3D ant world at https://ameisen-3d-welt.kimi.page/
("Ameisenkönigin — Neurale 3D-Welt"), captured and vendored locally for the antbb Neural Brain overlay.

## Assets
- Procedural city builder + UI: `assets/index-CR9Vm8Nj.js` (bundles three.js + city)
- Queen / scout / miniature GLBs under `models/` (optimized with gltf-transform meshopt+webp for web)
- Throne kit: `assets/throne/` — "王座 — Gilded Royal Throne" (asset-web-module)
- Market stall kit: `assets/market/` — "Rustic medieval market stall" (asset-web-module)
- Draco decoder under `draco/` (Google Draco, Apache-2.0 — used by three.js GLTFLoader)

## Third-party
- three.js (MIT) — bundled inside the Kimi app JS
- Draco wasm decoder (Apache-2.0)
- No runtime dependency on kimi.page or CDN after vendoring
- `https://www.kimi.ai/sdk-seed.js` removed from local index.html

Judith owns this project; reuse in antbb is by her request.
