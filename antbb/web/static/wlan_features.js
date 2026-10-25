/* antbb 🐜 · WLAN-Features: Grundriss-Schätzung (Canvas) + Geräte-Erkennung (nmap)
 * Passiv/read-only, scope-gebunden, oversight-gated. Kein Deauth/Injection. */
(function () {
  "use strict";
  const qs = (id) => document.getElementById(id);

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => (
      { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
    ));
  }

  // ---- Grundriss aus WLAN schätzen (wird auf der Heatmap-Canvas gezeichnet) --
  function announceEstimate(d) {
    // wlan_heatmap.js hört zu und zeichnet Waende + APs in Kartenstil.
    try { window.dispatchEvent(new CustomEvent("antbb:floorplan-data", { detail: d })); } catch (e) {}
  }

  async function estimateFloorplan(useLastScan) {
    const note = qs("floorplan-estimate-note");
    if (note) note.textContent = "Schätze Grundriss aus WLAN …";
    try {
      const r = await fetch("/api/wlan/floorplan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(useLastScan ? { use_last_scan: true } : {})
      });
      const d = await r.json();
      if (!d.ok) {
        if (note) note.textContent = "⚠ " + (d.error || "Schätzung fehlgeschlagen.");
        return;
      }
      announceEstimate(d);
      if (note) note.textContent = (d.note || "") + " – Karte oben aktualisiert.";
    } catch (e) {
      if (note) note.textContent = "⚠ Schätzung fehlgeschlagen: " + e;
    }
  }

  async function restoreEstimate() {
    try {
      const r = await fetch("/api/wlan/floorplan");
      const d = await r.json();
      if (d.ok && d.aps_norm) announceEstimate(d);
    } catch (e) { /* ehrlich leer lassen */ }
  }

  // ---- Client-Enumeration (EIN KLICK, passiv) --------------------------------
  function renderClients(clients) {
    const tbl = qs("clients-table");
    if (!tbl) return;
    if (!clients || !clients.length) {
      tbl.innerHTML = "<tbody><tr><td>Keine Clients gefunden (ehrlich leer).</td></tr></tbody>";
      return;
    }
    const rows = clients.map((c) => "<tr>" +
      "<td>" + esc(c.mac) + "</td>" +
      "<td>" + esc(c.power != null ? c.power + " dBm" : "–") + "</td>" +
      "<td>" + esc(c.packets) + "</td>" +
      "<td>" + esc(c.assoc_bssid) + "</td>" +
      "<td>" + esc((c.probes || []).join(", ")) + "</td></tr>");
    tbl.innerHTML = "<thead><tr><th>MAC</th><th>Signal</th><th>Pakete</th>" +
      "<th>Assoziierter AP</th><th>Probes</th></tr></thead><tbody>" +
      rows.join("") + "</tbody>";
  }

  async function queryClients() {
    const st = qs("clients-status");
    const btn = qs("btn-clients");
    const oversight = qs("clients-oversight");
    if (btn) btn.disabled = true;
    if (!oversight || !oversight.checked) {
      if (st) st.textContent = "⚠ Oversight-Häkchen setzen – Monitor-Mode ist eine aktive Aktion.";
      if (btn) btn.disabled = false;
      return;
    }
    if (st) st.textContent = "Monitor-Mode an → scanne ~20 s passiv → stelle zurück …";
    try {
      const r = await fetch("/api/wlan/clients", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ iface: "wlan1", seconds: 20, oversight_ok: true })
      });
      const d = await r.json();
      if (!d.ok) {
        if (st) st.textContent = "⚠ " + (d.error || "Client-Scan fehlgeschlagen.");
        return;
      }
      if (st) st.textContent = d.count + " Client(s) gefunden – " + (d.note || "");
      renderClients(d.clients);
    } catch (e) {
      if (st) st.textContent = "Fehler: " + e;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  // ---- Geraete-Erkennung (nmap, read-only) -----------------------------------
  const KIND_LABELS = {
    router: "Router/FritzBox", repeater: "Repeater/Mesh", iot: "IoT-Gerät",
    unknown: "unbekannt",
  };

  function renderDevices(devices) {
    const tbl = qs("devices-table");
    if (!tbl) return;
    if (!devices || !devices.length) {
      tbl.innerHTML = "<tbody><tr><td>Keine Geräte gefunden (ehrlich leer).</td></tr></tbody>";
      return;
    }
    const order = { router: 0, repeater: 1, iot: 2, unknown: 3 };
    const sorted = devices.slice().sort((a, b) =>
      (order[a.classification] != null ? order[a.classification] : 9) -
      (order[b.classification] != null ? order[b.classification] : 9));
    const rows = sorted.map((d) => {
      const ports = (d.ports || []).map((p) =>
        p.port + (p.service ? "/" + p.service : "")).join(", ");
      const hints = (d.firmware_hints || []);
      const fwCell = hints.length
        ? '<span class="dev-fw-old">' + esc(hints.join("; ")) + "</span>"
        : '<span class="dev-fw-ok">kein Hinweis</span>';
      return "<tr>" +
        '<td><span class="dev-kind dev-kind-' + esc(d.classification) + '">' +
          esc(KIND_LABELS[d.classification] || d.classification) + "</span></td>" +
        "<td>" + esc(d.ip) + "</td>" +
        "<td>" + esc(d.mac || "–") + "</td>" +
        "<td>" + esc(d.vendor || "–") + "</td>" +
        "<td>" + esc(d.hostname || "–") + "</td>" +
        "<td>" + esc(ports || "–") + "</td>" +
        "<td>" + fwCell + "</td></tr>";
    });
    tbl.innerHTML = "<thead><tr><th>Gerät</th><th>IP</th><th>MAC</th><th>Hersteller</th>" +
      "<th>Hostname</th><th>Offene Dienste</th><th>Firmware</th></tr></thead><tbody>" +
      rows.join("") + "</tbody>";
  }

  async function queryDevices() {
    const st = qs("devices-status");
    const btn = qs("btn-devices");
    const oversight = qs("devices-oversight");
    if (btn) btn.disabled = true;
    if (!oversight || !oversight.checked) {
      if (st) st.textContent = "⚠ Oversight-Häkchen setzen – aktiver Scan im eigenen Netz.";
      if (btn) btn.disabled = false;
      return;
    }
    if (st) st.textContent = "Scanne lokales Subnetz (nmap, read-only) …";
    try {
      const r = await fetch("/api/wlan/devices", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ oversight_ok: true })
      });
      const d = await r.json();
      if (!d.ok) {
        if (st) st.textContent = "⚠ " + (d.error || "Geräte-Scan fehlgeschlagen.");
        return;
      }
      const old = (d.devices || []).filter((x) => (x.firmware_hints || []).length).length;
      if (st) st.textContent = d.count + " Gerät(e) in " + (d.subnet || "?") +
        " – " + old + " mit Firmware-Hinweis. " + (d.note || "");
      renderDevices(d.devices);
    } catch (e) {
      if (st) st.textContent = "Fehler: " + e;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function restoreDevices() {
    try {
      const r = await fetch("/api/wlan/devices");
      const d = await r.json();
      if (d.ok && d.devices) {
        renderDevices(d.devices);
        const st = qs("devices-status");
        if (st) st.textContent = d.count + " Gerät(e) – letzter Stand vom Server.";
      }
    } catch (e) { /* ehrlich leer lassen */ }
  }

  function wire() {
    const estBtn = qs("btn-estimate-floorplan");
    if (estBtn) estBtn.addEventListener("click", function () { estimateFloorplan(true); });
    const clientsBtn = qs("btn-clients");
    if (clientsBtn) clientsBtn.addEventListener("click", queryClients);
    const devicesBtn = qs("btn-devices");
    if (devicesBtn) devicesBtn.addEventListener("click", queryDevices);
    // Nach einem Scan („Hier messen“ / Voll-Scan) Schätzung neu zeichnen.
    window.addEventListener("antbb:wlan-scan-done", function () { estimateFloorplan(true); });
    restoreEstimate();
    restoreDevices();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
