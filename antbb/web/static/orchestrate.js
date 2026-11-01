/* Yellow RE-Orchestrator: lädt State, zeigt echte Funde + Next-Step-Buttons. */
(function () {
  "use strict";
  const panel = document.getElementById("orch-panel");
  if (!panel) return;
  const caseId = panel.getAttribute("data-case");
  const base = "/yellow/case/" + encodeURIComponent(caseId) + "/orchestrate/state";

  function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => (
      { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
    ));
  }

  function renderState(data) {
    const st = data.state || {};
    const steps = st.steps || {};
    const f = st.findings || {};
    let html = "";
    // Funde
    html += "<div class='orch-funde'><b>Befund:</b> ";
    if (f.sha256) {
      html += "SHA-256 <code>" + esc(f.sha256.slice(0, 16)) + "…</code> · " +
              esc(f.size) + " Bytes · EP <code>" + esc(f.entrypoint_rva || "?") + "</code>";
      if (f.packer && f.packer.length) html += " · Packer: <b class='warn'>" + esc(f.packer.join(", ")) + "</b>";
      if (f.unpacked_file) html += " · entpackt: <b>" + esc(f.unpacked_file) + "</b>";
    } else {
      html += "noch keine Triage – Schritt 1 starten.";
    }
    html += "</div>";
    // Ausgeführte Schritte
    html += "<ul class='orch-steps'>";
    Object.keys(steps).forEach((k) => {
      const s = steps[k];
      html += "<li>" + (s.ok ? "✅" : "⚠️") + " <b>" + esc(k) + "</b> <span class='mut'>" +
              esc(s.at || "") + "</span>" +
              (s.result && s.result.error ? " – " + esc(s.result.error) : "") + "</li>";
    });
    html += "</ul>";
    // Next-Step-Buttons (echte Aktionen mit Oversight-Häkchen)
    html += "<div class='orch-next'><b>Als Nächstes (klickbar):</b><br>";
    const next = st.next_steps || [];
    if (!next.length) {
      html += "<span class='ok'>✅ Alle sinnvollen Schritte ausgeführt – keine offenen Zweifel.</span>";
    }
    next.forEach((n) => {
      html += "<div class='orch-item'><label class='orch-check'>" +
              "<input type='checkbox' class='orch-oversight' data-action='" + esc(n.action) + "'> " +
              "Oversight</label> " +
              "<button type='button' class='pill orch-run' data-action='" + esc(n.action) + "'>" +
              esc(n.label) + "</button> " +
              "<span class='mut'>" + esc(n.why) + "</span></div>";
    });
    html += "</div>";
    panel.innerHTML = html;
    panel.querySelectorAll(".orch-run").forEach((btn) => {
      btn.addEventListener("click", () => runStep(btn.getAttribute("data-action"), btn));
    });
  }

  async function load() {
    try {
      const r = await fetch(base);
      const d = await r.json();
      if (!d.ok) { panel.innerHTML = "<p class='mut'>⚠ " + esc(d.error || "Fehler") + "</p>"; return; }
      renderState(d);
    } catch (e) {
      panel.innerHTML = "<p class='mut'>⚠ Orchestrator nicht erreichbar: " + esc(e) + "</p>";
    }
  }

  async function runStep(action, btn) {
    const box = panel.querySelector(".orch-oversight[data-action='" + action + "']");
    if (!box || !box.checked) { alert("Oversight-Häkchen setzen – aktive Analyse."); return; }
    btn.disabled = true;
    btn.textContent = "läuft…";
    try {
      const r = await fetch(base + "/step", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ action: action, oversight_ok: true })
      });
      const d = await r.json();
      if (!d.ok && d.error) alert("Schritt fehlgeschlagen: " + d.error);
      await load();           // echte Ergebnisse + neue Next-Steps nachladen
    } catch (e) {
      alert("Fehler: " + e);
    }
  }

  load();
})();
