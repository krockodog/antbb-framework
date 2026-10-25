/* Blue Remediation: echte Findings, Oversight, Vorher/Nachher-Beleg. */
(function () {
  "use strict";
  function node(tag, text) {
    const el = document.createElement(tag);
    if (text != null) el.textContent = text;
    return el;
  }
  function load() {
    const host = document.getElementById("blue-remediation-list");
    if (!host) return;
    fetch("/api/blue/findings", {cache: "no-store"}).then(r => r.json()).then(data => {
      host.textContent = "";
      const rows = (data.findings || []).filter(f => f.can_apply && f.status !== "GESCHLOSSEN");
      if (!rows.length) {
        host.appendChild(node("p", "Keine offenen, unterstützten Remediation-Befunde."));
        return;
      }
      rows.forEach(f => {
        const card = node("article", null);
        card.className = "card";
        card.appendChild(node("h4", f.title || ("Finding #" + f.id)));
        card.appendChild(node("p", (f.evidence.check_id || "") + " · " + (f.status || "offen")));
        const result = node("pre", null);
        result.setAttribute("aria-live", "polite");
        const button = node("button", "Anwenden");
        button.type = "button";
        button.className = "blue-go";
        button.addEventListener("click", () => {
          if (!window.confirm("Human Oversight bestätigen und diese Systemänderung ausführen?")) return;
          const check = f.evidence.check_id;
          const body = {oversight_ack: true};
          if (check === "ip-forwarding") {
            if (!window.confirm("Router-Host-Warnung: IP-Forwarding wirklich deaktivieren?")) return;
            body.confirm_router = true;
          }
          if (check === "patch-reboot-required") {
            if (!window.confirm("Neustart nur planen, nicht sofort auslösen?")) return;
            body.confirm_reboot = true;
            body.schedule = window.prompt("Neustart-Zeitplan (systemd-Kalender)", "01:00") || "01:00";
          }
          if (check === "log-forwarding") {
            body.log_target = window.prompt("Syslog-Ziel (Hostname oder IP)") || "";
            if (!body.log_target) return;
          }
          button.disabled = true;
          result.textContent = "Remediation läuft …";
          fetch("/api/blue/findings/" + encodeURIComponent(f.id) + "/apply", {
            method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(body)
          }).then(async r => {
            const data = await r.json();
            if (!r.ok) throw new Error(data.detail || "Remediation fehlgeschlagen");
            result.textContent = JSON.stringify({closed: data.closed, scheduled: data.scheduled, evidence: data.evidence, backups: data.backups}, null, 2);
            button.textContent = data.closed ? "Geschlossen" : data.scheduled ? "Eingeplant" : "Geprüft – weiter offen";
            button.disabled = !data.closed && !data.scheduled ? false : true;
          }).catch(err => {
            result.textContent = String(err.message || err);
            button.disabled = false;
          });
        });
        card.appendChild(button);
        card.appendChild(result);
        host.appendChild(card);
      });
    }).catch(() => { host.textContent = "Befunde konnten nicht geladen werden."; });
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", load);
  else load();
})();
