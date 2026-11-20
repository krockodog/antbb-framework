/* Governance-Statusleiste für die FastAPI-Unterseiten (gleiche Daten wie die
   Startseite: /api/governance/status). Echte Zustände, keine Platzhalter.
   STOP ALL AGENTS nur für Admin (Server prüft die Rolle erneut). */
(function () {
  "use strict";
  if (window.__antbbGovBar) return; window.__antbbGovBar = true;
  var T = function (k, v) { return window.t ? window.t(k, v) : k; };
  var head = document.querySelector("header.antbb-topnav");
  if (!head) return;
  var bar = document.createElement("div");
  bar.className = "gov-sub-bar";
  bar.setAttribute("role", "status");
  head.insertAdjacentElement("afterend", bar);
  function pill(label, value, tone) {
    return '<span class="gsb-pill" data-tone="' + tone + '"><i></i>' + label + ': <b>' + value + '</b></span>';
  }
  function esc(s) { return String(s == null ? "" : s).replace(/[&<>"]/g, function (c) { return {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}[c]; }); }
  function post(path, body) {
    return fetch(path, {method: "POST", credentials: "same-origin",
      headers: {"Content-Type": "application/json", "Accept": "application/json"},
      body: JSON.stringify(body)}).then(function (r) {
        return r.json().catch(function () { return {}; }).then(function (d) {
          if (!r.ok) throw new Error(d.detail || ("HTTP " + r.status)); return d; });
      });
  }
  function render(s) {
    var sc = s.scope || {};
    var scopeTone = sc.state === "verified" ? "ok" : sc.state === "halted" ? "block" : sc.state === "none" ? "off" : "warn";
    var scopeVal = sc.state === "none" ? T("gov.state.none") : sc.state === "halted" ? T("gov.state.halted") :
      sc.state === "verified" ? T("gov.state.verified") : T("gov.state.unverified");
    var kill = s.kill_switch && s.kill_switch.state === "active";
    var h = pill(T("gov.bar.policy"), T("gov.state.default_deny"), "ok") +
      pill(T("gov.bar.scope"), esc(scopeVal), scopeTone) +
      pill(T("gov.bar.approval"), s.approval.state === "pending" ? esc(T("gov.state.pending", {n: s.approval.pending})) : T("gov.state.enabled"),
           s.approval.state === "pending" ? "warn" : "ok") +
      pill(T("gov.bar.audit"), s.audit.state === "active" ? T("gov.state.active") : T("gov.state.inactive"), s.audit.state === "active" ? "ok" : "off") +
      pill(T("gov.bar.kill"), kill ? T("gov.state.kill_active") : T("gov.state.ready"), kill ? "block" : "ok");
    if (s.viewer && s.viewer.can_kill) {
      h += '<button type="button" class="gsb-kill' + (kill ? " gsb-reset" : "") + '">' +
        (kill ? T("gov.kill.reset") : "■ " + T("gov.kill.button")) + '</button>';
    }
    bar.innerHTML = h;
    var btn = bar.querySelector(".gsb-kill");
    if (btn) btn.onclick = function () {
      if (!window.confirm(kill ? T("gov.kill.reset_confirm") : T("gov.kill.confirm"))) return;
      btn.disabled = true;
      (kill ? post("/api/governance/reset", {confirm: "RESET"}) : post("/api/governance/kill", {confirm: "STOP", reason: location.pathname}))
        .then(load).catch(function (e) { window.alert(e.message); load(); });
    };
  }
  function load() {
    fetch("/api/governance/status", {credentials: "same-origin", cache: "no-store", headers: {"Accept": "application/json"}})
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (s) { if (s) render(s); else bar.hidden = true; })
      .catch(function () { bar.hidden = true; });
  }
  load(); setInterval(load, 20000);
})();
