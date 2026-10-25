/* Superhirn-Log: live ledger from red/blue/yellow on /brain */
(function () {
  "use strict";
  if (window.__superhirnLogInstalled) return;
  window.__superhirnLogInstalled = true;

  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  function ensureUi() {
    if (document.getElementById("superhirn-log")) return;
    var style = el("style");
    style.textContent = [
      "#superhirn-hub{position:fixed;top:12px;left:12px;z-index:40;}",
      "#superhirn-hub a{display:inline-flex;align-items:center;gap:.35rem;padding:.35rem .7rem;border-radius:999px;border:1px solid rgba(212,175,106,.45);background:rgba(8,10,16,.72);color:#e8ecf5;font:600 .78rem/1.2 system-ui,sans-serif;text-decoration:none;backdrop-filter:blur(6px);}",
      "#superhirn-hub a:hover{border-color:#d4af6a;color:#fff;}",
      "#superhirn-log{position:fixed;right:12px;bottom:12px;width:min(420px,92vw);max-height:42vh;z-index:40;display:flex;flex-direction:column;border:1px solid rgba(212,175,106,.35);border-radius:14px;background:rgba(8,10,16,.82);color:#d7dce8;font:12px/1.35 ui-monospace,SFMono-Regular,Menlo,monospace;backdrop-filter:blur(8px);box-shadow:0 10px 40px rgba(0,0,0,.45);}",
      "#superhirn-log header{display:flex;align-items:center;justify-content:space-between;gap:.5rem;padding:.55rem .7rem;border-bottom:1px solid rgba(255,255,255,.06);}",
      "#superhirn-log header b{font:600 .72rem/1 system-ui,sans-serif;letter-spacing:.14em;text-transform:uppercase;color:#d4af6a;}",
      "#superhirn-log header button{border:0;background:transparent;color:#9aa3b5;cursor:pointer;font-size:.8rem;}",
      "#superhirn-log .body{overflow:auto;padding:.45rem .65rem .65rem;flex:1;}",
      "#superhirn-log .line{padding:.18rem 0;border-bottom:1px solid rgba(255,255,255,.04);white-space:pre-wrap;}",
      "#superhirn-log .t{color:#6b7280;margin-right:.4rem;}",
      "#superhirn-log .q-red{color:#ff7a8a;}",
      "#superhirn-log .q-blue{color:#7fd4e4;}",
      "#superhirn-log .q-yellow{color:#f0c14a;}",
      "#superhirn-log.collapsed{max-height:none;}",
      "#superhirn-log.collapsed .body{display:none;}"
    ].join("\n");
    document.head.appendChild(style);

    if (!document.getElementById("superhirn-hub")) {
      var hub = el("div", null);
      hub.id = "superhirn-hub";
      var a = el("a", null, "← Hub");
      a.href = "/";
      a.title = "Zurück zum Hub";
      hub.appendChild(a);
      document.body.appendChild(hub);
    }

    var box = el("aside");
    box.id = "superhirn-log";
    box.setAttribute("aria-label", "Superhirn Ereignis-Log");
    var head = el("header");
    head.appendChild(el("b", null, "Superhirn · Log"));
    var btn = el("button", null, "▾");
    btn.type = "button";
    btn.title = "Ein-/ausklappen";
    btn.onclick = function () {
      box.classList.toggle("collapsed");
      btn.textContent = box.classList.contains("collapsed") ? "▸" : "▾";
    };
    head.appendChild(btn);
    box.appendChild(head);
    var body = el("div", "body");
    body.id = "superhirn-log-body";
    body.appendChild(el("div", "line", "Warte auf Ereignisse der drei Königinnen…"));
    box.appendChild(body);
    document.body.appendChild(box);
  }

  function addLine(queen, at, msg) {
    var body = document.getElementById("superhirn-log-body");
    if (!body) return;
    if (body.dataset.empty === "1" || (body.children.length === 1 && body.textContent.indexOf("Warte") === 0)) {
      body.textContent = "";
      body.dataset.empty = "0";
    }
    var line = el("div", "line");
    var t = el("span", "t", at || "");
    var q = el("span", "q-" + queen, "[" + queen + "] ");
    line.appendChild(t);
    line.appendChild(q);
    line.appendChild(document.createTextNode(msg || ""));
    body.insertBefore(line, body.firstChild);
    while (body.children.length > 120) body.removeChild(body.lastChild);
  }

  var seen = new Set();
  function key(q, at, msg) { return q + "|" + at + "|" + msg; }

  async function pullQueen(q) {
    try {
      var r = await fetch("/api/queens/" + q + "/ledger", { cache: "no-store" });
      if (!r.ok) return;
      var d = await r.json();
      (d.ledger || []).slice(-30).forEach(function (row) {
        var k = key(q, row.at || "", row.message || "");
        if (seen.has(k)) return;
        seen.add(k);
        addLine(q, row.at || "", row.message || JSON.stringify(row));
      });
    } catch (e) { /* ignore */ }
  }

  async function pullBrain() {
    try {
      var r = await fetch("/api/brain", { cache: "no-store" });
      if (!r.ok) return;
      var d = await r.json();
      var strip = d.strip || "";
      if (strip) {
        var k = key("all", "strip", strip);
        if (!seen.has(k)) {
          seen.add(k);
          addLine("red", new Date().toLocaleTimeString("de-DE"), "Strip: " + strip);
        }
      }
      (d.queens || []).forEach(function (queen) {
        var msg = (queen.queen_id || "?") + ": " + (queen.live_satz || queen.strip_teil || "");
        var k = key(queen.queen_id || "?", "live", msg);
        if (seen.has(k)) return;
        seen.add(k);
        addLine(queen.queen_id || "red", new Date().toLocaleTimeString("de-DE"), queen.live_satz || msg);
      });
    } catch (e) { /* ignore */ }
  }

  function tick() {
    ensureUi();
    pullQueen("red");
    pullQueen("blue");
    pullQueen("yellow");
    pullBrain();
  }

  function boot() {
    ensureUi();
    tick();
    setInterval(tick, 4000);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
