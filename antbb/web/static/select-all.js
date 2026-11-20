/* antbb – Wiederverwendbare „Alle anwählen"-Logik (Karte / Playbook / global).
 * Dieselbe Tri-State-Logik, Override-Persistenz und Live-Zählwerke wie bei den
 * Red-Soldaten. Ein Haken ist nur eine Checklisten-Markierung (Override);
 * Oversight-/Scope-Gates beim tatsaechlichen Start bleiben UNVERAENDERT – 🔒
 * bleibt 🔒, Anhaken umgeht nichts. Speichert per /api/soldiers/overrides/batch.
 *
 * window.AntbbSelectAll(cfg) verdrahtet eine Seite. cfg:
 *   grid, card, pb, task, pbHead, pbCount, prog, bar  (CSS-Selektoren/Klassen)
 *   stepsWord(optional)  – Suffix fuer "x/y <Wort>"
 *   onRefresh(card)      – optionaler Zusatz-Refresh (z. B. seiteneigene Badges)
 *   toolbar              – Container fuer globale Buttons (optional)
 */
(function () {
  "use strict";
  var t = (window.t || function (k) { return k; });
  function esc(s){return String(s==null?"":s).replace(/[&<>"]/g,function(c){return {"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c];});}

  // Styles einmalig beim Laden injizieren – reicht auch, wenn eine Seite nur die
  // .sa-*-Klassen nutzt (z. B. soldiers.js), ohne AntbbSelectAll() aufzurufen.
  (function ensureStyle() {
    if (document.getElementById("sa-style")) return;
    var st = document.createElement("style"); st.id = "sa-style";
    st.textContent = ".sa-sel{display:inline-flex;gap:.3rem;align-items:center;font-size:.8rem;" +
      "opacity:.85;cursor:pointer;margin:.2rem .5rem .2rem 0}" +
      ".sa-sel input{accent-color:#f0b429}" +
      ".sa-sel-card{margin:.3rem 0;font-weight:600}" +
      ".sa-global{display:flex;gap:.5rem;align-items:center;flex-wrap:wrap;margin:.4rem 0}" +
      ".sa-status{font-size:.78rem;opacity:.8}.sa-status.blocked{color:#f87171;opacity:1}";
    (document.head || document.documentElement).appendChild(st);
  })();

  window.AntbbSelectAll = function (cfg) {
    var grid = typeof cfg.grid === "string" ? document.querySelector(cfg.grid) : cfg.grid;
    if (!grid) return null;
    var CARD = cfg.card, PB = cfg.pb, TASK = cfg.task;
    var PBHEAD = cfg.pbHead, PBCOUNT = cfg.pbCount, PROG = cfg.prog, BAR = cfg.bar;
    var stepsWord = cfg.stepsWord || "";

    function tasksIn(scope) { return Array.prototype.slice.call(scope.querySelectorAll(TASK)); }
    function triState(box, all, on) { if (!box) return; box.checked = all>0 && on===all; box.indeterminate = on>0 && on<all; }

    function refresh(card) {
      var boxes = tasksIn(card), done = card.querySelectorAll(TASK + ":checked").length;
      Array.prototype.forEach.call(card.querySelectorAll(PB), function (sec) {
        var tb = tasksIn(sec).length, on = sec.querySelectorAll(TASK + ":checked").length;
        triState(sec.querySelector(".sa-pb-all"), tb, on);
        if (PBCOUNT) { var cnt = sec.querySelector(PBCOUNT); if (cnt) cnt.textContent = on + "/" + tb + (stepsWord ? " " + stepsWord : ""); }
      });
      triState(card.querySelector(".sa-card-all"), boxes.length, done);
      if (PROG) { var badge = card.querySelector(PROG); if (badge) badge.textContent = done + "/" + boxes.length; }
      if (BAR) { var bar = card.querySelector(BAR); if (bar) bar.style.width = (boxes.length ? Math.round(100*done/boxes.length) : 0) + "%"; }
      if (typeof cfg.onRefresh === "function") try { cfg.onRefresh(card); } catch (e) {}
    }

    function status(msg, bad) { var el = document.getElementById("sa-status"); if (el) { el.textContent = msg || ""; el.classList.toggle("blocked", !!bad); } }

    function bulkSet(boxes, on) {
      var changed = boxes.filter(function (cb) { return cb.checked !== on; });
      changed.forEach(function (cb) { cb.checked = on; });
      var cards = []; changed.forEach(function (cb) { var c = cb.closest(CARD); if (c && cards.indexOf(c) < 0) cards.push(c); });
      cards.forEach(refresh);
      if (!changed.length) return Promise.resolve(0);
      var items = changed.map(function (cb) {
        var pb = cb.dataset.pb || cb.dataset.taskPb, task = cb.dataset.task;
        return { soldier: cb.closest(CARD).dataset.name, playbook: pb,
                 key: "task:" + pb + ":" + task, value: on ? "done" : "offen" };
      });
      status(t("red.sel.saving", {n: items.length}));
      var chunks = []; for (var i = 0; i < items.length; i += 500) chunks.push(items.slice(i, i + 500));
      return chunks.reduce(function (p, chunk) {
        return p.then(function () {
          return fetch("/api/soldiers/overrides/batch", { method: "POST",
            headers: {"Content-Type": "application/json"}, body: JSON.stringify({items: chunk}) })
            .then(function (r) { if (!r.ok) throw new Error(r.status); });
        });
      }, Promise.resolve())
        .then(function () { status(t("red.sel.saved", {n: items.length})); return items.length; })
        .catch(function (err) {
          changed.forEach(function (cb) { cb.checked = !on; }); cards.forEach(refresh);
          status(t("red.sel.error", {err: String(err && err.message || err)}), true);
        });
    }

    // Steuer-Checkboxen injizieren (idempotent).
    function decorate() {
      Array.prototype.forEach.call(grid.querySelectorAll(CARD), function (card) {
        if (!card.querySelector(".sa-card-all")) {
          var l = document.createElement("label");
          l.className = "sa-sel sa-sel-card";
          l.innerHTML = "<input type='checkbox' class='sa-card-all'> " + esc(t("red.sel.card"));
          var anchor = PROG ? card.querySelector(PROG) : null;
          var head = anchor && anchor.parentNode ? anchor.parentNode : card;
          head.parentNode.insertBefore(l, head.nextSibling);
        }
        Array.prototype.forEach.call(card.querySelectorAll(PB), function (sec) {
          if (sec.querySelector(".sa-pb-all") || !tasksIn(sec).length) return;
          var l = document.createElement("label");
          l.className = "sa-sel sa-sel-pb";
          l.title = t("red.sel.pb_title");
          l.innerHTML = "<input type='checkbox' class='sa-pb-all'> " + esc(t("red.sel.all"));
          var h = PBHEAD ? sec.querySelector(PBHEAD) : null;
          (h || sec).appendChild(l);
        });
        refresh(card);
      });
    }

    function globalSet(on) {
      var boxes = [];
      Array.prototype.forEach.call(grid.querySelectorAll(CARD), function (c) { if (!c.hidden) boxes = boxes.concat(tasksIn(c)); });
      return bulkSet(boxes, on);
    }

    // Globale Buttons + Status (in cfg.toolbar, falls vorhanden).
    var tb = cfg.toolbar ? (typeof cfg.toolbar === "string" ? document.querySelector(cfg.toolbar) : cfg.toolbar) : null;
    if (tb && !tb.querySelector(".sa-global")) {
      var box = document.createElement("div");
      box.className = "sa-global";
      box.innerHTML = "<button type='button' id='sa-all'>" + esc(t("red.sel.global_on")) +
        "</button> <button type='button' id='sa-none'>" + esc(t("red.sel.global_off")) +
        "</button> <span id='sa-status' class='sa-status' role='status'></span>";
      tb.appendChild(box);
      box.querySelector("#sa-all").addEventListener("click", function () { globalSet(true); });
      box.querySelector("#sa-none").addEventListener("click", function () { globalSet(false); });
    }

    grid.addEventListener("change", function (ev) {
      var el = ev.target; if (!el.matches) return;
      if (el.matches(".sa-pb-all")) { bulkSet(tasksIn(el.closest(PB)), el.checked); }
      else if (el.matches(".sa-card-all")) { bulkSet(tasksIn(el.closest(CARD)), el.checked); }
      else if (el.matches(TASK)) {
        var card = el.closest(CARD), pb = el.dataset.pb || el.dataset.taskPb, task = el.dataset.task;
        fetch("/api/soldiers/" + encodeURIComponent(card.dataset.name) + "/override", {
          method: "POST", headers: {"Content-Type": "application/json"},
          body: JSON.stringify({playbook: pb, key: "task:" + pb + ":" + task, value: el.checked ? "done" : "offen"})
        }).then(function (r) { if (!r.ok) throw new Error(r.status); refresh(card); })
          .catch(function () { el.checked = !el.checked; refresh(card); });
        refresh(card);
      }
    });

    decorate();
    return { refresh: function () { Array.prototype.forEach.call(grid.querySelectorAll(CARD), refresh); }, decorate: decorate, globalSet: globalSet };
  };
})();
