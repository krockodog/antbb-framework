/* queens.js — Drei Königinnen im Gehirn: rot mittig, blau/gelb geklont,
   gleich groß, korrekte Farben, Armee-Sektoren, Glas-Knoten,
   Knoten-Panel vom Ursprung her minimiert, keine Spiegelschrift. Nur /brain. */
(function () {
  var st = document.createElement("style");
  st.textContent = [
    ".ant{transform:none !important}",
    ".ant.queen{z-index:300 !important}",
    ".ant.team-red img{filter:saturate(1.2) drop-shadow(0 0 7px rgba(255,90,70,.6)) !important;}",
    ".ant.team-blue img{filter:saturate(1.25) hue-rotate(190deg) drop-shadow(0 0 7px rgba(57,194,255,.65)) !important;}",
    ".ant.team-yellow img{filter:saturate(1.5) hue-rotate(42deg) brightness(1.3) drop-shadow(0 0 7px rgba(255,206,58,.7)) !important;}",
    ".ant-node{width:2px !important;height:2px !important;background:rgba(0,0,0,0) !important;border:1px solid;}",
    ".ant-node .ant-node-lbl{font-size:8px !important;opacity:.5 !important;}"
  ].join("");
  document.head.appendChild(st);

  /* Knoten-Panel vom Ursprung her minimiert (⟨⟩ bleibt bedienbar) */
  var bp = document.getElementById("brain-panel");
  if (bp) bp.classList.add("collapsed");

  function label(el, txt) {
    var l = document.createElement("div");
    l.textContent = txt;
    l.style.cssText = "position:absolute;left:50%;bottom:100%;transform:translateX(-50%);" +
      "margin-bottom:4px;font:11px system-ui;color:#eee;white-space:nowrap;" +
      "background:rgba(8,12,20,.65);padding:2px 8px;border-radius:6px;pointer-events:none";
    el.appendChild(l);
  }
  var HEX = { red: "#ff5a46", blue: "#39c2ff", yellow: "#ffce3a" };

  var iv = setInterval(function () {
    var orig = document.querySelector(".ant.queen");
    if (!orig || orig.dataset.done) return;
    orig.dataset.done = "1";
    clearInterval(iv);
    var host = orig.parentElement;
    orig.style.left = "50%";
    orig.style.transform = "translateX(-50%)";
    orig.querySelectorAll(".queen-label").forEach(function (n) { n.remove(); });
    label(orig, "👑 Rote Königin");
    [["blue", 32, "🛡 Blaue Königin"], ["yellow", 68, "⚖ Gelbe Königin"]].forEach(function (q) {
      var el = orig.cloneNode(true);
      el.classList.add("team-" + q[0]);
      el.style.left = q[1] + "%";
      el.style.height = orig.style.height;   /* exakt gleich groß wie rot */
      el.style.filter = "drop-shadow(0 0 14px " + HEX[q[0]] + ")";
      el.querySelectorAll(".queen-label").forEach(function (n) { n.remove(); });
      host.appendChild(el);
      label(el, q[2]);
    });
  }, 800);
})();
