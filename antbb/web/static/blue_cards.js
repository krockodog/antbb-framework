/* antbb – Blue Queen: Karten-Interaktion (Server rendert Playbooks + Checklisten bereits).
 * Hier nur: Haken speichern (Override-API), Fortschritt, Filter (Text/Phase), SKILL.md-Dialog.
 * Kein Brain-Bezug, keine externen Ressourcen. */
(function () {
  "use strict";
  const grid = document.getElementById("blue-soldier-cards");
  if (!grid) return;
  const cards = Array.from(grid.querySelectorAll(".bq-card"));
  const filter = document.getElementById("soldier-filter");
  const empty = document.getElementById("bq-empty");
  let phase = "";

  const esc = s => String(s == null ? "" : s).replace(/[&<>"]/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}[c]));

  /* ---- Fortschritt ---- */
  function refresh(card) {
    const boxes = card.querySelectorAll(".bq-tasks input");
    const done = card.querySelectorAll(".bq-tasks input:checked").length;
    const badge = card.querySelector("[data-prog]");
    badge.textContent = done + "/" + boxes.length;
    badge.className = "bq-prog" + (boxes.length && done === boxes.length ? " full" : done ? " part" : "");
    card.querySelector("[data-bar]").style.width = (boxes.length ? Math.round(100 * done / boxes.length) : 0) + "%";
  }
  cards.forEach(refresh);

  grid.addEventListener("change", ev => {
    const cb = ev.target;
    if (!cb.matches(".bq-tasks input")) return;
    const card = cb.closest(".bq-card");
    const pb = cb.dataset.pb, task = cb.dataset.task;
    fetch("/api/soldiers/" + encodeURIComponent(card.dataset.name) + "/override", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({playbook: pb, key: "task:" + pb + ":" + task, value: cb.checked ? "done" : "offen"})
    }).then(r => { if (!r.ok) throw new Error(r.status); refresh(card); })
      .catch(() => { cb.checked = !cb.checked; refresh(card); });
    refresh(card);
  });

  /* ---- Filter ---- */
  cards.forEach(c => { c.dataset.search = c.textContent.toLowerCase().replace(/\s+/g, " "); });
  function apply() {
    const q = (filter && filter.value || "").trim().toLowerCase();
    let shown = 0;
    cards.forEach(c => {
      const okP = !phase || (c.dataset.phases || "").split(" ").includes(phase);
      const okQ = !q || c.dataset.search.includes(q);
      c.hidden = !(okP && okQ);
      if (!c.hidden) shown++;
    });
    if (empty) empty.hidden = shown > 0;
    document.querySelectorAll(".bq-chip").forEach(b => b.classList.toggle("active", b.dataset.filterPhase === phase));
    document.querySelectorAll(".bq-phase-btn").forEach(b => b.classList.toggle("on", !!phase && b.dataset.filterPhase === phase));
  }
  if (filter) filter.addEventListener("input", apply);
  document.querySelectorAll("[data-filter-phase]").forEach(b => b.addEventListener("click", () => {
    phase = (phase === b.dataset.filterPhase) ? "" : b.dataset.filterPhase;
    apply();
    if (phase) { const t = document.getElementById("soldier-section"); if (t) t.scrollIntoView({behavior: "smooth", block: "start"}); }
  }));

  /* ---- SKILL.md ---- */
  function mdLite(src) {
    const lines = String(src || "").replace(/\r\n/g, "\n").split("\n");
    let h = "", ul = false, code = false;
    const inl = s => esc(s).replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    const close = () => { if (ul) { h += "</ul>"; ul = false; } };
    lines.forEach((l, i) => {
      if (l.trim().startsWith("```")) { close(); h += code ? "</pre>" : "<pre>"; code = !code; return; }
      if (code) { h += esc(l) + "\n"; return; }
      if (/^---+$/.test(l.trim()) && i < 10) return;
      const m = l.match(/^(name|description|version|colony|license)\s*:\s*(.*)$/);
      if (m && i < 10) { h += '<div class="skill-meta"><span>' + esc(m[1]) + "</span>" + inl(m[2].replace(/^"|"$/g, "")) + "</div>"; return; }
      const hm = l.match(/^(#{1,3})\s+(.*)$/);
      if (hm) { close(); h += "<h" + (hm[1].length + 2) + ">" + inl(hm[2]) + "</h" + (hm[1].length + 2) + ">"; return; }
      if (/^>\s?/.test(l)) { close(); h += "<blockquote>" + inl(l.replace(/^>\s?/, "")) + "</blockquote>"; return; }
      const lm = l.match(/^\s*[-*]\s+(?:\[[ x]\]\s+)?(.*)$/);
      if (lm) { if (!ul) { h += "<ul>"; ul = true; } h += "<li>" + inl(lm[1]) + "</li>"; return; }
      if (!l.trim()) { close(); return; }
      close(); h += "<p>" + inl(l) + "</p>";
    });
    close();
    return h || "<p class='hint'>SKILL.md ist leer.</p>";
  }
  let CAP = null;
  const dlg = document.getElementById("bq-skill-dialog");
  const body = document.getElementById("bq-skill-body");
  const title = document.getElementById("bq-skill-title");
  grid.addEventListener("click", ev => {
    const b = ev.target.closest("[data-skill]");
    if (!b || !dlg) return;
    const name = b.dataset.skill;
    const show = () => {
      const s = ((CAP && CAP.soldiers) || []).find(x => x.name === name);
      title.textContent = "SKILL.md · " + name;
      body.innerHTML = s && s.skill ? mdLite(s.skill.skill_md) : "<p class='hint'>Nicht gefunden.</p>";
      if (typeof dlg.showModal === "function") dlg.showModal(); else dlg.setAttribute("open", "");
    };
    if (CAP) return show();
    fetch("/api/blue").then(r => r.json()).then(d => { CAP = d; show(); })
      .catch(() => { title.textContent = "SKILL.md"; body.innerHTML = "<p class='hint'>Konnte nicht geladen werden.</p>"; });
  });
  if (dlg) dlg.addEventListener("click", e => { if (e.target === dlg) dlg.close(); });
})();
