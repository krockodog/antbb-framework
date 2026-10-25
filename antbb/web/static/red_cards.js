/* antbb – Red Queen: Lädt echte Colony-Daten (Registry, Findings, Läufe) und rendert
 * Phasen-Pipeline, Soldaten-Karten, Findings + Fix-Brücke. Keine Mocks, keine externen
 * Ressourcen; alles same-origin unter :1001. */
(function () {
  "use strict";
  const esc = s => String(s == null ? "" : s).replace(/[&<>"]/g, c => ({"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}[c]));
  const TARGETS = window.RQ_TARGETS || [];
  const ICONS = {recon: "🧭", scanning: "🔎", api: "🔌", auth: "🔑", cloud: "☁️", codeaudit: "📜", poc: "💥",
                 llmsec: "🤖", mobile: "📱", infra: "🕸️", osint: "🌍", verify: "✅", analysis: "🧠",
                 reporting: "📄", takeover: "🎯", threatintel: "📰", fuzz: "🌪️", wifi: "📡"};

  /* ---------- Hero-Stats ---------- */
  function setStat(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }

  /* ---------- Phasen-Pipeline (octogent_phases aus der Registry) ---------- */
  function renderPhases(phases) {
    const host = document.getElementById("rq-pipeline");
    if (!host) return;
    if (!phases || !phases.length) {
      host.innerHTML = "<li class='hint'>Keine Phasen in der Registry — /api/capabilities prüfen.</li>";
      return;
    }
    host.innerHTML = phases.map((ph, i) => {
      const off = ph.mode === "offensive";
      const sols = (ph.soldiers || []).map(s => "<li>" + esc(s) + "</li>").join("");
      const tools = (ph.tools || []).map(t => "<li>" + esc(t) + "</li>").join("");
      return "<li class='rq-phase' style='--i:" + i + "'>" +
        "<div class='rq-phase-box'>" +
        "<span class='rq-phase-no'>" + (i + 1) + "</span>" +
        "<span class='rq-phase-name'>" + esc(ph.label || ph.phase) + "</span>" +
        "<span class='rq-phase-note'>" + esc(ph.note || "") + "</span>" +
        "<span class='rq-phase-count'>" + (ph.soldiers || []).length + " Soldaten</span>" +
        "<span class='rq-phase-mode " + (off ? "off" : "def") + "'>" + (off ? "offensiv" : "defensiv") + "</span>" +
        "</div>" +
        (sols ? "<ul class='rq-phase-sol'>" + sols + "</ul>" : "") +
        (tools ? "<ul class='rq-phase-tools'>" + tools + "</ul>" : "") +
        "</li>";
    }).join("");
  }

  /* ---------- Soldaten-Karten ---------- */
  function renderSoldiers(soldiers) {
    const grid = document.getElementById("rq-soldier-cards");
    if (!grid) return;
    if (!soldiers.length) {
      grid.innerHTML = "<p class='hint'>Keine Rot-Soldaten in der Registry gefunden.</p>";
      return;
    }
    grid.innerHTML = soldiers.map(s => {
      const key = String(s.name || "").replace(/^red-/, "");
      const pbs = (s.playbooks || []).map(pb => {
        const active = pb.oversight_required || pb.mode === "offensive";
        const items = (pb.task_items || []).map(ti =>
          "<li><label><input type='checkbox' data-pb='" + esc(pb.name) + "' data-task='" + esc(ti.task) + "'" +
          (ti.checked ? " checked" : "") + "> <span>" + esc(ti.task) + "</span></label></li>").join("");
        const tools = (pb.tools || []).map(t => "<code>" + esc(t) + "</code>").join("");
        return "<section class='rq-pb" + (pb.oversight_required ? " rq-pb-gated" : "") + "'>" +
          "<div class='rq-pb-head'><h5>" + esc(pb.name) + "</h5>" +
          "<span class='rq-mode" + (active ? " rq-mode-active" : "") + "'>" + (active ? "aktiv" : "defensiv") + "</span>" +
          (pb.oversight_required ? "<span class='rq-lock'>🔒 Oversight</span>" : "") +
          "<span class='rq-pb-count'>" + (pb.task_items || []).length + " Schritte</span></div>" +
          (pb.description ? "<p class='rq-pb-desc'>" + esc(pb.description) + "</p>" : "") +
          (tools ? "<p class='rq-pb-tools'><span>Tools</span>" + tools + "</p>" : "") +
          (items ? "<ul class='rq-tasks'>" + items + "</ul>" : "") +
          "</section>";
      }).join("");
      const skill = s.skill || {};
      return "<article class='rq-scard' data-name='" + esc(s.name) + "'>" +
        "<div class='rq-head'><span class='rq-ico'>" + (ICONS[key] || "🐜") + "</span>" +
        "<div class='rq-id'><h4>" + esc(s.specialty || s.name) + "</h4><code>" + esc(s.name) + "</code></div>" +
        "<span class='rq-prog' data-prog>0/0</span></div>" +
        "<p class='rq-role'>" + esc(s.role || "") + "</p>" +
        "<div class='rq-bar'><span data-bar style='width:0%'></span></div>" +
        "<div class='rq-pbs'>" + (pbs || "<p class='hint'>Keine Playbooks.</p>") + "</div>" +
        "<div class='rq-foot'><span>" + (s.playbooks || []).length + " Playbooks · " + (skill.task_count || 0) + " Aufgaben</span>" +
        "<button type='button' class='rq-skill-btn' data-skill='" + esc(s.name) + "'>📖 SKILL.md lesen</button></div>" +
        "</article>";
    }).join("");

    grid.querySelectorAll(".rq-scard").forEach(card => {
      card.dataset.search = card.textContent.toLowerCase().replace(/\s+/g, " ");
      refresh(card);
    });
  }

  function refresh(card) {
    const boxes = card.querySelectorAll(".rq-tasks input");
    const done = card.querySelectorAll(".rq-tasks input:checked").length;
    const badge = card.querySelector("[data-prog]");
    if (badge) {
      badge.textContent = done + "/" + boxes.length;
      badge.className = "rq-prog" + (boxes.length && done === boxes.length ? " full" : "");
    }
    const bar = card.querySelector("[data-bar]");
    if (bar) bar.style.width = (boxes.length ? Math.round(100 * done / boxes.length) : 0) + "%";
  }

  /* Haken speichern (gleiche Override-API wie Blue) */
  document.addEventListener("change", ev => {
    const cb = ev.target;
    if (!cb.matches || !cb.matches(".rq-tasks input")) return;
    const card = cb.closest(".rq-scard");
    const pb = cb.dataset.pb, task = cb.dataset.task;
    fetch("/api/soldiers/" + encodeURIComponent(card.dataset.name) + "/override", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({playbook: pb, key: "task:" + pb + ":" + task, value: cb.checked ? "done" : "offen"})
    }).then(r => { if (!r.ok) throw new Error(r.status); refresh(card); })
      .catch(() => { cb.checked = !cb.checked; refresh(card); });
    refresh(card);
  });

  /* ---------- Filter ---------- */
  const filterEl = document.getElementById("rq-soldier-filter");
  const emptyEl = document.getElementById("rq-empty");
  function applyFilter() {
    const q = (filterEl && filterEl.value || "").trim().toLowerCase();
    let shown = 0;
    document.querySelectorAll(".rq-scard").forEach(c => {
      const ok = !q || (c.dataset.search || "").includes(q);
      c.hidden = !ok;
      if (!c.hidden) shown++;
    });
    if (emptyEl) emptyEl.hidden = shown > 0;
  }
  if (filterEl) filterEl.addEventListener("input", applyFilter);

  /* ---------- SKILL.md Dialog ---------- */
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
  const dlg = document.getElementById("rq-skill-dialog");
  const body = document.getElementById("rq-skill-body");
  const title = document.getElementById("rq-skill-title");
  document.addEventListener("click", ev => {
    const b = ev.target.closest && ev.target.closest("[data-skill]");
    if (!b || !dlg) return;
    const show = () => {
      const s = ((CAP && CAP.soldiers) || []).find(x => x.name === b.dataset.skill);
      title.textContent = "SKILL.md · " + b.dataset.skill;
      body.innerHTML = s && s.skill ? mdLite(s.skill.skill_md) : "<p class='hint'>Nicht gefunden.</p>";
      if (typeof dlg.showModal === "function") dlg.showModal(); else dlg.setAttribute("open", "");
    };
    if (CAP) return show();
    fetch("/api/capabilities").then(r => r.json()).then(d => { CAP = d; show(); })
      .catch(() => { title.textContent = "SKILL.md"; body.innerHTML = "<p class='hint'>Konnte nicht geladen werden.</p>"; });
  });
  if (dlg) dlg.addEventListener("click", e => { if (e.target === dlg) dlg.close(); });

  /* ---------- Findings + Fix-Brücke ---------- */
  const sevRank = {critical: 4, high: 3, medium: 2, low: 1, info: 0};
  function renderFindings(rows) {
    const host = document.getElementById("rq-findings-body");
    if (!host) return;
    if (!rows.length) {
      host.innerHTML = "<tr><td colspan='5' class='hint'>Noch keine Findings — Kolonie starten oder Ziel öffnen.</td></tr>";
      return;
    }
    host.innerHTML = rows.map(r =>
      "<tr>" +
      "<td><span class='sev-" + esc(r.severity) + "'>" + esc(r.severity) + "</span></td>" +
      "<td>" + esc(r.title) + (r.agent ? "<br><code style='font-size:.66rem;color:#a5828a'>" + esc(r.agent) + "</code>" : "") + "</td>" +
      "<td class='hint'>" + esc(r.target_name) + "</td>" +
      "<td class='hint'>" + esc(r.category || "") + "</td>" +
      "<td><button type='button' class='rq-bluebtn' data-to-blue='" + r.id + "' data-target='" + r.target_id + "'>🛡 In Blau reparieren</button></td>" +
      "</tr>").join("");
  }

  document.addEventListener("click", ev => {
    const b = ev.target.closest && ev.target.closest("[data-to-blue]");
    if (!b) return;
    b.disabled = true;
    fetch("/api/findings/" + b.dataset.toBlue + "/to-blue", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target_id: Number(b.dataset.target)})
    }).then(r => r.json()).then(d => {
      b.textContent = d.ok ? "✅ Blue-Job #" + d.job_id : "⛔ " + (d.error || "fehlgeschlagen");
    }).catch(() => { b.textContent = "⛔ Fehler"; });
  });

  /* ---------- Läufe ---------- */
  function renderRuns(rows) {
    const host = document.getElementById("rq-runs-list");
    if (!host) return;
    if (!rows.length) {
      host.innerHTML = "<p class='hint'>Noch kein Lauf. Scope setzen, Oversight anhaken, Kolonie starten.</p>";
      return;
    }
    host.innerHTML = "<ul class='rq-list'>" + rows.slice(0, 30).map(r =>
      "<li><span class='rq-pill'>" + esc(r.when || "") + "</span>" +
      "<span class='rq-status'>" + esc(r.status || "done") + "</span> " +
      esc(r.summary || r.mode || "Lauf") +
      (r.run_id ? " · <code style='font-size:.7rem;color:#a5828a'>" + esc(String(r.run_id).slice(0, 8)) + "</code>" : "") +
      "</li>").join("") + "</ul>";
  }

  /* ---------- Start-Formular + Live-Feed ---------- */
  const form = document.getElementById("rq-run-form");
  const log = document.getElementById("rq-run-log");
  let feedSince = 0, feedTimer = null;
  function pollFeed() {
    fetch("/api/feed?since=" + feedSince).then(r => r.json()).then(d => {
      (d.events || []).forEach(ev => {
        feedSince++;
        const line = document.createElement("div");
        line.textContent = "[" + (ev.at || ev.time || "") + "] " + (ev.message || JSON.stringify(ev));
        log.appendChild(line);
      });
      log.scrollTop = log.scrollHeight;
    }).catch(() => {});
  }
  function startRun(targetId, opts) {
    const depth = opts.depth || "light";
    const active = Boolean(opts.active);
    const ack = Boolean(opts.ack);
    const phases = opts.phases || null;
    const label = opts.label || "Kolonie-Lauf";
    const btn = opts.button || null;
    if (btn) btn.disabled = true;
    log.textContent = "Starte " + label + " (Tiefe: " + depth + (active ? ", aktiv" : ", lesend") + ")…\n";
    const body = {active: active, depth: depth, oversight_ack: ack};
    if (phases) body.phases = phases;
    fetch("/api/targets/" + targetId + "/scan", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify(body)
    }).then(r => r.json().then(d => ({ok: r.ok, d}))).then(({ok, d}) => {
      log.textContent += (d.detail || d.status || JSON.stringify(d)) + "\n";
      if (ok) {
        feedSince = 0;
        if (feedTimer) clearInterval(feedTimer);
        feedTimer = setInterval(pollFeed, 2000);
        pollFeed();
        setTimeout(() => { if (feedTimer) { clearInterval(feedTimer); feedTimer = null; } loadAll(); }, 120000);
      }
    }).catch(e => { log.textContent += "Fehler: " + e.message + "\n"; })
      .finally(() => { if (btn) btn.disabled = false; });
  }

  /* Red-Team-Menü: erscheint nach Ziel-Auswahl, Freigabe-Logik wie im Formular */
  const actions = document.getElementById("rq-actions");
  const targetSel = form ? form.querySelector("select[name=target_id]") : null;
  const ackBoxMenu = document.getElementById("rq-ack");
  const scopeHint = document.getElementById("rq-actions-scope");
  const reportLink = document.getElementById("rq-report-link");
  function refreshMenu() {
    if (!actions || !targetSel) return;
    const tid = targetSel.value;
    actions.hidden = !tid;
    if (!tid) return;
    const name = targetSel.options[targetSel.selectedIndex].textContent || ("#" + tid);
    if (scopeHint) scopeHint.textContent = "Ziel: " + name.trim() + " — Standard: lesend. 🔒-Aktionen brauchen das Oversight-Häkchen im Block „Kolonie starten".";
    if (reportLink) reportLink.href = "/target/" + tid;
    const acked = Boolean(ackBoxMenu && ackBoxMenu.checked);
    document.querySelectorAll(".rq-mi-gated .rq-run").forEach(b => {
      b.disabled = !acked;
      b.title = acked ? "mit Human Oversight freigegeben" : "nur mit Human Oversight";
    });
  }
  if (targetSel) targetSel.addEventListener("change", refreshMenu);
  if (ackBoxMenu) ackBoxMenu.addEventListener("change", refreshMenu);
  document.querySelectorAll("#rq-menu .rq-run").forEach(btn => {
    btn.addEventListener("click", () => {
      const mi = btn.closest(".rq-mi");
      if (!mi || !targetSel || !targetSel.value) return;
      startRun(targetSel.value, {
        depth: (form && form.depth && form.depth.value) || "light",
        active: mi.classList.contains("rq-mi-gated"),
        ack: Boolean(ackBoxMenu && ackBoxMenu.checked),
        phases: (mi.dataset.phases || "").split(" ").filter(Boolean),
        label: (btn.dataset.label || "Lauf").replace(/&amp;/g, "&"),
        button: btn
      });
      if (log) log.scrollIntoView({behavior: "smooth", block: "nearest"});
    });
  });

  if (form) {
    const activeBox = document.getElementById("rq-active");
    const ackWrap = document.getElementById("rq-ack-wrap");
    const ackBox = document.getElementById("rq-ack");
    if (activeBox && ackWrap) activeBox.addEventListener("change", () => {
      ackWrap.style.display = activeBox.checked ? "" : "none";
      if (!activeBox.checked && ackBox) ackBox.checked = false;
      refreshMenu();
    });
    form.addEventListener("submit", ev => {
      ev.preventDefault();
      const targetId = form.target_id.value;
      if (!targetId) { log.textContent = "Ziel wählen — ohne Scope kein Lauf (default-deny)."; return; }
      startRun(targetId, {
        depth: form.depth.value === "intense" ? "intense" : "light",
        active: Boolean(activeBox && activeBox.checked),
        ack: Boolean(ackBox && ackBox.checked),
        label: "Kolonie-Lauf",
        button: form.querySelector(".rq-go")
      });
    });
  }

  /* ---------- Daten laden ---------- */
  function loadAll() {
    fetch("/api/capabilities").then(r => r.json()).then(cap => {
      CAP = cap;
      const reds = (cap.soldiers || []).filter(s => s.colony !== "blue");
      const pbN = reds.reduce((n, s) => n + (s.playbooks || []).length, 0);
      const taskN = reds.reduce((n, s) => n + ((s.skill || {}).task_count || 0), 0);
      setStat("rst-soldiers", reds.length);
      setStat("rst-playbooks", pbN);
      setStat("rst-tasks", taskN);
      renderPhases(cap.octogent_phases || []);
      renderSoldiers(reds);
      applyFilter();
    }).catch(() => {
      const host = document.getElementById("rq-soldier-cards");
      if (host) host.innerHTML = "<p class='hint'>Registry (/api/capabilities) antwortet nicht.</p>";
    });

    Promise.all(TARGETS.map(t =>
      fetch("/api/targets/" + t.id + "/findings").then(r => r.json())
        .then(rows => (rows || []).map(f => Object.assign({target_id: t.id, target_name: t.name}, f)))
        .catch(() => [])
    )).then(results => {
      const rows = [].concat.apply([], results)
        .sort((a, b) => (sevRank[b.severity] || 0) - (sevRank[a.severity] || 0));
      setStat("rst-findings", rows.length);
      renderFindings(rows.slice(0, 50));
    }).catch(() => {});

    fetch("/api/runs?colony=red").then(r => r.json()).then(renderRuns).catch(() => {});
  }
  loadAll();
})();
