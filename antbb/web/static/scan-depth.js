/* Queen depth suggestion + override (light|intense) */
(function () {
  "use strict";
  function suggest(scopeText, targetLabel) {
    var s = ((scopeText || "") + " " + (targetLabel || "")).toLowerCase();
    if (!s.trim()) return { depth: "light", reason: "Kein Scope → Leicht (sicherer Default)." };
    if (/(\/|cidr|netz|heimnetz|0\/|1\/|24|16|vlan|range|\*|,\s*\w)/.test(s)) {
      return { depth: "intense", reason: "Mehrere Ziele / Netz erkannt → Intensiv empfohlen." };
    }
    if (/(localhost|127\.0\.0\.1|::1|labor\.|intern|staging|test)/.test(s)) {
      return { depth: "light", reason: "Lokales/Lab-Ziel → Leicht empfohlen." };
    }
    return { depth: "intense", reason: "Externes/unbekanntes Ziel → Intensiv empfohlen." };
  }
  window.AntbbDepth = { suggest: suggest };
})();
