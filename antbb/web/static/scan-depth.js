/* Queen depth suggestion + override (light|intense) */
(function () {
  "use strict";
  function suggest(scopeText, targetLabel) {
    var s = ((scopeText || "") + " " + (targetLabel || "")).toLowerCase();
    function label(key) {
      return (window.t ? window.t(key) : key);
    }
    if (!s.trim()) return { depth: "light", reason: label("depth.none") };
    if (/(\/|cidr|netz|heimnetz|0\/|1\/|24|16|vlan|range|\*|,\s*\w)/.test(s)) {
      return { depth: "intense", reason: label("depth.net") };
    }
    if (/(localhost|127\.0\.0\.1|::1|labor\.|intern|staging|test)/.test(s)) {
      return { depth: "light", reason: label("depth.lab") };
    }
    return { depth: "intense", reason: label("depth.external") };
  }
  window.AntbbDepth = { suggest: suggest };
})();
