(function(){
  "use strict";
  function fixButtons(){
    document.querySelectorAll("a").forEach(function(a){
      var t=(a.textContent||"").replace(/\s+/g," ").trim();
      if(/^Gelbe\s+(Läufe|Laeufe|Fälle|Faelle)/i.test(t)){
        a.textContent="Gelbe Fälle";
        a.setAttribute("href","/yellow");
      }
    });
  }
  function paintFromApi(){
    return fetch("/api/queens",{cache:"no-store"}).then(function(r){
      if(!r.ok) return null;
      return r.json();
    }).then(function(rows){
      if(!rows) return;
      var by={}; rows.forEach(function(q){ by[q.queen_id]=q; });
      document.querySelectorAll(".queen-card").forEach(function(card){
        var data=by[card.getAttribute("data-queen")]; if(!data) return;
        card.querySelectorAll("p").forEach(function(p){
          if(!/Live-Status/i.test(p.textContent||"")) return;
          var label=p.querySelector("span");
          p.textContent="";
          if(label){ p.appendChild(label); p.appendChild(document.createTextNode(" "+(data.live_satz||""))); }
          else p.textContent="Live-Status "+(data.live_satz||"");
        });
        var host=null;
        card.querySelectorAll("div").forEach(function(d){
          if(host) return;
          var c=d.className||"";
          if(c.indexOf("flex")>=0 && c.indexOf("wrap")>=0) host=d;
        });
        if(host && Array.isArray(data.soldier_ids)){
          host.innerHTML="";
          data.soldier_ids.slice(0,10).forEach(function(id){
            var b=document.createElement("span");
            b.className="inline-flex items-center rounded-full border border-white/15 bg-black/20 px-2 py-0.5 text-xs";
            b.textContent=id;
            host.appendChild(b);
          });
        }
      });
    }).catch(function(){});
  }
  function boot(){ fixButtons(); paintFromApi(); }
  if(document.readyState==="loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
})();
