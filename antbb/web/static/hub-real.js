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
  var MOCK=/^(Mira|Joris|Nela|Karim|Sina|Oda|Henrik|Leonie|Tilda|Ruza|Piet|Esme)$/;
  function wipeMockPills(){
    document.querySelectorAll(".queen-card *").forEach(function(n){
      if(n.children && n.children.length) return;
      var t=(n.textContent||"").trim();
      if(MOCK.test(t)) n.remove();
    });
  }
  async function paintFromApi(){
    try{
      var r=await fetch("/api/queens",{cache:"no-store"});
      if(!r.ok) return;
      var rows=await r.json();
      var by={}; rows.forEach(function(q){ by[q.queen_id]=q; });
      document.querySelectorAll(".queen-card").forEach(function(card){
        var q=card.getAttribute("data-queen");
        var data=by[q]; if(!data) return;
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
    }catch(e){}
  }
  function boot(){ fixButtons(); wipeMockPills(); paintFromApi(); }
  if(document.readyState==="loading") document.addEventListener("DOMContentLoaded", boot);
  else boot();
  setTimeout(boot, 600);
  setTimeout(boot, 1800);
})();
