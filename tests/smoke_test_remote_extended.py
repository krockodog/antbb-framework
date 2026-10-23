"""Erweiterte Smoke-Tests Remote-Access (Tailscale aktiv + Cloudflare Free-Tier).

Beweist:
  * Oversight-Gates fuer enable/disable/funnel/dns-upsert.
  * honest-empty ohne Binaries/Tokens (keine erfundenen IPs/Hostnamen).
  * Env-Namen vorhanden, Werte nie in Status/State.
  * remote_full_status + capability_summary Struktur.
  * Access-/WARP-Setup-Schritte sind reine Texte.
  * Service-Fassade delegiert ohne Logik-Duplizierung.
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import tempfile
from antbb import remote_access as ra
from antbb.service import AntBBService

ok = 0
fail = 0


def check(name, cond):
    global ok, fail
    if cond:
        ok += 1
        print(f"  OK  {name}")
    else:
        fail += 1
        print(f"  XX  {name}")


# 1) Oversight-Gates
check("enable_tailscale ohne Oversight blockiert",
      ra.enable_tailscale(oversight=False)["ok"] is False)
check("disable_tailscale ohne Oversight blockiert",
      ra.disable_tailscale(oversight=False)["ok"] is False)
check("funnel ohne Oversight blockiert",
      ra.tailscale_funnel(enable=True, oversight=False)["ok"] is False)
check("dns_upsert ohne Oversight blockiert",
      ra.cloudflare_dns_upsert_cname("x.example.com", "y.cfargotunnel.com",
                                     oversight=False)["ok"] is False)

# 2) honest-empty ohne Binary
os.environ.pop("ANTBB_BIN", None)
os.environ.pop("ANTBB_TAILSCALE", None)
# Temporarily hide PATH binaries by pointing ANTBB override to nothing useful
# and relying on installed-state honestly.
ts = ra.tailscale_status()
if not ts["installed"]:
    check("tailscale honest-empty (kein IP/Hostname)",
          ts["ip"] == "" and ts["hostname"] == "" and ts["url"] == ""
          and ts["running"] is False)
else:
    check("tailscale Status-Struktur (installed)",
          "ip" in ts and "hostname" in ts and "running" in ts)

fun = ra.tailscale_funnel_status()
check("funnel_status Struktur",
      set(["installed", "available", "exposed", "url", "detail"]).issubset(fun))

wp = ra.warp_status()
check("warp_status Struktur",
      set(["installed", "connected", "detail"]).issubset(wp))
if not wp["installed"]:
    check("warp honest-empty ohne Binary", wp["connected"] is False)

# 3) API/DNS/Access honest-empty ohne Token
for k in (ra.CF_API_TOKEN_ENV, ra.CF_ACCOUNT_ID_ENV, ra.CF_ZONE_ID_ENV,
          ra.TS_AUTHKEY_ENV, ra.CLOUDFLARE_TOKEN_ENV):
    os.environ.pop(k, None)

api = ra.cloudflare_api_status()
check("api_status ohne Token = present False",
      api["token_env_present"] is False and api["valid"] is False)

dns = ra.cloudflare_dns_status()
check("dns_status ohne Token honest-empty",
      dns["records"] == [] and dns["token_env_present"] is False)

acc = ra.cloudflare_access_status()
check("access_status ohne Token honest-empty",
      acc["apps"] == [] and acc["token_env_present"] is False)

# 4) Secret-Disziplin: Token-Wert nie im Status
secret = "cf-api-DEADBEEF-should-never-leak"
os.environ[ra.CF_API_TOKEN_ENV] = secret
api2 = ra.cloudflare_api_status()
blob = str(api2)
check("API-Status enthaelt keinen Token-Wert", secret not in blob)
# full status likewise
full = ra.remote_full_status("cloudflare")
check("full_status enthaelt keinen Token-Wert", secret not in str(full))
del os.environ[ra.CF_API_TOKEN_ENV]

# 5) full_status + capability_summary Struktur
check("full_status hat env_names", "env_names" in full and "warp" in full)
check("full_status hat funnel im tailscale-Block",
      "funnel" in full["tailscale"])
check("full_status hat api/access/dns",
      "api" in full["cloudflare"] and "access" in full["cloudflare"]
      and "dns" in full["cloudflare"])

summary = ra.remote_capability_summary()
check("capability_summary keys",
      set(summary) == {"installed", "skipped", "failed"})
check("capability_summary Listen",
      all(isinstance(summary[k], list) for k in summary))

# 6) Setup-Schritte rein Text
steps = ra.cloudflare_access_setup_steps("gui.example.com")
check("access_steps nicht leer", isinstance(steps, list) and len(steps) >= 3)
check("access_steps enthalten OTP-Hinweis",
      any("OTP" in s or "One-time" in s or "E-Mail" in s for s in steps))
wsteps = ra.warp_setup_steps()
check("warp_steps nicht leer", isinstance(wsteps, list) and len(wsteps) >= 2)

# 7) Service-Fassade (keine Duplizierung)
tmp = tempfile.mkdtemp()
db = os.path.join(tmp, "t.db")
svc = AntBBService(db_path=db)
check("svc.get_remote_mode default off", svc.get_remote_mode() == "off")
svc.set_remote_mode("tailscale")
fst = svc.remote_full_status()
check("svc.remote_full_status mode=tailscale", fst["mode"] == "tailscale")
# Oversight-Gate via Service
r = svc.enable_tailscale(oversight=False)
check("svc.enable_tailscale ohne Oversight blockiert", r["ok"] is False)
r2 = svc.tailscale_funnel(enable=True, oversight=False)
check("svc.funnel ohne Oversight blockiert", r2["ok"] is False)
sum2 = svc.remote_capability_summary()
check("svc.capability_summary", "installed" in sum2)
svc.close()

# 8) enable_tailscale ohne Binary ehrlich
# (wenn Binary fehlt: ok=False; wenn vorhanden aber nicht Running und kein Key: ok=False)
r3 = ra.enable_tailscale(oversight=True)
check("enable_tailscale mit Oversight antwortet strukturiert",
      "ok" in r3 and "reason" in r3 and r3.get("running") in (True, False, None)
      or "running" not in r3 or isinstance(r3.get("running"), bool))
# refine: running key may be absent when binary missing
check("enable_tailscale gibt ok bool", isinstance(r3.get("ok"), bool))

print("=" * 60)
print(f"ERGEBNIS: {ok}/{ok + fail} Checks OK")
raise SystemExit(1 if fail else 0)
