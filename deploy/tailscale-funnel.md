# Optional: Tailscale Funnel statt Caddy

Funnel stellt `127.0.0.1:1001` unter `https://<maschine>.<tailnet>.ts.net` ins Internet,
mit TLS-Zertifikat von Tailscale. Keine eigene Domain, keine offenen Ports am Router.
Syntax geprüft gegen https://tailscale.com/kb/1311/tailscale-funnel (Client ≥ 1.52).

Voraussetzungen: Tailscale installiert (`curl -fsSL https://tailscale.com/install.sh | sh`),
HTTPS-Zertifikate und Funnel im Tailnet erlaubt (Admin-Konsole: DNS → HTTPS Certificates;
Access Controls → `funnel`-Attribut für den Node). Funnel erlaubt nur die Ports 443, 8443, 10000.

```bash
sudo tailscale up                      # Login interaktiv im Browser, kein Auth-Key im Klartext
docker compose up -d                   # App wie in oracle-free.md (antbb.env mit Hash)
deploy/funnel.sh on                    # = sudo tailscale funnel --bg 1001
deploy/funnel.sh url                   # zeigt https://<maschine>.<tailnet>.ts.net
deploy/funnel.sh status                # = sudo tailscale funnel status
deploy/funnel.sh off                   # = sudo tailscale funnel --https=443 off (Fallback: funnel reset)
```

`--bg` überlebt Neustarts. Tailscale reicht den Original-Host, `X-Forwarded-Proto: https` und
`X-Forwarded-For` an `127.0.0.1:1001` weiter; uvicorn vertraut diesen Headern nur von `127.0.0.1`.
Login, Hosted-Modus und Gates gelten unverändert. Caddy und Funnel nicht gleichzeitig auf 443 betreiben.
