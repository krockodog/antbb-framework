# All and One (antbb) auf Oracle Cloud Always Free

Ziel: die komplette App (Hub `/`, `/red`, `/blue`, `/yellow`, `/brain`, `/wlan`, API) als
gehostete Web-App unter einer eigenen (Sub-)Domain, ohne laufende Kosten.

```
Internet ──443/80──> Caddy (Let's Encrypt, auf dem Host) ──> 127.0.0.1:1001 ──> Docker: antbb (ANTBB_HOSTED=1)
```

- Instanz: **Ampere A1 (arm64), Ubuntu**, Region Frankfurt, im Always-Free-Kontingent.
- Öffentlich offen: nur **22 (SSH), 80, 443**. Port 1001 lauscht nur auf `127.0.0.1`.
- Login vor allen Routen (außer `/healthz`), Hosted-Modus erzwingt Oversight und Scope serverseitig.
- Keine Secrets im Image oder Repo. Hash und Provider-Keys nur in `antbb.env` (chmod 600, gitignored).

Platzhalter unten: `ANTBB_DOMAIN` (z. B. `antbb.example.org`), `<OCI-IP>` (öffentliche IP der Instanz).

## 1. Instanz und Netzwerk (OCI-Konsole)

1. Compute → Instance erstellen: Shape `VM.Standard.A1.Flex` (Always Free), Image Ubuntu (aarch64), SSH-Key hinterlegen.
2. Öffentliche IP notieren (am besten als *Reserved Public IP*, damit sie sich nicht ändert).
3. Networking → Virtual Cloud Networks → VCN → Subnet → **Security List** → *Add Ingress Rules*:
   - Source `0.0.0.0/0`, TCP, Destination Port `80` (für Let's Encrypt HTTP-01 und Redirect)
   - Source `0.0.0.0/0`, TCP, Destination Port `443`
   - Die vorhandene Regel für `22` bleibt. Port `1001` **nicht** freigeben.

## 2. DNS

Beim DNS-Anbieter der Domain einen **A-Record** anlegen: `ANTBB_DOMAIN → <OCI-IP>`.
Prüfen: `dig +short ANTBB_DOMAIN` muss `<OCI-IP>` liefern, bevor Caddy das Zertifikat holt.

## 3. Host einrichten (Docker, Firewall, Caddy)

```bash
ssh ubuntu@<OCI-IP>
git clone https://github.com/krockodog/antbb-framework.git ~/antbb && cd ~/antbb
git checkout feat/hosted-webapp        # bis der Branch gemergt ist
sudo ANTBB_DOMAIN=antbb.example.org ACME_EMAIL=du@example.org deploy/oracle-setup.sh
```

`deploy/oracle-setup.sh` installiert Docker Engine + Compose-Plugin (offizielles Docker-Repo),
öffnet 80/443 per `iptables` oberhalb der REJECT-Regel des OCI-Images und speichert mit
`netfilter-persistent` (ufw ist auf OCI-Ubuntu-Images bewusst deaktiviert und greift dort nicht),
installiert Caddy (offizielles Repo) und schreibt `/etc/caddy/Caddyfile` aus `deploy/Caddyfile.template`.
`ACME_EMAIL` ist optional.

## 4. Admin-Hash und antbb.env

```bash
cd ~/antbb
docker build -t antbb-allone:hosted .   # baut nativ für arm64 (Next.js-Export + FastAPI)
deploy/make-password-hash.sh              # fragt das Passwort ohne Echo, gibt den Hash aus
install -m 600 /dev/null antbb.env
nano antbb.env
```

Inhalt `antbb.env` (Beispiel, Werte selbst eintragen):

```
ANTBB_ADMIN_USER=admin
ANTBB_ADMIN_PASSWORD_HASH=pbkdf2_sha256:240000:<salt>:<hash>
# optional, nur wenn vorhanden:
# MINIMAX_API_KEY=
```

Kein `ANTBB_ADMIN_PASSWORD` (Klartext) und kein `ANTBB_EXPOSE` eintragen: der Hosted-Modus verweigert dann den Start.

## 5. Starten und prüfen

```bash
docker compose up -d                      # nutzt das gebaute Image antbb-allone:hosted
docker compose ps                         # STATUS: healthy
curl -s http://127.0.0.1:1001/healthz     # {"ok":true}
curl -sI https://antbb.example.org/ | head -1   # 303 -> /login
ANTBB_TEST_PASSWORD='…' deploy/smoke-hosted.sh https://antbb.example.org
```

Von außen darf nur 80/443 antworten: `nc -vz <OCI-IP> 1001` muss scheitern.

## Betrieb

- Update: `git pull && docker compose up -d --build`
- Logs: `docker compose logs -f antbb`, `sudo journalctl -u caddy -f`
- Abschalten: `docker compose down` (Daten bleiben im Volume `antbb-data`); öffentlich ganz zu: `sudo systemctl stop caddy`
- Passwort ändern: neuen Hash erzeugen, in `antbb.env` ersetzen, `docker compose up -d`
- Zu viele Fehlversuche: Login gesperrt (429) für `ANTBB_LOGIN_WINDOW` Sekunden (Default 600).

## Multi-Arch-Image (optional)

Auf der A1-Instanz baut `docker compose build` direkt arm64. Ein Image für amd64 **und** arm64
auf einem anderen Rechner: `docker buildx build --platform linux/amd64,linux/arm64 -t antbb-allone:hosted .`
(braucht QEMU/binfmt und ein Registry-Ziel mit `--push`, oder `--load` für eine einzelne Plattform).

## Alternativen

- **Ohne eigene Domain: DuckDNS** (kostenlos). Subdomain auf duckdns.org anlegen, als `ANTBB_DOMAIN`
  `<name>.duckdns.org` verwenden; Caddy holt das Zertifikat genauso per HTTP-01. Der DuckDNS-Token wird
  nur zum IP-Update gebraucht und gehört in eine root-only Datei (z. B. `/etc/antbb/duckdns.env`, chmod 600),
  nie ins Repo. Bei einer Reserved Public IP reicht ein einmaliges Update.
- **Tailscale Funnel** statt Caddy: siehe `deploy/tailscale-funnel.md`.
