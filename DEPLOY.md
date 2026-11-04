# Deploy

All and One - RED-BLUE-Yellow-Ant-Team

The console is an authorized-scope pentest platform. Deploy it on loopback, behind a login, as an unprivileged user.

Surface: `http://127.0.0.1:1001`

Roles: Red-Teaming, Blue Safety-Teaming, Yellow Reverse-Teaming.

## Account and directory

```bash
sudo useradd --system --create-home --home-dir /opt/antbb --shell /usr/sbin/nologin antbb
sudo mkdir -p /opt/antbb
sudo rsync -a --exclude .git --exclude antbb.env --exclude data ./ /opt/antbb/
sudo python3 -m venv /opt/antbb/.venv
sudo /opt/antbb/.venv/bin/pip install -r /opt/antbb/requirements.txt
sudo chown -R antbb:antbb /opt/antbb
```

Working directory: `/opt/antbb`.

## Credential

There is no default password. Generate a hash as the operator and store it only in `/opt/antbb/antbb.env` (mode 600, owner `antbb`):

```bash
python -m antbb.webauth hash-password
# antbb.env:
# ANTBB_ADMIN_USER=admin
# ANTBB_ADMIN_PASSWORD_HASH=pbkdf2_sha256:<iterations>:<salt>:<hash>
```

`ANTBB_ADMIN_PASSWORD` is accepted and hashed at startup. Prefer the hash. Do not commit the file.

## systemd

Unit file: `deploy/antbb.service` (installed as `antbb.service`).

It sets `User=antbb`, `WorkingDirectory=/opt/antbb`, `NoNewPrivileges=true`, and:

```ini
Environment=ALLONE_HOST=127.0.0.1
Environment=ALLONE_PORT=1001
ExecStart=/opt/antbb/.venv/bin/python -m api --host 127.0.0.1 --port 1001
```

No ambient capabilities are set. Port 1001 is unprivileged, so the unit does not grant a capability to bind privileged ports.

```bash
sudo cp deploy/antbb.service /etc/systemd/system/antbb.service
sudo systemctl daemon-reload
sudo systemctl enable --now antbb
```

Health check (no session): `curl -s http://127.0.0.1:1001/api/health`

## Binding beyond localhost

The default is `ANTBB_EXPOSE=0` (also when the variable is unset): loopback only. Network access is the one-line switch `ANTBB_EXPOSE=1` together with `ANTBB_HOST` (or `--host`). The process prints a warning. Leave it at `0` on a normal deployment and use an SSH tunnel when you need a remote browser. Do not publish the port.

Starting as root is refused. `ANTBB_ALLOW_ROOT=1` only logs a warning and is not the supported setup.

## Containers

`Dockerfile` ends with `USER antbb` (uid 1000). `docker-compose.yml` uses host networking so the process really binds `127.0.0.1` on the host, drops all capabilities, and sets `no-new-privileges`. Put the password hash in `antbb.env`. Do not publish `0.0.0.0:1001`.

## Privileged scans stay outside this process

Monitor-mode WLAN client enumeration needs a raw socket. The web process does not get `CAP_NET_RAW` or `CAP_NET_ADMIN`. Where that scan exists, it is a separate sudoers wrapper (`/opt/allone/wlan_clients_run`) invoked only after Oversight, and it is limited to that helper. The UI, API, and queens run as `antbb`.

## What did not change

Scope stays default-deny. Active and offensive steps still require Human Oversight. A legal notice does not replace Oversight.
