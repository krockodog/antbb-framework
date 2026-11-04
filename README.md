# All and One - RED-BLUE-Yellow-Ant-Team

ANTBB is a self-hosted platform for **authorized** security work. Three queens share one process:

| Queen | Role | What it does |
|---|---|---|
| **Red** | Red-Teaming | Bug bounty and pentest inside an allowlist. Findings need evidence. |
| **Blue** | Blue Safety-Teaming | Hardening, posture, and remediation with before/after evidence. |
| **Yellow** | Yellow Reverse-Teaming | Reverse engineering of samples you are allowed to analyze. |

The German manual is [README.de.md](README.de.md). This file is the English overview.

Unauthorized probing of other people's systems is a crime (German StGB § 202a–c; the US CFAA). The notice on every page does not replace a human decision.

## Quick start

Fresh clone on Linux (the project is tested on Debian/Ubuntu). The unit file `deploy/antbb.service` runs as `User=antbb` / `Group=antbb`, with `WorkingDirectory=/opt/antbb`, and reads `/opt/antbb/antbb.env`. The `useradd` line is the one in [DEPLOY.md](DEPLOY.md). On Debian/Ubuntu it creates the `antbb` group the unit requires, and `--create-home` creates `/opt/antbb`.

1. Create the unprivileged account (this also creates the `antbb` group the unit requires):

   ```bash
   sudo useradd --system --create-home --home-dir /opt/antbb --shell /usr/sbin/nologin antbb
   ```

2. Clone, then copy the tree into `/opt/antbb`. `git clone` cannot target `/opt/antbb` directly because `useradd --create-home` already created that directory. The `rsync` flags are the ones in `DEPLOY.md`:

   ```bash
   git clone https://github.com/krockodog/antbb-framework.git
   sudo rsync -a --exclude .git --exclude antbb.env --exclude data ./antbb-framework/ /opt/antbb/
   ```

3. Create the virtualenv the unit executes (`/opt/antbb/.venv/bin/python`) and install dependencies:

   ```bash
   sudo python3 -m venv /opt/antbb/.venv
   sudo /opt/antbb/.venv/bin/pip install -r /opt/antbb/requirements.txt
   ```

4. Create the env file (mode 600). It is gitignored. Do not commit it.

   ```bash
   sudo cp /opt/antbb/antbb.env.example /opt/antbb/antbb.env
   sudo chmod 600 /opt/antbb/antbb.env
   ```

5. From `/opt/antbb`, generate a hash. The command prompts; it does not take the password as an argument. Username defaults to `admin` when `ANTBB_ADMIN_USER` is unset.

   ```bash
   cd /opt/antbb
   sudo .venv/bin/python -m antbb.webauth hash-password
   ```

6. As root (the file is mode 600), add the printed line to `/opt/antbb/antbb.env` as `ANTBB_ADMIN_PASSWORD_HASH=...`. Then give the tree to `antbb`, or that file stays unreadable by the service user:

   ```bash
   sudo chown -R antbb:antbb /opt/antbb
   ```

7. Install and start `antbb.service`, or run the same program by hand.

   Service (`deploy/antbb.service` loads `antbb.env` via `EnvironmentFile`):

   ```bash
   sudo cp /opt/antbb/deploy/antbb.service /etc/systemd/system/antbb.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now antbb
   ```

   Or, as user `antbb` (this program does not read `antbb.env` by itself, so the file has to be sourced in the same shell):

   ```bash
   sudo -u antbb bash -c 'cd /opt/antbb && set -a && . ./antbb.env && set +a && exec .venv/bin/python -m api --host 127.0.0.1 --port 1001'
   ```

8. Open http://127.0.0.1:1001/login

- Nothing starts without `ANTBB_ADMIN_PASSWORD_HASH` (or `ANTBB_ADMIN_PASSWORD`). There is no default password.
- Do not run it as root. The entry points refuse, and the unit sets `User=antbb`.
- The bind stays `127.0.0.1` unless you set `ANTBB_EXPOSE=1` on purpose. That opt-in logs a warning.
- From another machine, use an SSH tunnel (`ssh -L 1001:127.0.0.1:1001 <user>@<host>`) and open the same URL locally. Do not publish the port.

`./run.sh` is a different launcher (`install-and-start.sh`). It also refuses root, a missing hash, and a non-loopback bind without `ANTBB_EXPOSE=1`, and it defaults to port 8000, not 1001.

## Safety model

These controls are on by default and this change does not weaken them:

1. **Authorized scope only.** You name the systems you are allowed to test.
2. **Default-deny.** An empty allowlist means no target and no run. Wildcards are rejected.
3. **Oversight.** Active or offensive steps (verification, proof-of-concept, fixes, tunnels, wireless actions) wait for a human confirmation. The legal text is not that confirmation.
4. **Defensive default.** Reads and posture checks run without switching the platform into an offensive mode.
5. **Non-destructive find-and-prove.** A finding is verified only with evidence. Anything the tool cannot do is reported as such, not invented.
6. **No secrets in findings.** Cracked material is masked and is not stored.

## Install

The first-run path is [Quick start](#quick-start). The block below is only the clone and the virtualenv. Linux, Python 3.11+, and git. Node 20 is only needed to rebuild the hub.

```bash
git clone https://github.com/krockodog/antbb-framework.git
cd antbb-framework
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp antbb.env.example antbb.env
chmod 600 antbb.env
```

`antbb.env` is gitignored. Never commit it.

## Secure configuration

Three settings are required before the console is usable. The server refuses to start when they are missing.

### Localhost

The web UI and API bind to **127.0.0.1** everywhere they are started: `python -m api`, `python -m antbb.serve`, `run_web.py`, `./run.sh`, `install.sh`, `install-and-start.sh`, the Dockerfile, Compose, and `deploy/antbb.service`.

Another interface is an explicit opt-in. Set `ANTBB_EXPOSE=1` and the host you want (`ANTBB_HOST` or `--host`). The process prints a warning. Without the opt-in it exits, and a process that was started with a raw `uvicorn --host 0.0.0.0` rejects requests.

```bash
# normal
python -m api --host 127.0.0.1 --port 1001

# deliberate exposure (avoid this; use an SSH tunnel)
ANTBB_EXPOSE=1 python -m api --host 0.0.0.0 --port 1001
```

Health check, no login: `curl -s http://127.0.0.1:1001/api/health`

### Login

There is **no default password** and no account in git.

```bash
python -m antbb.webauth hash-password
```

Put the printed line into `antbb.env`:

```bash
ANTBB_ADMIN_USER=admin
ANTBB_ADMIN_PASSWORD_HASH=pbkdf2_sha256:<iterations>:<salt_hex>:<hash_hex>
```

`ANTBB_ADMIN_PASSWORD` is accepted and hashed in memory at startup. Prefer the hash. The password is never logged.

On a terminal, `install-and-start.sh` asks once and writes only the hash (mode 600). Non-interactive runs exit until the hash is set.

Every route except `GET /api/health` (and the per-queen health checks) requires a session. The session cookie is `HttpOnly` and `SameSite=Lax`. It is marked `Secure` when the request is HTTPS, when `ANTBB_COOKIE_SECURE=1`, or when `ANTBB_TRUST_PROXY=1` and `X-Forwarded-Proto` is `https`.

State-changing requests that use the cookie are rejected when the browser sends a cross-site `Origin`, `Referer`, or `Sec-Fetch-Site`. API clients can send `Authorization: Bearer <token>` (the token is returned by `POST /api/login`) instead of the cookie. Login attempts are rate-limited, and the password check runs the same hash work when the user does not exist.

`ANTBB_AUTH=0` does not disable a configured password.

### Non-root

Run the platform as a normal user. `deploy/antbb.service` sets `User=antbb` and `NoNewPrivileges=true`. The Dockerfile ends with `USER antbb`. Compose drops all capabilities and sets `no-new-privileges`.

The official entry points refuse to start as root. `ANTBB_ALLOW_ROOT=1` only logs a warning; do not use it for a real deployment.

Port 1001 does not need `cap_net_bind_service`. No extra capabilities are granted.

Monitor-mode WLAN capture needs a raw socket. That work is not done inside the web process. The existing path is a separate sudoers wrapper, and only after Oversight. The queens, API, and UI stay unprivileged.

Details and the unit file: [DEPLOY.md](DEPLOY.md).

## Usage

```bash
python -m api --host 127.0.0.1 --port 1001
```

`./run.sh` starts the colony UI through `install-and-start.sh` (port 8000 unless `ANTBB_PORT` is set). `python -m antbb.serve` is the same colony UI. `python -m api` is the unified All-and-One surface on port 1001.

Sign in at `http://127.0.0.1:1001/login`. Then:

1. Create a target and add allowlist entries. Empty scope denies every run.
2. Confirm Oversight on that target before any active step.
3. Start a colony. Light mode is the read-oriented path. Intensive mode still will not take offensive actions unless Oversight is set.
4. Read findings, history, and reports. Reports land under `data/reports/<queen>/` (gitignored).

Yellow standalone (`python -m yellow_queen`) uses the same bind rule (`YQ_HOST`, default `127.0.0.1`) and the same login. `YQ_EXPOSE=1` is the same opt-in as `ANTBB_EXPOSE=1`.

## Contributing

- Open a pull request. Do not force-push, and do not merge on the maintainer's behalf.
- Keep default-deny and Oversight intact. A change that skips either one will not be accepted.
- Do not commit `antbb.env`, tokens, packet captures, or real findings. `data/` stays gitignored.
- Run the tests from a virtualenv:

  ```bash
  .venv/bin/pip install -r requirements.txt pytest
  .venv/bin/pytest -q
  ```

- New web behavior needs a test for auth and for the loopback bind. See `tests/test_bind_and_auth.py`.
- Run a secret scan before you commit (`gitleaks detect --source . --no-banner`).

## Breaking changes for existing deployments

- The process **will not start** until `ANTBB_ADMIN_PASSWORD_HASH` or `ANTBB_ADMIN_PASSWORD` is set.
- The process **will not start as root** unless `ANTBB_ALLOW_ROOT=1`.
- Listen address defaults to **127.0.0.1**. A previous `0.0.0.0` or LAN bind stops working until `ANTBB_EXPOSE=1` is set on purpose.
- `ANTBB_AUTH` is no longer an off switch once a password is configured. Sessions are required.
- The documented service user is `antbb` and the directory is `/opt/antbb`. The meta endpoint reports `127.0.0.1`, not a LAN address.

## License

See [LICENSE](LICENSE). Built for authorized tests, your own lab, and defensive work.
