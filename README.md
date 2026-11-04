# All and One - RED-BLUE-Yellow-Ant-Team

ANTBB is a self-hosted platform for **authorized** security work. Three queens share one process:

| Queen | Role | What it does |
|---|---|---|
| **Red** | Red-Teaming | Bug bounty and pentest inside an allowlist. Findings need evidence. |
| **Blue** | Blue Safety-Teaming | Hardening, posture, and remediation with before/after evidence. |
| **Yellow** | Yellow Reverse-Teaming | Reverse engineering of samples you are allowed to analyze. |

The German manual is [README.de.md](README.de.md). This file is the English overview.

Unauthorized probing of other people's systems is a crime (German StGB § 202a–c; the US CFAA). The notice on every page does not replace a human decision.

## Safety model

These controls are on by default and this change does not weaken them:

1. **Authorized scope only.** You name the systems you are allowed to test.
2. **Default-deny.** An empty allowlist means no target and no run. Wildcards are rejected.
3. **Oversight.** Active or offensive steps (verification, proof-of-concept, fixes, tunnels, wireless actions) wait for a human confirmation. The legal text is not that confirmation.
4. **Defensive default.** Reads and posture checks run without switching the platform into an offensive mode.
5. **Non-destructive find-and-prove.** A finding is verified only with evidence. Anything the tool cannot do is reported as such, not invented.
6. **No secrets in findings.** Cracked material is masked and is not stored.

## Install

Linux, Python 3.11+, and git. Node 20 is only needed to rebuild the hub.

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
