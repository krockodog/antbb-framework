# Demo

All and One - RED-BLUE-Yellow-Ant-Team

This is a local, authorized-scope walkthrough. It does not open the console on the network.

1. Create a password hash and put it in `antbb.env` (mode 600). There is no default password.

   ```bash
   python -m antbb.webauth hash-password
   ```

2. Start the unified UI on loopback, as your normal user (not root):

   ```bash
   python -m api --host 127.0.0.1 --port 1001
   ```

3. Open `http://127.0.0.1:1001`, sign in, and confirm `GET /api/health` answers without a session.
4. Add a target, add an allowlist entry, and confirm Oversight before any active step.
5. Leave the scope empty and confirm a run does not start. That is default-deny.

Roles in the demo: Red-Teaming, Blue Safety-Teaming, Yellow Reverse-Teaming.
Full deployment notes: [DEPLOY.md](DEPLOY.md). Narrative: [README.md](README.md).
