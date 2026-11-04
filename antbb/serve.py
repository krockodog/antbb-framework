"""Official entry point for the antbb web UI.

``python -m antbb.serve`` binds 127.0.0.1, refuses root, and refuses to
start when no admin credential is configured. ``python -m api`` serves the
unified All-and-One app on port 1001 through the same checks.
"""
from __future__ import annotations

import argparse
import os
import sys


def main(argv: list[str] | None = None) -> None:
    from antbb.netbind import assert_runtime_safe

    parser = argparse.ArgumentParser(prog="antbb.serve")
    parser.add_argument("--app", default="antbb.web.app:app")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    args = parser.parse_args(argv)

    host = assert_runtime_safe(args.host)
    port = args.port
    if port is None:
        raw = os.environ.get("ANTBB_PORT") or os.environ.get("ANTBB_WEB_PORT") or os.environ.get("ALLONE_PORT") or "8000"
        port = int(raw)
    os.environ["ANTBB_SERVE"] = "1"
    os.environ["ANTBB_HOST"] = host
    # A non-loopback opt-in must stay visible in the process environment
    # so the request guard and the launcher agree.
    print(f"[antbb] listening on http://{host}:{port}", file=sys.stderr)
    import uvicorn

    uvicorn.run(args.app, host=host, port=port, reload=False)


if __name__ == "__main__":
    main()
