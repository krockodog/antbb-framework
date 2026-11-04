"""Unified All-and-One surface. Loopback, authenticated, unprivileged."""
from __future__ import annotations

import os
import sys


def main() -> None:
    os.environ.setdefault(
        "ANTBB_PORT",
        os.environ.get("ALLONE_PORT", "1001"),
    )
    if os.environ.get("ALLONE_HOST") and not os.environ.get("ANTBB_HOST"):
        os.environ["ANTBB_HOST"] = os.environ["ALLONE_HOST"]
    forwarded = [arg for arg in sys.argv[1:] if arg != "--app"]
    sys.argv = [sys.argv[0], "--app", "api.main:app", "--port", os.environ["ANTBB_PORT"], *forwarded]
    from antbb.serve import main as serve_main

    serve_main()


if __name__ == "__main__":
    main()
