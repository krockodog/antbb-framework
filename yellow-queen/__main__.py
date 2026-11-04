"""Yellow Queen standalone server. Loopback unless YQ_EXPOSE/ANTBB_EXPOSE=1."""
from __future__ import annotations

import os
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


def main() -> None:
    import uvicorn

    from antbb.netbind import assert_runtime_safe
    from yellow_queen.config import PORT

    if os.environ.get("YQ_EXPOSE") and not os.environ.get("ANTBB_EXPOSE"):
        os.environ["ANTBB_EXPOSE"] = os.environ["YQ_EXPOSE"]
    host = assert_runtime_safe(os.environ.get("YQ_HOST"))
    print(
        f"[yellow-queen] listening on http://{host}:{PORT} "
        "(override with YQ_HOST / YQ_PORT; non-loopback needs ANTBB_EXPOSE=1)",
        file=sys.stderr,
    )
    os.environ["ANTBB_SERVE"] = "1"
    uvicorn.run("yellow_queen.web.app:app", host=host, port=PORT, log_level="info")


if __name__ == "__main__":
    main()
