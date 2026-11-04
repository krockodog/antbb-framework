#!/usr/bin/env python3
"""Start the antbb web UI on 127.0.0.1 as an unprivileged user.

Binding anywhere else requires ANTBB_EXPOSE=1. A password hash is required.
"""
from antbb.serve import main

if __name__ == "__main__":
    main()
