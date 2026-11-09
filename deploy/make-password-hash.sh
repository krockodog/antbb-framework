#!/usr/bin/env bash
# Prints a pbkdf2_sha256 hash for ANTBB_ADMIN_PASSWORD_HASH.
# The password is asked without echo and never passed as an argument.
#   deploy/make-password-hash.sh            # uses the built image (docker compose)
#   deploy/make-password-hash.sh --local    # uses python3 in this checkout
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${1:-}" == "--local" ]]; then
  exec python3 -m antbb.webauth hash-password
fi
# antbb.env may not exist yet (compose requires it), so use plain docker.
image="antbb-allone:hosted"
docker image inspect "$image" >/dev/null 2>&1 || docker build -t "$image" .
exec docker run --rm -it --network none "$image" python -m antbb.webauth hash-password
