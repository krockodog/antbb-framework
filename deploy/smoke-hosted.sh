#!/usr/bin/env bash
# Smoke test for a running hosted instance (ANTBB_HOSTED=1).
# Usage: ANTBB_TEST_PASSWORD='...' deploy/smoke-hosted.sh [base_url] [username]
# The password is read from the environment only, never from argv.
# The wrong-password test deliberately triggers the login rate limit for a
# throwaway username, not for the admin account.
set -u
BASE="${1:-http://127.0.0.1:1001}"
USER_NAME="${2:-admin}"
PASS="${ANTBB_TEST_PASSWORD:-}"
JAR="$(mktemp)"; trap 'rm -f "$JAR"' EXIT
fail=0
check() { # name expected actual
  if [[ "$3" == $2 ]]; then echo "OK   $1 ($3)"; else echo "FAIL $1: expected $2, got $3"; fail=1; fi
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

check "healthz public"            200 "$(code "$BASE/healthz")"
for p in / /red /blue /yellow /brain /wlan /api/queens /api/targets /api/meta; do
  check "unauth $p"               "@(302|303|401)" "$(code "$BASE$p")"
done
for p in /docs /openapi.json; do
  check "hidden $p" "@(401|404)" "$(code "$BASE$p")"
done
check "unauth POST /api/targets"  "@(401|403)" "$(code -X POST -H 'content-type: application/json' -d '{}' "$BASE/api/targets")"

H="$(curl -s -D - -o /dev/null "$BASE/login")"
for h in content-security-policy strict-transport-security x-frame-options x-content-type-options referrer-policy; do
  if grep -qi "^$h:" <<<"$H"; then echo "OK   header $h"; else echo "FAIL header $h missing"; fail=1; fi
done

# Wrong password: 401 first, then 429 once the per-user budget is used up.
last=""
for i in $(seq 1 12); do
  last="$(code -X POST -H "Origin: $BASE" --data-urlencode "username=ratelimit-probe" --data-urlencode "password=wrong-$i" "$BASE/api/login")"
done
check "wrong password rate-limited" 429 "$last"

check "cross-site login rejected" 403 "$(code -X POST -H 'Origin: https://evil.example' -H 'content-type: application/json' -d '{"username":"x","password":"y"}' "$BASE/api/login")"

if [[ -n "$PASS" ]]; then
  out="$(curl -s -c "$JAR" -D - -o /dev/null -X POST -H "Origin: $BASE" \
        --data-urlencode "username=$USER_NAME" --data-urlencode "password@-" "$BASE/login" < <(printf '%s' "$PASS"))"
  st="$(head -1 <<<"$out" | awk '{print $2}')"
  loc="$(grep -i '^location:' <<<"$out" | tr -d '\r' | awk '{print $2}')"
  check "login ok -> redirect" 303 "$st"
  check "login redirect target" "/" "$loc"
  if grep -i '^set-cookie: antbb_session' <<<"$out" | grep -qi 'secure' && grep -i '^set-cookie: antbb_session' <<<"$out" | grep -qi 'httponly' && grep -i '^set-cookie: antbb_session' <<<"$out" | grep -qi 'samesite=strict'; then
    echo "OK   session cookie Secure; HttpOnly; SameSite=Strict"
  else echo "FAIL session cookie flags"; fail=1; fi
  # curl's cookie jar does not resend Secure cookies over http://, so pass it explicitly.
  tok="$(awk '$6=="antbb_session"{print $7}' "$JAR")"
  for p in / /red /blue /yellow /brain /api/queens /api/meta; do
    check "auth $p" 200 "$(code -b "antbb_session=$tok" "$BASE$p")"
  done
  check "auth POST w/o origin (CSRF)" 403 "$(code -b "antbb_session=$tok" -X POST -H 'content-type: application/json' -d '{"name":"x"}' "$BASE/api/targets")"
  check "auth POST cross-site (CSRF)" 403 "$(code -b "antbb_session=$tok" -X POST -H 'Origin: https://evil.example' -H 'content-type: application/json' -d '{"name":"x"}' "$BASE/api/targets")"
  check "remote tunnel start blocked" 403 "$(code -b "antbb_session=$tok" -X POST -H "Origin: $BASE" -H 'content-type: application/json' -d '{}' "$BASE/api/remote/tunnel/start")"
else
  echo "SKIP login tests (ANTBB_TEST_PASSWORD not set)"
fi
exit $fail
