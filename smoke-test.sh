#!/usr/bin/env bash
# Local smoke test: signs a fake event with HS_WEBHOOK_SECRET the way Help Scout
# would, POSTs it to the shim, and prints the HTTP status.
#
# Run from the project dir on the Hermes box AFTER `docker compose up -d --build`.
#
#   200 -> shim verified HS SHA1, re-signed SHA256, Hermes accepted and ran the
#          agent. Confirm a run fired for conversation 99999 in the gateway logs.
#   401 -> signature mismatch. If the shim logs "bad Help Scout signature", the
#          HS_WEBHOOK_SECRET here differs from the running container's. If the 401
#          came from Hermes, WEBHOOK_SECRET in .env != Hermes's global secret.
#   502 -> Hermes webhook adapter isn't listening on 8644 (not enabled / not
#          restarted).
set -euo pipefail

cd "$(dirname "$0")"

SHIM_URL="${SHIM_URL:-http://127.0.0.1:9100/hs}"
SECRET="$(grep '^HS_WEBHOOK_SECRET=' .env | cut -d= -f2)"

if [ -z "$SECRET" ]; then
  echo "HS_WEBHOOK_SECRET is empty in .env -- fill it before smoke testing." >&2
  exit 1
fi

BODY='{"id":99999,"subject":"Smoke test ticket","status":"active"}'
SIG="$(printf '%s' "$BODY" | openssl dgst -sha1 -hmac "$SECRET" -binary | base64)"

echo "POST $SHIM_URL"
CODE="$(curl -s -o /dev/stderr -w '%{http_code}\n' -X POST "$SHIM_URL" \
  -H "Content-Type: application/json" \
  -H "X-HelpScout-Signature: $SIG" \
  -H "X-HelpScout-Event: convo.created" \
  -d "$BODY")"
echo "HTTP $CODE"
