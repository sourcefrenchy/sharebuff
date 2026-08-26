#!/usr/bin/env bash
# Local end-to-end smoke test: start the fallback server, post a secret with
# the CLI, then exercise the full claim lifecycle via the browser-equivalent
# node client (tests/e2e.mjs).
set -euo pipefail
cd "$(dirname "$0")/.."

ADDR=127.0.0.1:8391
./sharebuff-server -addr "$ADDR" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 1

PLAINTEXT='hello from the E2E test — été 🔐'
OUT=$(printf '%s' "$PLAINTEXT" | ./sharebuff --server "http://$ADDR" 2>/dev/null)
URL=$(echo "$OUT" | awk '/^URL:/{print $2}')
PIN=$(echo "$OUT" | awk '/^PIN:/{print $2}')

echo "-- wrong PIN must not burn (403)"
node tests/e2e.mjs "$URL" "AAAAAA" --expect-status 403
echo "-- immediate retry hits the cooldown (429, uncounted)"
node tests/e2e.mjs "$URL" "AAAAAA" --expect-status 429
sleep 3
echo "-- correct PIN retrieves and decrypts"
GOT=$(node tests/e2e.mjs "$URL" "$PIN")
[ "$GOT" = "$PLAINTEXT" ] || { echo "PLAINTEXT MISMATCH"; exit 1; }
echo "-- second claim finds a tombstone (410)"
node tests/e2e.mjs "$URL" "$PIN" --expect-status 410
echo "E2E OK"
