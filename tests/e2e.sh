#!/usr/bin/env bash
# Local end-to-end smoke test: start the fallback server, post secrets with
# the CLI (text via stdin, text via clipboard on macOS, binary file), then
# exercise the full claim lifecycle via the browser-equivalent node client.
set -euo pipefail
cd "$(dirname "$0")/.."

ADDR=127.0.0.1:8391
SERVER_URL="http://$ADDR"
TMP=$(mktemp -d)
./sharebuff-server -addr "$ADDR" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true; rm -rf "$TMP"' EXIT
sleep 1

post() { ./sharebuff --server "$SERVER_URL" "$@" 2>/dev/null; }
geturl() { echo "$1" | awk '/^URL:/{print $2}'; }
getpin() { echo "$1" | awk '/^PIN:/{print $2}'; }

echo "== text mode (stdin) =="
PLAINTEXT='hello from the E2E test — été 🔐'
OUT=$(printf '%s' "$PLAINTEXT" | post)
URL=$(geturl "$OUT"); PIN=$(getpin "$OUT")
CODE=${URL#*#}; NORM=$(printf "%s" "$CODE" | tr -d "-")
[ ${#NORM} -eq 13 ] || { echo "default tier should be tiny (13 chars), got ${#NORM}: $CODE"; exit 1; }
echo "-- default tier is tiny: $CODE"
[ "$(printf "%s" "$PIN" | tr -cd "-" | wc -c | tr -d " ")" -eq 2 ] || { echo "default PIN should be 3 dash-joined words, got: $PIN"; exit 1; }
echo "-- default PIN is 3 words: $PIN"
echo "-- wrong PIN must not burn (403)"
node tests/e2e.mjs "$URL" "AAAAAA" --expect-status 403
echo "-- immediate retry hits the cooldown (429, uncounted)"
node tests/e2e.mjs "$URL" "AAAAAA" --expect-status 429
sleep 3
echo "-- correct PIN retrieves and decrypts (typed with spaces and capitals)"
TYPEDPIN=$(printf "%s" "$PIN" | tr "-" " " | tr "a-z" "A-Z")
GOT=$(node tests/e2e.mjs "$URL" "$TYPEDPIN")
[ "$GOT" = "$PLAINTEXT" ] || { echo "PLAINTEXT MISMATCH"; exit 1; }
echo "-- second claim finds a tombstone (410)"
node tests/e2e.mjs "$URL" "$PIN" --expect-status 410

for TIER in tiny short full; do
  echo "== --$TIER link, typed by hand (lowercase, no dashes, o/l for 0/1) =="
  OUT=$(printf "%s tier payload" "$TIER" | post --$TIER)
  URL=$(geturl "$OUT"); PIN=$(getpin "$OUT")
  CODE=${URL#*#}
  NORM=$(printf "%s" "$CODE" | tr -d "-")
  WANT=13; [ "$TIER" = short ] && WANT=31; [ "$TIER" = full ] && WANT=57
  [ ${#NORM} -eq $WANT ] || { echo "$TIER code has ${#NORM} chars, want $WANT: $CODE"; exit 1; }
  TYPED=$(printf "%s" "$CODE" | tr "A-Z" "a-z" | tr -d "-" | tr "01" "ol")
  GOT=$(node tests/e2e.mjs "${URL%%#*}#$TYPED" "$(printf "%s" "$PIN" | tr "A-Z" "a-z")")
  [ "$GOT" = "$TIER tier payload" ] || { echo "TYPED-CODE MISMATCH ($TIER): $GOT"; exit 1; }
  echo "-- $CODE typed as $TYPED: OK"
done

if [ "$(uname)" = "Darwin" ]; then
  echo "== text mode (clipboard via pbcopy/pbpaste) =="
  CLIPTEXT="clipboard payload $$ été"
  SAVED=$(pbpaste 2>/dev/null || true)
  printf '%s' "$CLIPTEXT" | pbcopy
  OUT=$(post --clip < /dev/null)
  printf '%s' "$SAVED" | pbcopy   # restore the user's clipboard
  URL=$(geturl "$OUT"); PIN=$(getpin "$OUT")
  GOT=$(node tests/e2e.mjs "$URL" "$PIN")
  [ "$GOT" = "$CLIPTEXT" ] || { echo "CLIPBOARD MISMATCH"; exit 1; }
fi

echo "== file mode (3 MiB binary, byte-exact) =="
head -c 3145728 /dev/urandom > "$TMP/blob.pdf"
OUT=$(post --file "$TMP/blob.pdf")
URL=$(geturl "$OUT"); PIN=$(getpin "$OUT")
node tests/e2e.mjs "$URL" "$PIN" > "$TMP/blob.out" 2> "$TMP/blob.info"
grep -q '"t":"file"' "$TMP/blob.info" && grep -q '"n":"blob.pdf"' "$TMP/blob.info" \
  || { echo "FILE HEADER MISSING: $(cat "$TMP/blob.info")"; exit 1; }
H1=$(shasum -a 256 "$TMP/blob.pdf" | cut -d' ' -f1)
H2=$(shasum -a 256 "$TMP/blob.out" | cut -d' ' -f1)
[ "$H1" = "$H2" ] || { echo "FILE HASH MISMATCH"; exit 1; }
echo "-- sha256 match ($H1)"
echo "-- file secret is one-shot too (410)"
node tests/e2e.mjs "$URL" "$PIN" --expect-status 410

echo "== oversize file is rejected locally =="
head -c $((20*1024*1024+1)) /dev/zero > "$TMP/toobig.bin"
if ./sharebuff --server "$SERVER_URL" --file "$TMP/toobig.bin" 2>"$TMP/err.txt"; then
  echo "OVERSIZE ACCEPTED"; exit 1
fi
grep -qi "limit" "$TMP/err.txt" || { echo "unexpected error: $(cat "$TMP/err.txt")"; exit 1; }

echo "E2E OK"
