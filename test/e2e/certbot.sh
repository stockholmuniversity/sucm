#!/usr/bin/env bash
# Level 1 smoke with a real client. Credentials come from the state dir (outside the repo):
#   ${ACME_STATE_DIR:-~/.config/sucm-acme-tester}/tester.env
# certbot's own config dir (incl. its account key) is persisted in <state dir>/certbot, because the
# server binds an EAB kid to the first account key it sees.
# Works as a non-root user and ignores any existing /etc/letsencrypt or ~/.config/letsencrypt config.
set -euo pipefail

STATE="${ACME_STATE_DIR:-$HOME/.config/sucm-acme-tester}"
if [ -f "$STATE/tester.env" ]; then
  set -a; . "$STATE/tester.env"; set +a
fi
: "${ACME_DIRECTORY:?}" "${ACME_EAB_KID:?}" "${ACME_EAB_HMAC_KEY:?}" "${ACME_TEST_DOMAIN:?}"

umask 077
mkdir -p "$STATE/certbot"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Empty cli.ini replaces the default cli.ini locations so a broken host setup cannot interfere.
: > "$WORK/cli.ini"

# The server is trust-based (no challenge round-trip), so the manual auth hook is a no-op.
certbot certonly \
  --config "$WORK/cli.ini" \
  --server "$ACME_DIRECTORY" \
  --eab-kid "$ACME_EAB_KID" --eab-hmac-key "$ACME_EAB_HMAC_KEY" \
  --manual --preferred-challenges http --manual-auth-hook /bin/true \
  --register-unsafely-without-email --agree-tos --non-interactive --force-renewal \
  -d "$ACME_TEST_DOMAIN" \
  --config-dir "$STATE/certbot" --work-dir "$WORK/w" --logs-dir "$WORK/l"

openssl x509 -in "$STATE/certbot/live/$ACME_TEST_DOMAIN/cert.pem" -noout -subject -issuer -enddate
echo "certbot level1: OK"
