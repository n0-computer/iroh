#!/usr/bin/env bash
#
# End-to-end test for iroh-relay multi-hostname ACME support against a local
# pebble ACME server, exercising real TLS-ALPN-01 challenge validation.
#
# Starts pebble, then iroh-relay in LetsEncrypt cert mode pointed at pebble via
# IROH_RELAY_ACME_URL / IROH_RELAY_ACME_CA, and checks with curl that:
#   - every configured hostname is served a cert signed by pebble's CA,
#   - an unconfigured hostname is refused at the TLS handshake, and
#   - pebble actually completed a challenge (no PEBBLE_VA_ALWAYS_VALID).
#
# pebble's validation authority resolves each hostname and connects back to the
# relay's TLS-ALPN-01 responder. Two things make that callback reach the relay:
# pebble's validation TLS port is set to the relay's HTTPS port, and an
# /etc/hosts mounted into the pebble container maps each hostname to 127.0.0.1
# (pebble reads it through its system resolver, so no separate DNS server is
# needed). Host networking lets pebble's loopback reach the relay's listener.
#
# Exits 0 if all checks pass, 1 otherwise.
#
# Requirements: docker (Linux host networking), curl, jq, the iroh-relay sources.

set -euo pipefail

PEBBLE_IMAGE="${PEBBLE_IMAGE:-ghcr.io/letsencrypt/pebble:latest}"
RELAY_HTTP_PORT="${RELAY_HTTP_PORT:-8080}"
RELAY_HTTPS_PORT="${RELAY_HTTPS_PORT:-8443}"

# The workdir is always a fresh mktemp directory, never taken from the
# environment. This is what keeps cleanup safe: nothing here can ever delete a
# path the user supplied, no matter how the environment is set. The pebble
# container name is derived from it, so a run never force-removes a container it
# did not create.
WORK="$(mktemp -d "${TMPDIR:-/tmp}/iroh-relay-pebble.XXXXXXXX")"
PEBBLE_NAME="${PEBBLE_NAME:-$(basename "$WORK")}"

# Reject non-numeric ports so a bad value cannot leak into the generated config
# or the jq program further down.
case "${RELAY_HTTP_PORT}:${RELAY_HTTPS_PORT}" in
    *[!0-9:]*) echo "RELAY_HTTP_PORT and RELAY_HTTPS_PORT must be numeric" >&2; exit 1 ;;
esac

# Hostnames the relay is configured to serve, plus one it is not.
HOSTS=(relay-a.localhost relay-b.localhost)
HOST_BAD=relay-evil.localhost

PEBBLE_DIR_URL="https://localhost:14000/dir"
PEBBLE_MGMT_URL="https://localhost:15000"

log() { printf '\n=== %s ===\n' "$*"; }
ok()  { printf '  [ ok ] %s\n' "$*"; }
fail() {
    printf '\n  [FAIL] %s\n' "$*" >&2
    [ -f "$WORK/relay.log" ] && { echo "--- relay.log (tail) ---" >&2; tail -n 30 "$WORK/relay.log" >&2; }
    docker logs "$PEBBLE_NAME" >/dev/null 2>&1 && { echo "--- pebble.log (tail) ---" >&2; docker logs "$PEBBLE_NAME" 2>&1 | tail -20 >&2; }
    exit 1
}

RELAY_PID=""
cleanup() {
    set +e
    [ -n "$RELAY_PID" ] && kill "$RELAY_PID" 2>/dev/null
    docker rm -f "$PEBBLE_NAME" >/dev/null 2>&1
}
trap cleanup EXIT

# curl the relay over HTTPS for a given hostname. --fail turns a non-2xx or TLS
# error into a non-zero exit; --resolve pins the SNI hostname to loopback.
curl_relay() {
    curl -s --fail --max-time 5 -o /dev/null \
        --cacert "$WORK/pebble-issuer-root.pem" \
        --resolve "$1:${RELAY_HTTPS_PORT}:127.0.0.1" \
        "https://$1:${RELAY_HTTPS_PORT}/healthz"
}

# --- start pebble ------------------------------------------------------------

mkdir -p "$WORK/certs"

{ echo "127.0.0.1 localhost"; echo "::1 localhost"
  for host in "${HOSTS[@]}"; do echo "127.0.0.1 $host"; done; } > "$WORK/hosts"

log "starting pebble ($PEBBLE_IMAGE)"
# Derive pebble's config from the image default, setting its TLS-ALPN-01
# validation port to the relay's HTTPS port so the callback lands on the relay.
cid=$(docker create "$PEBBLE_IMAGE")
docker cp "$cid:/test/config/pebble-config.json" "$WORK/pebble-config.in.json" >/dev/null
docker rm "$cid" >/dev/null
jq ".pebble.tlsPort = ${RELAY_HTTPS_PORT}" "$WORK/pebble-config.in.json" > "$WORK/pebble-config.json"

docker run -d --rm --name "$PEBBLE_NAME" --network host \
    -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
    -v "$WORK/pebble-config.json:/pebble-config.json:ro" \
    -v "$WORK/hosts:/etc/hosts:ro" \
    "$PEBBLE_IMAGE" -config /pebble-config.json >/dev/null

for i in $(seq 1 30); do
    curl -sk -o /dev/null "$PEBBLE_DIR_URL" && break
    [ "$i" = 30 ] && fail "pebble did not come up"
    sleep 0.5
done
ok "pebble up (validation port = ${RELAY_HTTPS_PORT})"

# pebble.minica.pem signs pebble's own ACME/management TLS, so the relay must
# trust it (IROH_RELAY_ACME_CA). The certs pebble *issues* chain to a separate
# root served by the management interface, which curl needs to verify the relay.
docker cp "$PEBBLE_NAME:/test/certs/pebble.minica.pem" "$WORK/pebble.minica.pem" >/dev/null
curl -s --cacert "$WORK/pebble.minica.pem" "$PEBBLE_MGMT_URL/roots/0" -o "$WORK/pebble-issuer-root.pem"
ok "fetched pebble CAs"

# --- start relay -------------------------------------------------------------

hostnames=$(printf '"%s", ' "${HOSTS[@]}")
cat > "$WORK/relay.toml" <<EOF
enable_relay = true
enable_quic_addr_discovery = false
enable_metrics = false
http_bind_addr = "0.0.0.0:${RELAY_HTTP_PORT}"

[tls]
https_bind_addr = "0.0.0.0:${RELAY_HTTPS_PORT}"
hostname = [ ${hostnames%, } ]
cert_mode = "LetsEncrypt"
contact = "test@iroh.test"
cert_dir = "${WORK}/certs"
EOF

log "starting iroh-relay (hostnames: ${HOSTS[*]})"
IROH_RELAY_ACME_URL="$PEBBLE_DIR_URL" \
IROH_RELAY_ACME_CA="$WORK/pebble.minica.pem" \
RUST_LOG="${RUST_LOG:-iroh_relay=debug,rustls_acme=info,warn}" \
    cargo run --quiet --bin iroh-relay --features server -- \
    --config-path "$WORK/relay.toml" > "$WORK/relay.log" 2>&1 &
RELAY_PID=$!

# --- checks ------------------------------------------------------------------

log "waiting for the relay to pass validation and provision a cert"
for i in $(seq 1 90); do
    kill -0 "$RELAY_PID" 2>/dev/null || fail "relay exited early"
    curl_relay "${HOSTS[0]}" 2>/dev/null && break
    [ "$i" = 90 ] && fail "relay did not provision a cert in time"
    sleep 1
done
ok "relay provisioned a cert"

log "every configured hostname serves a pebble-signed cert"
for host in "${HOSTS[@]}"; do
    curl_relay "$host" || fail "$host: expected a valid pebble-signed cert"
    ok "$host: served a pebble-signed cert, verified by curl"
done

log "an unconfigured hostname is refused"
curl_relay "$HOST_BAD" 2>/dev/null && fail "$HOST_BAD: handshake unexpectedly succeeded"
ok "$HOST_BAD: TLS handshake refused, as expected"

log "pebble ran a real challenge validation"
docker logs "$PEBBLE_NAME" 2>&1 | grep -q "set VALID by completed challenge" \
    || fail "pebble recorded no completed challenge (was validation skipped?)"
docker logs "$PEBBLE_NAME" 2>&1 | grep -E "set VALID by completed challenge|Issued certificate" | tail -4
ok "pebble validated the TLS-ALPN-01 challenge and issued the cert"

log "ALL CHECKS PASSED"
echo "artifacts (logs, certs, config) left in $WORK"
