#!/usr/bin/env bash
# Entry point for the quic-interop-runner.
#
# Environment variables set by the runner (via docker-compose.yml):
#   ROLE            — "server" or "client"
#   TESTCASE        — e.g. handshake, transfer, retry, resumption, zerortt,
#                     http3, connectionmigration, keyupdate, chacha20,
#                     multiplexing, rebind
#   REQUESTS        — space-separated URLs for client to download
#                     Format: "https://server4:443/path ..."
#                     The server host and port are parsed from here.
#   SSLKEYLOGFILE   — where to write TLS key material (NSS key log format)
#   QLOGDIR         — directory for qlog output
#   CERTS           — directory containing cert.pem and priv.key (server role)

set -euo pipefail

ROLE="${ROLE:-server}"
TESTCASE="${TESTCASE:-handshake}"
SSLKEYLOGFILE="${SSLKEYLOGFILE:-/dev/null}"
QLOGDIR="${QLOGDIR:-/logs/qlog}"
CERT_DIR="${CERTS:-/certs}"

mkdir -p "${QLOGDIR}"

# ── Network setup (mirrors martenseemann/quic-network-simulator-endpoint's
#    /setup.sh).  Without this, Docker veth TX-checksum offloading leaves
#    partial/zero checksums in the packets, and NS3's forwarding breaks. ──────
echo "Setting up routes..."

# Disable TX checksum offloading so every outgoing packet gets a valid
# checksum before NS3 captures and forwards it.
ethtool -K eth0 tx off 2>/dev/null || true

# Route all 193.167.0.0/16 traffic (both leftnet + rightnet) via the local
# sim gateway (.2 of our own subnet).  This ensures the NS3 simulation sees
# every packet that crosses between client and server.
IP=$(hostname -I | cut -f1 -d" ")
GATEWAY="${IP%.*}.2"
UNNEEDED_ROUTE="${IP%.*}.0"
echo "Endpoint IPv4: ${IP}, gateway: ${GATEWAY}"
route add -net 193.167.0.0 netmask 255.255.0.0 gw "${GATEWAY}" 2>/dev/null || true
route del -net "${UNNEEDED_ROUTE}" netmask 255.255.255.0 2>/dev/null || true

# Flush any stale ARP cache entries in the NS3 network simulator.
#
# The NS3 sim container is kept alive across test cases, but the client and
# server containers are recreated for every test (new MAC addresses, same
# IPs).  Without a forced ARP exchange the sim's cached <IP → old-MAC>
# entry causes every packet from test N+1 onward to be delivered to the
# now-dead container from test N, so the server never receives the
# client's Initial packets.
#
# We send a real ARP REQUEST for the gateway's MAC address (not a
# gratuitous/self-addressed ARP).  Because the gateway is an NS3 router
# node, NS3 *must* process the request and send a reply — and as part of
# processing the inbound ARP request it caches the sender's IP→MAC mapping
# (our new container MAC).  This is more reliable than a gratuitous ARP
# (-U / -A) which some NS3 builds silently ignore.
#
# IMPORTANT: Keep this fast.  The NS3 sim waits only 10 s for server:443
# to become available; every second spent here is one less second the
# server has to complete its TLS handshake.  3 probes ≈ 3 s is sufficient
# for normal inter-test ARP refresh.  Tests that would contaminate the NS3
# ARP state via a 60 s timeout (http3, connectionmigration) are ordered
# AFTER the tests we care about in ci.yml — so stale-ARP recovery for the
# post-timeout case is not needed here.
arping -c 3 -I eth0 "${GATEWAY}" 2>/dev/null || true

# IPv6 equivalent
IPV6=$(hostname -I | cut -f2 -d" " 2>/dev/null || true)
if [[ -n "${IPV6}" && "${IPV6}" =~ ":" ]]; then
    GWV6="${IPV6%:*}:2"
    UNNEEDED_V6="${IPV6%:*}:"
    ip -d route add fd00:cafe:cafe::/48 via "${GWV6}" 2>/dev/null || true
    ip -d route del "${UNNEEDED_V6}/64" 2>/dev/null || true
fi

# Map test cases to feature flags understood by our binaries.
# Unknown or unsupported test cases exit 127 so the runner marks them "unsupported".
case "${TESTCASE}" in
    handshake|multiplexing|multiconnect)
        # quinn-interop negotiates h3 for HTTPS handshake/transfer tests.
        EXTRA_FLAGS=(--http3)
        ;;
    transfer)
        EXTRA_FLAGS=(--http09)
        ;;
    retry)
        EXTRA_FLAGS=(--retry)
        ;;
    resumption)
        EXTRA_FLAGS=(--resumption --http09)
        ;;
    zerortt)
        EXTRA_FLAGS=(--early-data --http09)
        ;;
    http3)
        EXTRA_FLAGS=(--http3)
        ;;
    connectionmigration)
        EXTRA_FLAGS=(--migrate --http09)
        ;;
    rebind)
        EXTRA_FLAGS=(--rebind --http09)
        ;;
    keyupdate)
        EXTRA_FLAGS=(--key-update --http09)
        ;;
    chacha20)
        EXTRA_FLAGS=(--chacha20 --http09)
        ;;
    v2)
        EXTRA_FLAGS=(--v2)
        ;;
    ecn)
        EXTRA_FLAGS=(--http09)
        ;;
    *)
        echo "Unknown TESTCASE: ${TESTCASE}" >&2
        exit 127
        ;;
esac

if [[ "${ROLE}" == "server" ]]; then
    exec zquic-server \
        --port 443 \
        --keylog "${SSLKEYLOGFILE}" \
        --qlog-dir "${QLOGDIR}" \
        "${EXTRA_FLAGS[@]}" \
        --cert "${CERT_DIR}/cert.pem" \
        --key  "${CERT_DIR}/priv.key" \
        --www  /www
else
    # Parse the server host and port from the first URL in REQUESTS.
    # The docker-compose does not set a SERVER env var for the client
    # container; the server address is encoded in the REQUESTS URLs.
    # URL format: https://server4:443/path
    HOST="server4"
    PORT="443"
    if [[ -n "${REQUESTS:-}" ]]; then
        FIRST_URL="${REQUESTS%% *}"         # take only the first URL
        HOSTPATH="${FIRST_URL#https://}"    # strip https://
        HOSTPORT="${HOSTPATH%%/*}"          # strip everything after the first /
        if [[ "${HOSTPORT}" == *:* ]]; then
            HOST="${HOSTPORT%:*}"
            PORT="${HOSTPORT##*:}"
        else
            HOST="${HOSTPORT}"
        fi
    fi

    # Build per-URL download flags.
    URL_FLAGS=()
    for url in ${REQUESTS:-}; do
        URL_FLAGS+=(--url "${url}")
    done

    # connectionmigration: when server is dual-stack "server46", client must migrate
    if [[ "${REQUESTS:-}" == *server46* ]]; then
        EXTRA_FLAGS+=(--migrate)
    fi

    exec zquic-client \
        --host "${HOST}" \
        --port "${PORT}" \
        --keylog "${SSLKEYLOGFILE}" \
        --qlog-dir "${QLOGDIR}" \
        "${EXTRA_FLAGS[@]}" \
        "${URL_FLAGS[@]}" \
        --output /downloads
fi
