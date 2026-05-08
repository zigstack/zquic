#!/usr/bin/env bash
#
# Quick local comparative benchmark (no Docker required).
#
# Builds each implementation from source on the host machine, then runs
# loopback throughput tests.  Ideal for fast iteration on macOS/Linux.
#
# Prerequisites:
#   - zquic: Zig 0.16+
#   - quiche: Rust toolchain (cargo)
#   - ngtcp2: cmake, autoconf, automake, libtool, pkg-config
#   - openssl (for cert generation)
#
# Usage:
#   bash bench/local_compare.sh                        # zquic only
#   bash bench/local_compare.sh zquic quiche           # compare two
#   bash bench/local_compare.sh zquic quiche ngtcp2    # compare three
#   SIZE_MB=100 RUNS=5 bash bench/local_compare.sh     # custom params

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

SIZE_MB="${SIZE_MB:-10}"
RUNS="${RUNS:-3}"
PORT="${PORT:-14433}"
IMPLS=("${@:-zquic}")

# Temp dirs
TMP=$(mktemp -d /tmp/zquic_bench.XXXXXX)
CERT="${TMP}/cert.pem"
KEY="${TMP}/priv.key"
WWW="${TMP}/www"
DL="${TMP}/downloads"
RESULTS="${TMP}/results.txt"
mkdir -p "${WWW}" "${DL}"

cleanup() {
    # Kill any leftover server processes.
    for pid_file in "${TMP}"/*.pid; do
        [ -f "$pid_file" ] && kill "$(cat "$pid_file")" 2>/dev/null || true
    done
    rm -rf "${TMP}"
}
trap cleanup EXIT

# ── Generate cert ────────────────────────────────────────────────────────────

echo "Generating TLS certificate..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "${KEY}" -out "${CERT}" -days 1 -nodes \
    -subj "/CN=localhost" 2>/dev/null

# ── Generate test file ───────────────────────────────────────────────────────

TESTFILE="${WWW}/bench.bin"
echo "Creating ${SIZE_MB} MB test file..."
dd if=/dev/urandom of="${TESTFILE}" bs=1048576 count="${SIZE_MB}" 2>/dev/null

EXPECTED_BYTES=$((SIZE_MB * 1048576))

# ── Build implementations ────────────────────────────────────────────────────

BINS_DIR="${TMP}/bins"
mkdir -p "${BINS_DIR}"

build_zquic() {
    echo "  Building zquic..."
    (cd "${PROJECT_ROOT}" && zig build -Doptimize=ReleaseFast 2>&1) || {
        echo "  ⚠ zquic build failed"; return 1
    }
    cp "${PROJECT_ROOT}/zig-out/bin/server" "${BINS_DIR}/zquic-server"
    cp "${PROJECT_ROOT}/zig-out/bin/client" "${BINS_DIR}/zquic-client"
}

build_quiche() {
    echo "  Building quiche (this may take a few minutes)..."
    local QUICHE_DIR="${QUICHE_SRC:-${TMP}/quiche}"
    if [ ! -d "${QUICHE_DIR}" ]; then
        git clone --recursive --depth 1 https://github.com/cloudflare/quiche.git "${QUICHE_DIR}" 2>/dev/null
    fi
    (cd "${QUICHE_DIR}" && cargo build --release --package quiche_apps 2>&1) || {
        echo "  ⚠ quiche build failed"; return 1
    }
    cp "${QUICHE_DIR}/target/release/quiche-server" "${BINS_DIR}/"
    cp "${QUICHE_DIR}/target/release/quiche-client" "${BINS_DIR}/"
}

build_ngtcp2() {
    echo "  Building ngtcp2 (this may take several minutes)..."
    local BUILD="${TMP}/ngtcp2_build"
    mkdir -p "${BUILD}"

    # Build quictls/openssl
    if [ ! -d "${BUILD}/openssl" ]; then
        git clone --depth 1 https://github.com/quictls/openssl.git "${BUILD}/openssl" 2>/dev/null
        (cd "${BUILD}/openssl" && \
            ./config --prefix="${BUILD}/local" --openssldir="${BUILD}/local" && \
            make -j"$(nproc 2>/dev/null || sysctl -n hw.logicalcpu)" && \
            make install_sw) 2>&1 || { echo "  ⚠ openssl build failed"; return 1; }
    fi

    # Build nghttp3
    if [ ! -d "${BUILD}/nghttp3" ]; then
        git clone --recursive --depth 1 https://github.com/ngtcp2/nghttp3.git "${BUILD}/nghttp3" 2>/dev/null
        (cd "${BUILD}/nghttp3" && autoreconf -fi && \
            ./configure --prefix="${BUILD}/local" --enable-lib-only \
                PKG_CONFIG_PATH="${BUILD}/local/lib64/pkgconfig:${BUILD}/local/lib/pkgconfig" && \
            make -j"$(nproc 2>/dev/null || sysctl -n hw.logicalcpu)" && make install) 2>&1 || {
            echo "  ⚠ nghttp3 build failed"; return 1
        }
    fi

    # Build ngtcp2 (cmake to get example binaries)
    if [ ! -d "${BUILD}/ngtcp2" ]; then
        git clone --recursive --depth 1 https://github.com/ngtcp2/ngtcp2.git "${BUILD}/ngtcp2" 2>/dev/null
    fi
    if [ ! -f "${BUILD}/ngtcp2/build/examples/qtlsserver" ]; then
        local LIBEV_PREFIX="/opt/homebrew"
        [ -d "/usr/local/include/ev.h" ] && LIBEV_PREFIX="/usr/local"
        (cd "${BUILD}/ngtcp2" && mkdir -p build && cd build && \
            cmake -DCMAKE_INSTALL_PREFIX="${BUILD}/local" \
                -DCMAKE_PREFIX_PATH="${BUILD}/local;${LIBEV_PREFIX}" \
                -DENABLE_OPENSSL=ON \
                -DENABLE_EXAMPLES=ON \
                .. && \
            make -j"$(nproc 2>/dev/null || sysctl -n hw.logicalcpu)") 2>&1 || {
            echo "  ⚠ ngtcp2 build failed"; return 1
        }
    fi

    cp "${BUILD}/ngtcp2/build/examples/qtlsserver" "${BINS_DIR}/ngtcp2-server" 2>/dev/null || true
    cp "${BUILD}/ngtcp2/build/examples/qtlsclient" "${BINS_DIR}/ngtcp2-client" 2>/dev/null || true
}

echo ""
echo "Building implementations..."
for impl in "${IMPLS[@]}"; do
    "build_${impl}" || { echo "Skipping ${impl} (build failed)"; }
done

# ── Run benchmarks ───────────────────────────────────────────────────────────

start_server() {
    local impl="$1"
    case "${impl}" in
        zquic)
            "${BINS_DIR}/zquic-server" --port "${PORT}" --cert "${CERT}" \
                --key "${KEY}" --www "${WWW}" --http09 &
            ;;
        quiche)
            "${BINS_DIR}/quiche-server" --listen "127.0.0.1:${PORT}" \
                --cert "${CERT}" --key "${KEY}" --root "${WWW}" \
                --no-retry &
            ;;
        ngtcp2)
            DYLD_LIBRARY_PATH="${TMP}/ngtcp2_build/local/lib:${DYLD_LIBRARY_PATH:-}" \
            LD_LIBRARY_PATH="${TMP}/ngtcp2_build/local/lib64:${TMP}/ngtcp2_build/local/lib:${LD_LIBRARY_PATH:-}" \
                "${BINS_DIR}/ngtcp2-server" '*' "${PORT}" \
                "${KEY}" "${CERT}" -d "${WWW}" -q &
            ;;
        *)
            echo "Unknown impl: ${impl}"; return 1
            ;;
    esac
    echo $! > "${TMP}/${impl}_server.pid"
    sleep 0.5  # let server bind
}

stop_server() {
    local impl="$1"
    local pidfile="${TMP}/${impl}_server.pid"
    if [ -f "${pidfile}" ]; then
        kill "$(cat "${pidfile}")" 2>/dev/null || true
        wait "$(cat "${pidfile}")" 2>/dev/null 3>/dev/null || true
        rm -f "${pidfile}"
    fi
} 2>/dev/null

run_client() {
    local impl="$1"
    rm -rf "${DL}"/*
    case "${impl}" in
        zquic)
            "${BINS_DIR}/zquic-client" --host localhost --port "${PORT}" \
                --url "https://localhost:${PORT}/bench.bin" \
                --output "${DL}" --http09
            ;;
        quiche)
            "${BINS_DIR}/quiche-client" --no-verify \
                --dump-responses "${DL}" \
                "https://127.0.0.1:${PORT}/bench.bin"
            ;;
        ngtcp2)
            DYLD_LIBRARY_PATH="${TMP}/ngtcp2_build/local/lib:${DYLD_LIBRARY_PATH:-}" \
            LD_LIBRARY_PATH="${TMP}/ngtcp2_build/local/lib64:${TMP}/ngtcp2_build/local/lib:${LD_LIBRARY_PATH:-}" \
                "${BINS_DIR}/ngtcp2-client" localhost "${PORT}" \
                "https://localhost:${PORT}/bench.bin" \
                --download "${DL}" --exit-on-first-stream-close -q
            ;;
    esac
}

echo ""
echo "============================================================"
echo "  zquic comparative benchmark (local)"
echo "============================================================"
echo "  file size      : ${SIZE_MB} MB"
echo "  runs           : ${RUNS}"
echo "  implementations: ${IMPLS[*]}"
echo ""

# Header for results file
echo "impl,run,elapsed_s,throughput_mbps,bytes,status" > "${RESULTS}"

for impl in "${IMPLS[@]}"; do
    # Check binary exists
    case "${impl}" in
        zquic)   [ -x "${BINS_DIR}/zquic-server" ] || { echo "⚠ ${impl} not built, skipping"; continue; } ;;
        quiche)  [ -x "${BINS_DIR}/quiche-server" ] || { echo "⚠ ${impl} not built, skipping"; continue; } ;;
        ngtcp2)  [ -x "${BINS_DIR}/ngtcp2-server" ] || { echo "⚠ ${impl} not built, skipping"; continue; } ;;
    esac

    for run in $(seq 1 "${RUNS}"); do
        printf "  %-12s run %d/%d ... " "${impl}" "${run}" "${RUNS}"

        # Clean download directory before each run.
        rm -rf "${DL:?}"/*

        start_server "${impl}" >/dev/null 2>&1

        # Time the client transfer using perl for sub-second precision.
        T0=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')
        run_client "${impl}" >/dev/null 2>&1
        rc=$?
        T1=$(perl -MTime::HiRes=time -e 'printf "%.6f\n", time')

        stop_server "${impl}"

        ELAPSED=$(python3 -c "print(f'{${T1} - ${T0}:.3f}')")

        # Check download
        DL_FILE="${DL}/bench.bin"
        if [ -f "${DL_FILE}" ]; then
            RECV_BYTES=$(wc -c < "${DL_FILE}" | tr -d ' ')
        else
            RECV_BYTES=0
        fi

        if [ "${RECV_BYTES}" -eq "${EXPECTED_BYTES}" ] && [ "${rc}" -eq 0 ]; then
            TP=$(python3 -c "print(f'{${RECV_BYTES} * 8 / (${ELAPSED} * 1e6):.1f}')")
            echo "${TP} Mbps (${ELAPSED}s)"
            echo "${impl},${run},${ELAPSED},${TP},${RECV_BYTES},OK" >> "${RESULTS}"
        else
            echo "FAILED (${RECV_BYTES}/${EXPECTED_BYTES} bytes, exit=${rc})"
            echo "${impl},${run},${ELAPSED},0,${RECV_BYTES},FAIL" >> "${RESULTS}"
        fi
    done
done

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  Summary (${SIZE_MB} MB transfer, ${RUNS} runs each)"
echo "============================================================"
printf "  %-15s %12s %12s %12s\n" "Implementation" "Avg Mbps" "Avg Time" "Success"
echo "  -----------------------------------------------------------"

for impl in "${IMPLS[@]}"; do
    python3 -c "
import csv, sys
rows = [r for r in csv.DictReader(open('${RESULTS}')) if r['impl'] == '${impl}']
ok = [r for r in rows if r['status'] == 'OK']
if ok:
    avg_tp = sum(float(r['throughput_mbps']) for r in ok) / len(ok)
    avg_t  = sum(float(r['elapsed_s']) for r in ok) / len(ok)
    print(f'  {\"${impl}\":<15} {avg_tp:>10.1f}   {avg_t:>10.2f}s   {len(ok)}/{len(rows)}')
else:
    print(f'  {\"${impl}\":<15} {\"   -\":>12} {\"   -\":>12}   0/{len(rows)}')
"
done

echo ""
echo "Raw results: ${RESULTS}"
echo ""
