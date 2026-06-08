#!/usr/bin/env bash
# Run P0 cross-impl interop tests locally (matches CI matrix).
# Requires: zig, docker, python 3.12+, quic-interop-runner checkout.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNNER="${QUIC_INTEROP_RUNNER:-/Users/partha/projects/zig/zquic/quic-interop-runner}"
LOG_ROOT="${1:-/tmp/zquic-cross-impl-local}"
CROSS_P0="handshake,transfer,multiplexing"

# Match CI: linux target for Docker. On Apple Silicon use aarch64; on Intel/CI use x86_64.
ARCH="$(uname -m)"
if [[ "$ARCH" == "arm64" ]]; then
  ZIG_TARGET="aarch64-linux-gnu"
else
  ZIG_TARGET="x86_64-linux-gnu"
fi

echo "==> Building zquic for ${ZIG_TARGET}..."
cd "$ROOT"
zig build -Doptimize=ReleaseFast -Dtarget="${ZIG_TARGET}" -Dcpu=baseline
zig build test --summary all

echo "==> Building zquic:interop Docker image..."
docker build -f interop/Dockerfile.prebuilt -t zquic:interop .

if [[ ! -d "$RUNNER/.venv" ]]; then
  echo "==> Creating interop runner venv..."
  (cd "$RUNNER" && uv venv .venv && uv pip install -r requirements.txt)
fi

# Match CI: bump interop runner timeouts (upstream default is 60s).
(cd "$RUNNER" && python3 - <<'EOF'
import pathlib

base = pathlib.Path("testcase.py")
src = base.read_text()
old = '    def timeout() -> int:\n        """timeout in s"""\n        return 60\n'
new = '    def timeout() -> int:\n        """timeout in s"""\n        return 180\n'
if old in src:
    base.write_text(src.replace(old, new, 1))
    print("Patched TestCase.timeout() -> 180s")

mux = pathlib.Path("testcases_quic.py")
msrc = mux.read_text()
needle = '        return "Thousands of files are transferred over a single connection, and server increased stream limits to accomodate client requests."\n\n    def get_paths_raw(self):'
insert = (
    '        return "Thousands of files are transferred over a single connection, and server increased stream limits to accomodate client requests."\n\n'
    "    @staticmethod\n"
    "    def timeout() -> int:\n"
    "        return 480\n\n"
    "    def get_paths_raw(self):"
)
if needle in msrc and "class TestCaseMultiplexing" in msrc:
    mux.write_text(msrc.replace(needle, insert, 1))
    print("Patched TestCaseMultiplexing.timeout() -> 480s")
EOF
)

PY="$RUNNER/.venv/bin/python"
mkdir -p "$LOG_ROOT"

run_suite() {
  local client="$1" server="$2" tag="$3"
  echo ""
  echo "==> ${client} -> ${server} (${tag})"
  "$PY" "$RUNNER/run.py" \
    --client "$client" \
    --server "$server" \
    --test "$CROSS_P0" \
    --log-dir "$LOG_ROOT/logs-${tag}" \
    --json "$LOG_ROOT/results-${tag}.json" \
    || return 1
}

FAILED=0
run_suite quinn zquic cross-quinn-zquic || FAILED=1
run_suite zquic quinn cross-zquic-quinn || FAILED=1

echo ""
if [[ "$FAILED" -eq 0 ]]; then
  echo "All cross-impl P0 tests passed."
else
  echo "Some cross-impl P0 tests failed — logs in ${LOG_ROOT}"
  exit 1
fi
