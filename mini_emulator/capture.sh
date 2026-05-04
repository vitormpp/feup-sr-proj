#!/usr/bin/env bash
# Capture pcaps on every SEED docker bridge in parallel.
# Usage: sudo ./capture.sh [label]    e.g. sudo ./capture.sh baseline
# Stop with Ctrl+C. One pcap per network is written under captures/<label>_<ts>/.
set -uo pipefail

LABEL="${1:-capture}"
OUT_DIR="captures/${LABEL}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT_DIR"

PROJECT="${COMPOSE_PROJECT_NAME:-mini_emulator}"
NETWORKS=(net_160_net0 net_161_net0 net_162_net0 net_ix_ix103)

declare -a PIDS=()

cleanup() {
    echo
    echo "Stopping captures..."
    for pid in "${PIDS[@]}"; do
        sudo kill -INT "$pid" 2>/dev/null || true
    done
    wait 2>/dev/null
    echo "Pcaps written to: $OUT_DIR"
}
trap cleanup INT TERM EXIT

for net in "${NETWORKS[@]}"; do
    full="${PROJECT}_${net}"
    net_id=$(docker network inspect "$full" -f '{{.Id}}' 2>/dev/null) || {
        echo "WARN: docker network '$full' not found, skipping" >&2
        continue
    }
    bridge="br-${net_id:0:12}"
    out="${OUT_DIR}/${net}.pcap"
    echo "[$net] $bridge -> $out"
    sudo tcpdump -i "$bridge" -w "$out" -U -n >/dev/null 2>&1 &
    PIDS+=($!)
done

if [ ${#PIDS[@]} -eq 0 ]; then
    echo "No captures started." >&2
    exit 1
fi

echo "Capturing on ${#PIDS[@]} bridges. Press Ctrl+C to stop."
wait
