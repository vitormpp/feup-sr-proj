#!/usr/bin/env bash
# Capture rich network telemetry on every SEED docker bridge using Zeek.
# Runs Zeek as a docker container — no host install required (works on any
# Ubuntu version, including 20.04 which no longer has prebuilt zeek packages).
# Produces structured JSON logs (conn, dns, http, ssl, weird, notice, arp, ...)
# per network.
# Usage: sudo ./capture_zeek.sh [label]   e.g. sudo ./capture_zeek.sh baseline
# Stop with Ctrl+C. One log dir per network under captures_zeek/<label>_<ts>/<network>/.
set -uo pipefail

ZEEK_IMAGE="${ZEEK_IMAGE:-zeek/zeek:latest}"

if ! command -v docker >/dev/null 2>&1; then
    echo "docker not found." >&2
    exit 1
fi

LABEL="${1:-capture}"
OUT_DIR="$(pwd)/captures_zeek/${LABEL}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT_DIR"

PROJECT="${COMPOSE_PROJECT_NAME:-mini_emulator}"
NETWORKS=(net_160_net0 net_161_net0 net_162_net0 net_ix_ix103)

if ! sudo docker image inspect "$ZEEK_IMAGE" >/dev/null 2>&1; then
    echo "Pulling $ZEEK_IMAGE (one-time)..."
    sudo docker pull "$ZEEK_IMAGE" || {
        echo "Failed to pull $ZEEK_IMAGE. Override with ZEEK_IMAGE=<image> ./capture_zeek.sh" >&2
        exit 1
    }
fi

declare -a CONTAINERS=()

cleanup() {
    trap - INT TERM EXIT
    echo
    echo "Stopping captures (Zeek flushes final log records on shutdown)..."
    for c in "${CONTAINERS[@]}"; do
        sudo docker stop -t 5 "$c" >/dev/null 2>&1 || true
        sudo docker rm "$c" >/dev/null 2>&1 || true
    done

    # Collapse per-bridge logs: one file per bridge, all event types merged.
    # Each JSON record carries a `_path` field (conn/dns/weird/arp/...) so types stay distinguishable.
    echo "Merging per-bridge logs..."
    for sub in "$OUT_DIR"/*/; do
        [ -d "$sub" ] || continue
        bridge_name=$(basename "$sub")
        out_file="$OUT_DIR/${bridge_name}.log"
        for f in "$sub"*.log; do
            [ -e "$f" ] || continue
            cat "$f" >> "$out_file"
        done
        rm -rf "$sub"
    done

    # Restore ownership to the invoking user when running under sudo
    real_user="${SUDO_USER:-$(id -un)}"
    if [ -n "$real_user" ] && [ "$real_user" != "root" ]; then
        chown -R "$real_user:$real_user" "$OUT_DIR" 2>/dev/null || true
    fi
    echo "Zeek logs written to: $OUT_DIR"
}
trap cleanup INT TERM EXIT

for net in "${NETWORKS[@]}"; do
    full="${PROJECT}_${net}"
    net_id=$(sudo docker network inspect "$full" -f '{{.Id}}' 2>/dev/null) || {
        echo "WARN: docker network '$full' not found, skipping" >&2
        continue
    }
    bridge="br-${net_id:0:12}"
    log_dir="${OUT_DIR}/${net}"
    mkdir -p "$log_dir"
    cname="zeek_cap_${net}_$$"
    echo "[$net] $bridge -> $log_dir"
    # --net=host: container sees host bridges (br-XXXXX) directly
    # NET_ADMIN/NET_RAW: required for promiscuous capture
    # -C: skip checksum validation (virtual bridges often have offloaded checksums)
    # LogAscii::use_json=T: emit JSON — easier to feed into pandas / ML pipelines
    sudo docker run -d --name "$cname" \
        --net=host \
        --cap-add=NET_ADMIN --cap-add=NET_RAW \
        --security-opt seccomp=unconfined \
        --user 0 \
        -v "$log_dir":/logs \
        -w /logs \
        --entrypoint zeek \
        "$ZEEK_IMAGE" \
        -C -i "$bridge" \
        Log::default_logdir=/logs \
        LogAscii::use_json=T >/dev/null || {
            echo "WARN: failed to start zeek container for $net" >&2
            continue
        }
    CONTAINERS+=("$cname")
done

if [ ${#CONTAINERS[@]} -eq 0 ]; then
    echo "No captures started." >&2
    exit 1
fi

# Startup health-check: give Zeek 2s to either run or fail, then show logs for any that died
sleep 2
any_alive=0
for c in "${CONTAINERS[@]}"; do
    if [ "$(sudo docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null)" = "true" ]; then
        any_alive=1
    else
        echo "ERROR: container $c is not running. Logs:" >&2
        sudo docker logs "$c" 2>&1 | sed 's/^/    /' >&2
    fi
done
if [ "$any_alive" -eq 0 ]; then
    echo "All zeek containers exited. Aborting." >&2
    exit 1
fi

echo "Zeek capturing on ${#CONTAINERS[@]} bridges. Press Ctrl+C to stop."
sleep infinity
