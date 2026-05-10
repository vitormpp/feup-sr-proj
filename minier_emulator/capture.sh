#!/usr/bin/env bash
set -uo pipefail

LABEL="${1:-capture}"
MODE="${2:-network}"

OUT_DIR="captures/${LABEL}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUT_DIR"

PROJECT="${COMPOSE_PROJECT_NAME:-minier_emulator}"

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

capture_networks() {
    for net in "${NETWORKS[@]}"; do
        full="${PROJECT}_${net}"

        net_id=$(docker network inspect "$full" -f '{{.Id}}' 2>/dev/null) || {
            echo "WARN: docker network '$full' not found"
            continue
        }

        bridge="br-${net_id:0:12}"
        out="${OUT_DIR}/${net}.pcap"

        echo "[NET] $bridge -> $out"

        sudo tcpdump -i "$bridge" \
            -w "$out" -U -n \
            >/dev/null 2>&1 &

        PIDS+=($!)
    done
}

capture_containers() {
    containers=$(docker ps --format '{{.Names}}')

    # bridge -> space-separated list of known IPs on that bridge
    declare -A bridge_known_ips=()

    for c in $containers; do

        networks=$(docker inspect \
            -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}' \
            "$c")

        for net in $networks; do

            net_id=$(docker network inspect "$net" \
                -f '{{.Id}}' 2>/dev/null) || continue

            bridge="br-${net_id:0:12}"

            ip=$(docker inspect \
                -f "{{with index .NetworkSettings.Networks \"$net\"}}{{.IPAddress}}{{end}}" \
                "$c")

            [ -z "$ip" ] && continue

            out="${OUT_DIR}/${c}.pcap"

            echo "[CT] $c ($ip) on $bridge -> $out"

            sudo tcpdump -i "$bridge" \
                "host $ip" \
                -w "$out" -U -n \
                >/dev/null 2>&1 &

            PIDS+=($!)

            # Accumulate this IP for the unknown-traffic filter on this bridge
            bridge_known_ips["$bridge"]+=" $ip"
        done
    done

    # For every bridge that had at least one container, also capture traffic
    # that does NOT match any known container IP into a separate file.
    for bridge in "${!bridge_known_ips[@]}"; do
        ips="${bridge_known_ips[$bridge]}"

        # Build a tcpdump filter: "not host <ip1> and not host <ip2> ..."
        filter=""
        for ip in $ips; do
            [ -n "$filter" ] && filter+=" and "
            filter+="not host $ip"
        done

        out="${OUT_DIR}/unknown_${bridge}.pcap"
        echo "[UNKNOWN] $bridge (filter: $filter) -> $out"

        sudo tcpdump -i "$bridge" \
            "$filter" \
            -w "$out" -U -n \
            >/dev/null 2>&1 &

        PIDS+=($!)
    done
}

case "$MODE" in
    network)
        capture_networks
        ;;
    container)
        capture_containers
        ;;
    *)
        echo "Unknown mode: $MODE"
        exit 1
        ;;
esac

if [ ${#PIDS[@]} -eq 0 ]; then
    echo "No captures started."
    exit 1
fi

echo "Capturing... Press Ctrl+C to stop."
wait