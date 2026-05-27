#!/usr/bin/env bash
# =============================================================================
# capture_full.sh — Comprehensive packet capture for the SEED emulator.
#
# The default bridge-based capture (capture.sh) misses intra-network L2
# traffic (ARP, broadcast, locally-switched unicast) because the Linux bridge
# tap doesn't always deliver locally-forwarded frames to the host.
#
# This script fixes that by:
#   1.  Running tcpdump inside every container's network namespace (via
#       nsenter) on each of its eth interfaces.  This guarantees we see
#       every packet the container sees, including ARP requests/replies.
#   2.  Grouping the per-container pcaps by Docker network.
#   3.  Merging + deduplicating per-network so the final output has one
#       pcap per network with no repeated packets.
#   4.  Optionally producing a single merged pcap of all networks.
#
# Usage:
#   sudo ./capture_full.sh [label]
#   sudo ./capture_full.sh baseline          # label = "baseline"
#   sudo CAPTURE_SECS=120 ./capture_full.sh  # auto-stop after 120s
#
# Environment variables:
#   CAPTURE_SECS        — if set, auto-stop after this many seconds
#                         (default: empty = run until Ctrl+C)
#   COMPOSE_PROJECT_NAME — compose project name (default: mini_emulator)
#   SNAPLEN             — tcpdump snap length   (default: 0 = full packet)
#
# Outputs:  captures_full/<label>_<timestamp>/
#               <network>.pcap        — deduplicated per-network pcap
#               merged.pcap           — all networks merged (optional)
#               raw/                  — per-container raw pcaps (kept for debug)
#
# Stop with Ctrl+C.
# =============================================================================
set -uo pipefail

# ─────────────────────────────────────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────────────────────────────────────
LABEL="${1:-capture}"
TS="$(date +%Y%m%d_%H%M%S)"
OUT_DIR="$(pwd)/captures_full/${LABEL}_${TS}"
RAW_DIR="${OUT_DIR}/raw"
mkdir -p "$RAW_DIR"

PROJECT="${COMPOSE_PROJECT_NAME:-mini_emulator}"
SNAPLEN="${SNAPLEN:-0}"
CAPTURE_SECS="${CAPTURE_SECS:-}"

# Docker network names from the compose topology
NETWORKS=(net_160_net0 net_161_net0 net_162_net0 net_ix_ix103)

# ─────────────────────────────────────────────────────────────────────────────
#  Sanity checks
# ─────────────────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (sudo)." >&2
    exit 1
fi

for cmd in docker tcpdump nsenter editcap mergecap; do
    command -v "$cmd" >/dev/null 2>&1 || {
        echo "ERROR: '$cmd' not found. Install wireshark-common:" >&2
        echo "  sudo apt-get install wireshark-common" >&2
        exit 1
    }
done

# ─────────────────────────────────────────────────────────────────────────────
#  Discover containers and their network memberships
# ─────────────────────────────────────────────────────────────────────────────
echo "================================================================"
echo "  SEED Emulator — Full packet capture (per-container nsenter)"
echo "================================================================"
echo "  Label     : $LABEL"
echo "  Output    : $OUT_DIR"
echo "  Snap len  : ${SNAPLEN:-0 (full)}"
[[ -n "$CAPTURE_SECS" ]] && echo "  Duration  : ${CAPTURE_SECS}s (auto-stop)" \
                         || echo "  Duration  : until Ctrl+C"
echo "================================================================"
echo

# Build a mapping: container_id -> network_name -> interface_name
# We inspect each compose network to find which containers are attached.

declare -A CONTAINER_PID=()    # container_id -> PID (namespace)
declare -A CONTAINER_NAME=()   # container_id -> human name
declare -a CAPTURE_JOBS=()     # "pid:pcap_file:network" tuples
declare -a ALL_PIDS=()

# For each network, find all attached containers and their interface indices
for net in "${NETWORKS[@]}"; do
    full="${PROJECT}_${net}"
    echo "[net] Inspecting $full ..."

    # Get the network's containers via docker network inspect
    container_ids=$(docker network inspect "$full" \
        --format '{{range $k,$v := .Containers}}{{$k}} {{end}}' 2>/dev/null) || {
        echo "  WARN: network '$full' not found, skipping." >&2
        continue
    }

    for cid in $container_ids; do
        # Skip very short IDs (shouldn't happen, but guard)
        [[ ${#cid} -lt 12 ]] && continue

        # Get container name and PID
        cname=$(docker inspect "$cid" --format '{{.Name}}' 2>/dev/null | sed 's|^/||')
        cpid=$(docker inspect "$cid" --format '{{.State.Pid}}' 2>/dev/null)

        if [[ -z "$cpid" || "$cpid" == "0" ]]; then
            echo "  WARN: container $cname ($cid) not running, skipping." >&2
            continue
        fi

        CONTAINER_PID["$cid"]="$cpid"
        CONTAINER_NAME["$cid"]="$cname"

        # Find the interface name inside the container's namespace for this network.
        # Strategy: list all eth* interfaces inside the namespace.
        # For containers on multiple networks, Docker creates eth0, eth1, etc.
        # We enumerate them all per container (deduplicated later).

        ifaces=$(nsenter -t "$cpid" -n ip -o link show 2>/dev/null \
            | grep -oP '(?<=: )\S+(?=@)' \
            | grep -v '^lo$' || true)

        if [[ -z "$ifaces" ]]; then
            # Fallback: try without the @... suffix pattern
            ifaces=$(nsenter -t "$cpid" -n ip -o link show 2>/dev/null \
                | awk -F': ' '{print $2}' \
                | awk '{print $1}' \
                | grep -v '^lo$' || true)
        fi

        for iface in $ifaces; do
            # Determine which network this iface belongs to by matching the IP
            iface_ip=$(nsenter -t "$cpid" -n ip -4 -o addr show dev "$iface" 2>/dev/null \
                | grep -oP 'inet \K[0-9.]+' || true)

            # Match IP to network subnet
            matched_net=""
            case "$iface_ip" in
                10.160.0.*) matched_net="net_160_net0" ;;
                10.161.0.*) matched_net="net_161_net0" ;;
                10.162.0.*) matched_net="net_162_net0" ;;
                10.103.0.*) matched_net="net_ix_ix103" ;;
                *)          matched_net="unknown_${iface_ip}" ;;
            esac

            # Sanitise container name for filenames
            safe_name=$(echo "$cname" | tr '/:. ' '____')
            pcap_file="${RAW_DIR}/${matched_net}__${safe_name}__${iface}.pcap"

            # Avoid duplicate captures (same container+iface already queued)
            dup_key="${cpid}:${iface}"
            if printf '%s\n' "${CAPTURE_JOBS[@]}" 2>/dev/null | grep -qF "$dup_key"; then
                continue
            fi

            echo "  [+] $cname ($iface, $iface_ip) -> $matched_net"

            # Launch tcpdump inside the container's network namespace
            nsenter -t "$cpid" -n \
                tcpdump -i "$iface" -s "$SNAPLEN" -w "$pcap_file" -U -n -q 2>/dev/null &
            cap_pid=$!
            ALL_PIDS+=("$cap_pid")
            CAPTURE_JOBS+=("${cap_pid}:${pcap_file}:${matched_net}:${dup_key}")
        done
    done
done

if [[ ${#ALL_PIDS[@]} -eq 0 ]]; then
    echo "ERROR: No captures started. Are the containers running?" >&2
    exit 1
fi

echo
echo "Capturing on ${#ALL_PIDS[@]} interfaces across ${#CONTAINER_PID[@]} containers."

# ─────────────────────────────────────────────────────────────────────────────
#  Wait for capture to finish
# ─────────────────────────────────────────────────────────────────────────────
cleanup() {
    trap - INT TERM EXIT
    echo
    echo "Stopping ${#ALL_PIDS[@]} capture(s)..."
    for pid in "${ALL_PIDS[@]}"; do
        kill -INT "$pid" 2>/dev/null || true
    done
    # Give tcpdump a moment to flush
    sleep 2
    for pid in "${ALL_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    # ─────────────────────────────────────────────────────────────────────
    #  Merge + deduplicate per network
    # ─────────────────────────────────────────────────────────────────────
    echo
    echo "Merging and deduplicating per-network pcaps..."

    # Collect pcap files per network
    declare -A NET_PCAPS=()
    for job in "${CAPTURE_JOBS[@]}"; do
        IFS=':' read -r _pid pcap_file net_name _dup <<< "$job"
        if [[ -s "$pcap_file" ]]; then
            NET_PCAPS["$net_name"]+=" $pcap_file"
        fi
    done

    declare -a FINAL_PCAPS=()
    for net_name in "${!NET_PCAPS[@]}"; do
        files=(${NET_PCAPS[$net_name]})
        out_pcap="${OUT_DIR}/${net_name}.pcap"

        if [[ ${#files[@]} -eq 1 ]]; then
            # Only one capture for this network — just copy it
            cp "${files[0]}" "$out_pcap"
            echo "  $net_name: 1 source -> $out_pcap"
        else
            # Multiple captures — merge chronologically, then deduplicate
            merged_tmp="${OUT_DIR}/.merged_${net_name}.pcap"
            mergecap -w "$merged_tmp" "${files[@]}"

            # editcap -d: remove packets with identical content within a 1μs window
            editcap -d "$merged_tmp" "$out_pcap"
            dups_info=$(editcap -d "$merged_tmp" /dev/null 2>&1 | tail -1 || true)
            echo "  $net_name: ${#files[@]} sources merged+deduped -> $out_pcap  $dups_info"

            rm -f "$merged_tmp"
        fi
        FINAL_PCAPS+=("$out_pcap")
    done

    # Create a single merged pcap of all networks
    if [[ ${#FINAL_PCAPS[@]} -gt 1 ]]; then
        merged_all="${OUT_DIR}/merged.pcap"
        mergecap -w "$merged_all" "${FINAL_PCAPS[@]}"
        echo "  All networks merged -> $merged_all"
    fi

    # Fix ownership
    real_user="${SUDO_USER:-$(id -un)}"
    if [[ -n "$real_user" && "$real_user" != "root" ]]; then
        chown -R "${real_user}:${real_user}" "$OUT_DIR" 2>/dev/null || true
    fi

    echo
    echo "================================================================"
    echo "  Capture complete!"
    echo "  Output directory : $OUT_DIR"
    echo "  Per-network pcaps:"
    for f in "$OUT_DIR"/*.pcap; do
        [[ -e "$f" ]] || continue
        sz=$(du -sh "$f" 2>/dev/null | cut -f1)
        echo "    $(basename "$f")  ($sz)"
    done
    echo "  Raw per-container pcaps: $RAW_DIR/"
    echo "================================================================"
}
trap cleanup INT TERM EXIT

if [[ -n "$CAPTURE_SECS" ]]; then
    echo "Auto-stopping in ${CAPTURE_SECS}s..."
    sleep "$CAPTURE_SECS"
else
    echo "Press Ctrl+C to stop."
    # Wait for any child — sleep infinity is cleaner than 'wait' here because
    # we want the trap to fire on Ctrl+C, not on tcpdump exits.
    sleep infinity &
    SLEEP_PID=$!
    wait "$SLEEP_PID" 2>/dev/null || true
fi