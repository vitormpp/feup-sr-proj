#!/usr/bin/env bash
# =============================================================================
# train_model.sh  —  Capture normal traffic from the SEED emulator and train
#                    an Isolation Forest outlier-detection model.
#
# Usage:
#   sudo ./train_model.sh [OPTIONS]
#
# Options:
#   -d  DIR     Working / output directory          (default: ./training_run_<ts>)
#   -t  SECS    How long to capture traffic          (default: 120)
#   -p  FILE    Path to save the trained model       (default: <DIR>/model.pkl)
#   -c  FILE    Path to docker-compose file          (default: ./docker-compose.yml)
#   -s          Skip docker-compose up (containers already running)
#   -h          Show this help
#
# Requirements (host):
#   docker, docker compose (v2) or docker-compose (v1), tcpdump, python3
#   Python packages: nfstream, scikit-learn, pandas, joblib
#   Install deps:  pip install nfstream scikit-learn pandas joblib
#
# What it does:
#   1. docker compose up -d          (starts the emulator)
#   2. Discover the four br-XXXX bridge interfaces for the compose networks
#   3. tcpdump on each bridge -> merged single capture.pcap
#   4. python3 train_outlier_model.py  (NFStream features + IsolationForest)
#   5. Saves  model.pkl  and  scaler.pkl  ready for later inference
# =============================================================================
set -euo pipefail

# --------------------------------------------------------------------------- #
#  Defaults
# --------------------------------------------------------------------------- #
CAPTURE_SECS=120
COMPOSE_FILE="./docker-compose.yml"
PROJECT_NAME="mini_emulator"
SKIP_UP=0
TS=$(date +%Y%m%d_%H%M%S)
WORK_DIR="./training_run_${TS}"
MODEL_PATH=""   # filled in after WORK_DIR is known, unless overridden by -p

NETWORKS=(net_160_net0 net_161_net0 net_162_net0 net_ix_ix103)

# --------------------------------------------------------------------------- #
#  Argument parsing
# --------------------------------------------------------------------------- #
usage() {
    grep '^#' "$0" | sed 's/^# \{0,2\}//' | head -30
    exit 0
}

while getopts "d:t:p:c:sh" opt; do
    case $opt in
        d) WORK_DIR="$OPTARG" ;;
        t) CAPTURE_SECS="$OPTARG" ;;
        p) MODEL_PATH="$OPTARG" ;;
        c) COMPOSE_FILE="$OPTARG" ;;
        s) SKIP_UP=1 ;;
        h) usage ;;
        *) echo "Unknown option -$OPTARG" >&2; exit 1 ;;
    esac
done

[[ -z "$MODEL_PATH" ]] && MODEL_PATH="${WORK_DIR}/model.pkl"

# --------------------------------------------------------------------------- #
#  Sanity checks
# --------------------------------------------------------------------------- #
require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found on PATH." >&2; exit 1; }; }
require_cmd docker
require_cmd tcpdump
require_cmd python3

# Resolve the invoking user's home directory (works correctly under sudo)
REAL_USER="${SUDO_USER:-$(id -un)}"
REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)

# Use venv python if available, otherwise fall back to system python3
VENV_PYTHON="${REAL_HOME}/venv/bin/python3"
if [[ -x "$VENV_PYTHON" ]]; then
    PYTHON_CMD="$VENV_PYTHON"
    echo "  Using venv Python: $PYTHON_CMD"
else
    PYTHON_CMD="python3"
    echo "  venv not found at $VENV_PYTHON — using system python3"
fi

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (sudo) so tcpdump can capture on bridge interfaces." >&2
    exit 1
fi

# Detect compose command (v2 plugin preferred, fall back to v1 standalone)
if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    COMPOSE_CMD="docker-compose"
else
    echo "ERROR: Neither 'docker compose' (plugin) nor 'docker-compose' (standalone) found." >&2
    exit 1
fi

[[ -f "$COMPOSE_FILE" ]] || { echo "ERROR: Compose file not found: $COMPOSE_FILE" >&2; exit 1; }

mkdir -p "$(dirname "$MODEL_PATH")"
mkdir -p "$WORK_DIR"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TRAIN_SCRIPT="${SCRIPT_DIR}/train_outlier_model.py"
[[ -f "$TRAIN_SCRIPT" ]] || { echo "ERROR: Python training script not found: $TRAIN_SCRIPT" >&2; exit 1; }

echo "================================================================"
echo "  SEED Emulator — Normal-traffic capture + model training"
echo "================================================================"
echo "  Compose file : $COMPOSE_FILE"
echo "  Working dir  : $WORK_DIR"
echo "  Capture time : ${CAPTURE_SECS}s"
echo "  Model output : $MODEL_PATH"
echo "  Python       : $PYTHON_CMD"
echo "================================================================"

# --------------------------------------------------------------------------- #
#  Step 1 — Bring up the emulator
# --------------------------------------------------------------------------- #
if [[ $SKIP_UP -eq 0 ]]; then
    echo
    echo "[1/4] Starting containers  (docker compose up -d)..."
    $COMPOSE_CMD -f "$COMPOSE_FILE" -p "$PROJECT_NAME" up -d --build
    echo "      Giving containers 15 s to fully initialize..."
    sleep 15
else
    echo "[1/4] Skipping docker compose up (-s flag set)."
fi

# --------------------------------------------------------------------------- #
#  Step 2 — Resolve bridge interface names
# --------------------------------------------------------------------------- #
echo
echo "[2/4] Resolving bridge interfaces for compose networks..."

declare -a BRIDGE_IFACES=()
for net in "${NETWORKS[@]}"; do
    full="${PROJECT_NAME}_${net}"
    net_id=$(docker network inspect "$full" -f '{{.Id}}' 2>/dev/null) || {
        echo "  WARN: docker network '$full' not found — skipping." >&2
        continue
    }
    bridge="br-${net_id:0:12}"
    # Verify the interface actually exists on the host
    if ip link show "$bridge" >/dev/null 2>&1; then
        echo "  $net  ->  $bridge"
        BRIDGE_IFACES+=("$bridge")
    else
        echo "  WARN: bridge interface $bridge not found on host (network $full)" >&2
    fi
done

if [[ ${#BRIDGE_IFACES[@]} -eq 0 ]]; then
    echo "ERROR: No bridge interfaces found. Are the containers running?" >&2
    exit 1
fi

# --------------------------------------------------------------------------- #
#  Step 3 — Capture traffic with tcpdump across all bridges
# --------------------------------------------------------------------------- #
echo
echo "[3/4] Capturing traffic for ${CAPTURE_SECS}s on ${#BRIDGE_IFACES[@]} bridge(s)..."

PCAP_DIR="${WORK_DIR}/pcaps"
mkdir -p "$PCAP_DIR"

declare -a TCPDUMP_PIDS=()
declare -a PCAP_FILES=()

for bridge in "${BRIDGE_IFACES[@]}"; do
    pcap_file="${PCAP_DIR}/${bridge}.pcap"
    PCAP_FILES+=("$pcap_file")
    # -s0: full snaplen  |  -Z root: don't drop privs  |  -w: write pcap
    tcpdump -i "$bridge" -s 0 -Z root -w "$pcap_file" -q 2>/dev/null &
    TCPDUMP_PIDS+=($!)
    echo "  tcpdump PID $!  ->  $pcap_file"
done

# Wait for the capture window
echo "  Capturing for ${CAPTURE_SECS}s... (Ctrl+C to abort)"
sleep "$CAPTURE_SECS"

# Stop all tcpdump processes gracefully
echo "  Stopping tcpdump processes..."
for pid in "${TCPDUMP_PIDS[@]}"; do
    kill -SIGTERM "$pid" 2>/dev/null || true
done
# Give them a moment to flush
sleep 2
for pid in "${TCPDUMP_PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
done

# Merge per-bridge pcaps into one file using tcpdump itself
# (mergecap from wireshark-common is preferred but may not be installed)
MERGED_PCAP="${WORK_DIR}/capture.pcap"
echo "  Merging ${#PCAP_FILES[@]} pcap file(s) -> $MERGED_PCAP"

if command -v mergecap >/dev/null 2>&1; then
    mergecap -w "$MERGED_PCAP" "${PCAP_FILES[@]}"
else
    # Fallback: concatenate with tcpdump (strips duplicate global headers)
    # Use -r on first file to keep header, then append raw packets from others
    echo "  (mergecap not found — using tcpdump concatenation fallback)"
    FIRST=1
    for pf in "${PCAP_FILES[@]}"; do
        [[ -s "$pf" ]] || continue
        if [[ $FIRST -eq 1 ]]; then
            cp "$pf" "$MERGED_PCAP"
            FIRST=0
        else
            # Skip the 24-byte global pcap header and append packet data
            tail -c +25 "$pf" >> "$MERGED_PCAP"
        fi
    done
fi

PCAP_SIZE=$(du -sh "$MERGED_PCAP" 2>/dev/null | cut -f1)
echo "  Merged pcap: $MERGED_PCAP  ($PCAP_SIZE)"

# --------------------------------------------------------------------------- #
#  Step 4 — Feature extraction + model training
# --------------------------------------------------------------------------- #
echo
echo "[4/4] Running NFStream feature extraction + Isolation Forest training..."
echo "  Script : $TRAIN_SCRIPT"
echo "  Input  : $MERGED_PCAP"
echo "  Output : $MODEL_PATH"
echo

SCALER_PATH="${MODEL_PATH%.pkl}_scaler.pkl"
FEATURES_CSV="${WORK_DIR}/features.csv"

# Run the python training script using the resolved venv/system python
$PYTHON_CMD "$TRAIN_SCRIPT" \
    --pcap       "$MERGED_PCAP"  \
    --model-out  "$MODEL_PATH"   \
    --scaler-out "$SCALER_PATH"  \
    --features-csv "$FEATURES_CSV"

# Fix ownership back to invoking user
if [[ -n "$REAL_USER" && "$REAL_USER" != "root" ]]; then
    chown -R "${REAL_USER}:${REAL_USER}" "$WORK_DIR" 2>/dev/null || true
    chown "${REAL_USER}:${REAL_USER}" "$MODEL_PATH"  2>/dev/null || true
    chown "${REAL_USER}:${REAL_USER}" "$SCALER_PATH" 2>/dev/null || true
fi

echo
echo "================================================================"
echo "  Done!"
echo "  Capture    : $MERGED_PCAP"
echo "  Features   : $FEATURES_CSV"
echo "  Model      : $MODEL_PATH"
echo "  Scaler     : $SCALER_PATH"
echo "================================================================"
echo
echo "  To load the model later in Python:"
echo "    import joblib"
echo "    model  = joblib.load('$MODEL_PATH')"
echo "    scaler = joblib.load('$SCALER_PATH')"
echo "    # score_samples returns negative anomaly scores (lower = more anomalous)"
echo "    scores = model.score_samples(scaler.transform(X_new))"