#!/usr/bin/env bash
# merge_pcaps.sh — Merge all .pcap/.pcapng files in a directory into one file
# Usage: ./merge_pcaps.sh [OPTIONS] <input_dir> [output_file]
#
# Dependencies: mergecap (part of Wireshark/tshark)
#   Install: sudo apt install wireshark-common   (Debian/Ubuntu)
#            sudo dnf install wireshark           (Fedora/RHEL)
#            brew install wireshark               (macOS)

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
OUTPUT_FILE=""
RECURSIVE=false
SORT_BY_TIME=true
VERBOSE=false

# ── Helpers ─────────────────────────────────────────────────────────────────
usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS] <input_dir> [output_file]

Merges all pcap/pcapng files in <input_dir> into a single capture file.

Arguments:
  input_dir     Directory containing .pcap / .pcapng / .cap files
  output_file   Output file path (default: <input_dir>/merged.pcapng)

Options:
  -r            Recurse into subdirectories
  -n            Do NOT sort packets by timestamp (faster, preserves file order)
  -o <file>     Output file (alternative to positional argument)
  -v            Verbose output
  -h            Show this help and exit

Examples:
  $(basename "$0") ./captures
  $(basename "$0") -r ./captures merged_all.pcapng
  $(basename "$0") -n -o result.pcapng ./captures
EOF
  exit 0
}

log() { [[ "$VERBOSE" == true ]] && echo "[INFO] $*" || true; }
err() { echo "[ERROR] $*" >&2; exit 1; }

# ── Argument parsing ─────────────────────────────────────────────────────────
while getopts ":rno:vh" opt; do
  case $opt in
    r) RECURSIVE=true ;;
    n) SORT_BY_TIME=false ;;
    o) OUTPUT_FILE="$OPTARG" ;;
    v) VERBOSE=true ;;
    h) usage ;;
    :) err "Option -$OPTARG requires an argument." ;;
    \?) err "Unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))

[[ $# -lt 1 ]] && usage

INPUT_DIR="${1%/}"   # strip trailing slash
[[ -d "$INPUT_DIR" ]] || err "Input directory not found: $INPUT_DIR"

# Second positional arg overrides -o if both provided
if [[ $# -ge 2 && -z "$OUTPUT_FILE" ]]; then
  OUTPUT_FILE="$2"
fi
OUTPUT_FILE="${OUTPUT_FILE:-$INPUT_DIR/merged.pcapng}"

# ── Dependency check ─────────────────────────────────────────────────────────
if ! command -v mergecap &>/dev/null; then
  err "mergecap not found. Install it with:
  Debian/Ubuntu : sudo apt install wireshark-common
  Fedora/RHEL   : sudo dnf install wireshark
  macOS (Brew)  : brew install wireshark"
fi

# ── Collect files ────────────────────────────────────────────────────────────
declare -a PCAP_FILES=()

declare -a FIND_CMD=(find "$INPUT_DIR")
[[ "$RECURSIVE" == false ]] && FIND_CMD+=(-maxdepth 1)
FIND_CMD+=(-type f \( -iname "*.pcap" -o -iname "*.pcapng" -o -iname "*.cap" \) -print0)

while IFS= read -r -d '' f; do
  # Skip the output file itself if it already lives in the input dir
  [[ "$(realpath "$f")" == "$(realpath "$OUTPUT_FILE" 2>/dev/null)" ]] && continue
  PCAP_FILES+=("$f")
done < <("${FIND_CMD[@]}" 2>/dev/null | sort -z)

FILE_COUNT=${#PCAP_FILES[@]}

if [[ $FILE_COUNT -eq 0 ]]; then
  err "No pcap/pcapng/cap files found in: $INPUT_DIR"
fi

echo "Found $FILE_COUNT capture file(s) to merge."
log "Output → $OUTPUT_FILE"

if [[ "$VERBOSE" == true ]]; then
  for f in "${PCAP_FILES[@]}"; do
    log "  $f"
  done
fi

# ── Merge ────────────────────────────────────────────────────────────────────
MERGECAP_ARGS=()
[[ "$SORT_BY_TIME" == true ]] && MERGECAP_ARGS+=(-a)   # -a = chronological order
MERGECAP_ARGS+=(-w "$OUTPUT_FILE")
MERGECAP_ARGS+=("${PCAP_FILES[@]}")

echo "Merging..."
if mergecap "${MERGECAP_ARGS[@]}"; then
  SIZE=$(du -sh "$OUTPUT_FILE" 2>/dev/null | cut -f1)
  echo "Done! Merged file: $OUTPUT_FILE ($SIZE)"
else
  err "mergecap failed. Check the files above for corruption."
fi