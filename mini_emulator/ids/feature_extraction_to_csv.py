"""
pcap_to_csv.py
==============
Command-line tool that converts a PCAP file into a CSV of ML-ready features
using the extraction logic from feature_extraction.py.

Usage
-----
    python pcap_to_csv.py <pcap_file> [options]

Arguments
---------
    pcap_file               Path to the input .pcap or .pcapng file.

Options
-------
    -o, --output <path>     Output CSV path.
                            Defaults to <pcap_file_stem>.csv in the same
                            directory as the input file.
    -w, --window <float>    Rolling temporal feature window in seconds.
                            Default: 1.0
    -k, --known <ip> ...    Whitelist of known-good IP addresses.
                            Packets whose src or dst is not in this list
                            are labelled malicious (label=1).
                            Omit to disable the unknown-address check.
    -h, --help              Show this help message and exit.

Examples
--------
    # Basic — output written to capture.csv
    python pcap_to_csv.py capture.pcap

    # Custom output path and 2-second rolling window
    python pcap_to_csv.py capture.pcap -o features/output.csv -w 2.0

    # With known-address whitelist
    python pcap_to_csv.py capture.pcap -k 192.168.1.1 192.168.1.2 10.0.0.1
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Import the feature extraction module.
# Both files are expected to live in the same directory; adjust sys.path if
# feature_extraction.py is elsewhere.
# ---------------------------------------------------------------------------
try:
    from ids.feature_extraction import extract_features
except ImportError as exc:
    sys.exit(
        f"[ERROR] Could not import feature_extraction.py: {exc}\n"
        "Make sure feature_extraction.py is in the same directory as this "
        "script, or add its location to PYTHONPATH."
    )

KNOWN_ADDRESSES = [
    "10.160.0.71",
    "10.160.0.72",
    "10.160.0.73",
    "10.160.0.254",
    "10.103.0.160",
    "10.161.0.71",
    "10.161.0.72",
    "10.161.0.73",
    "10.161.0.254",
    "10.103.0.161",
    "10.162.0.71",
    "10.162.0.72",
    "10.162.0.73",
    "10.162.0.74",
    "10.162.0.254",
    "10.103.0.162",
    "10.103.0.103",
    "10.0.0.1",
    "10.0.0.2",
    "10.0.0.3",
]

# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pcap_to_csv",
        description="Convert a PCAP file to a CSV of ML-ready features.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )

    parser.add_argument(
        "pcap_file",
        metavar="pcap_file",
        help="Path to the input .pcap or .pcapng file.",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="path",
        default=None,
        help=(
            "Output CSV path. "
            "Defaults to <pcap_file_stem>.csv next to the input file."
        ),
    )
    parser.add_argument(
        "-w", "--window",
        metavar="seconds",
        type=float,
        default=1.0,
        help="Rolling temporal feature window in seconds (default: 1.0).",
    )
    parser.add_argument(
        "-k", "--known",
        metavar="ip",
        nargs="+",
        default=KNOWN_ADDRESSES,
        help=(
            "Whitelist of known-good IP addresses. "
            "Packets from/to unlisted addresses are labelled malicious. "
            "Omit to disable the unknown-address check."
        ),
    )

    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args   = parser.parse_args(argv)

    pcap_path = Path(args.pcap_file)
    if not pcap_path.exists():
        parser.error(f"Input file not found: {pcap_path}")
    if not pcap_path.is_file():
        parser.error(f"Not a file: {pcap_path}")

    # Resolve output path
    if args.output is None:
        csv_path = pcap_path.with_suffix(".csv")
    else:
        csv_path = Path(args.output)

    # Create parent directories if needed
    csv_path.parent.mkdir(parents=True, exist_ok=True)

    print(f"[pcap_to_csv] Input  : {pcap_path}")
    print(f"[pcap_to_csv] Output : {csv_path}")
    print(f"[pcap_to_csv] Window : {args.window}s")
    if args.known:
        print(f"[pcap_to_csv] Known addresses ({len(args.known)}): "
              f"{', '.join(args.known)}")
    else:
        print("[pcap_to_csv] Known addresses : (check disabled)")

    # -----------------------------------------------------------------------
    # Feature extraction  — NO logic changed from feature_extraction.py
    # -----------------------------------------------------------------------
    print("[pcap_to_csv] Loading and extracting features …")
    try:
        df = extract_features(
            pcap_path=str(pcap_path),
            known_addresses=args.known,
            window_seconds=args.window,
        )
    except ValueError as exc:
        sys.exit(f"[ERROR] Feature extraction failed: {exc}")

    # -----------------------------------------------------------------------
    # Write CSV
    # -----------------------------------------------------------------------
    df.to_csv(csv_path, index=False)

    n_rows      = len(df)
    n_malicious = int(df["label"].sum())
    n_normal    = n_rows - n_malicious

    print(f"[pcap_to_csv] Done — {n_rows} rows written to {csv_path}")
    print(f"              label=0 (normal)   : {n_normal}")
    print(f"              label=1 (malicious): {n_malicious}")
    print(f"              columns            : {len(df.columns)}")


if __name__ == "__main__":
    main()