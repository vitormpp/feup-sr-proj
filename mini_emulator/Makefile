# =============================================================================
# Makefile  -  SEED Emulator: capture normal traffic, train an Isolation Forest
#              outlier-detection model, and run live anomaly detection.
#
# Quick start:
#   sudo make all                    # up + capture + train  (one-shot)
#   sudo make detect IFACE=br-XXXX   # live detection on a host bridge
#   make attack                      # SYN flood (run from attacker host)
#
# Common variables (override on the command line, e.g. CAPTURE_SECS=300):
#   CAPTURE_SECS    seconds to capture for training      (default: 120)
#   WORK_DIR        output directory                     (default: ./training_run)
#   COMPOSE_FILE    docker-compose path                  (default: ./docker-compose.yml)
#   IFACE           interface for live detection         (no default)
#   DETECT_PCAP     replay pcap instead of live capture  (no default)
#   THRESHOLD       anomaly score threshold              (default: model.offset_)
#   ATTACK_REPS     SYN flood rounds                     (default: 10)
#   ATTACK_PKTS     packets per round                    (default: 2000)
# =============================================================================

SHELL        := /bin/bash
.ONESHELL:
.SHELLFLAGS  := -euo pipefail -c

# --- Paths / settings ------------------------------------------------------- #
CAPTURE_SECS ?= 120
COMPOSE_FILE ?= ./docker-compose.yml
PROJECT_NAME ?= mini_emulator
WORK_DIR     ?= ./training_run
PCAP_DIR     := $(WORK_DIR)/pcaps
MERGED_PCAP  := $(WORK_DIR)/capture.pcap
MODEL_PATH   ?= $(WORK_DIR)/model.pkl
SCALER_PATH  ?= $(WORK_DIR)/model_scaler.pkl
FEATURES_CSV ?= $(WORK_DIR)/features.csv
LOG_DIR      ?= $(WORK_DIR)/logs

# Compose networks to capture on (must match docker-compose.yml)
NETWORKS     := net_160_net0 net_161_net0 net_162_net0 net_ix_ix103

# --- Detection / attack defaults ------------------------------------------- #
IFACE        ?=
DETECT_PCAP  ?=
THRESHOLD    ?=
ATTACK_REPS  ?= 10
ATTACK_PKTS  ?= 2000

# --- Resolve invoking user's home (so sudo finds their venv) --------------- #
REAL_USER    := $(shell if [ -n "$$SUDO_USER" ]; then echo "$$SUDO_USER"; else id -un; fi)
REAL_HOME    := $(shell getent passwd $(REAL_USER) | cut -d: -f6)
VENV_PYTHON  := $(REAL_HOME)/venv/bin/python3
PYTHON       := $(shell if [ -x "$(VENV_PYTHON)" ]; then echo "$(VENV_PYTHON)"; else echo "python3"; fi)

# --- Compose v2 vs v1 ------------------------------------------------------ #
COMPOSE      := $(shell if docker compose version >/dev/null 2>&1; then echo "docker compose"; else echo "docker-compose"; fi)

# --- Locate sibling scripts ------------------------------------------------ #
MKFILE_DIR    := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
TRAIN_SCRIPT  := $(MKFILE_DIR)train_outlier_model.py
DETECT_SCRIPT := $(MKFILE_DIR)run_model.py
ATTACK_SCRIPT := $(MKFILE_DIR)../syn_flood/perform_flood.py

.PHONY: help up down list-bridges capture train all detect attack clean check-root check-trained

# =============================================================================
help:
	@echo "Targets:"
	@echo "  make up                         docker compose up -d --build (15 s warm-up)"
	@echo "  make down                       docker compose down"
	@echo "  make list-bridges               show host bridge interfaces for the compose networks"
	@echo "  sudo make capture               tcpdump on every emulator bridge for CAPTURE_SECS"
	@echo "  make train                      train IsolationForest from \$$(MERGED_PCAP)"
	@echo "  sudo make all                   up + capture + train"
	@echo "  sudo make detect IFACE=br-XXXX  live anomaly detection on an interface"
	@echo "       make detect DETECT_PCAP=f  replay-mode detection on a pcap"
	@echo "  make attack                     run perform_flood.py (ATTACK_REPS, ATTACK_PKTS)"
	@echo "  make clean                      rm -rf \$$(WORK_DIR)"
	@echo ""
	@echo "Resolved settings:"
	@echo "  PYTHON         = $(PYTHON)"
	@echo "  COMPOSE        = $(COMPOSE)"
	@echo "  WORK_DIR       = $(WORK_DIR)"
	@echo "  MODEL_PATH     = $(MODEL_PATH)"
	@echo "  SCALER_PATH    = $(SCALER_PATH)"
	@echo "  CAPTURE_SECS   = $(CAPTURE_SECS)"

# =============================================================================
check-root:
	@if [ "$$(id -u)" -ne 0 ]; then \
	    echo "ERROR: this target must be run as root (sudo make $@)" >&2; exit 1; \
	fi

check-trained:
	@if [ ! -f "$(MODEL_PATH)" ] || [ ! -f "$(SCALER_PATH)" ]; then \
	    echo "ERROR: model artifacts missing." >&2; \
	    echo "       expected: $(MODEL_PATH)" >&2; \
	    echo "                 $(SCALER_PATH)" >&2; \
	    echo "       run 'sudo make all' first, or pass MODEL_PATH=/SCALER_PATH=" >&2; \
	    exit 1; \
	fi

# =============================================================================
up:
	$(COMPOSE) -f $(COMPOSE_FILE) -p $(PROJECT_NAME) up -d --build
	@echo "Waiting 15 s for containers to settle..."
	@sleep 15

down:
	$(COMPOSE) -f $(COMPOSE_FILE) -p $(PROJECT_NAME) down

# =============================================================================
list-bridges:
	@for net in $(NETWORKS); do
	    full="$(PROJECT_NAME)_$$net"
	    nid=$$(docker network inspect "$$full" -f '{{.Id}}' 2>/dev/null) || { echo "  $$full -> (network not found)"; continue; }
	    bridge="br-$${nid:0:12}"
	    if ip link show "$$bridge" >/dev/null 2>&1; then
	        echo "  $$net -> $$bridge"
	    else
	        echo "  $$net -> $$bridge (interface missing on host)"
	    fi
	done

# =============================================================================
capture: check-root
	mkdir -p "$(PCAP_DIR)"
	BRIDGES=()
	for net in $(NETWORKS); do
	    full="$(PROJECT_NAME)_$$net"
	    nid=$$(docker network inspect "$$full" -f '{{.Id}}' 2>/dev/null) || { echo "  WARN: network $$full not found, skipping"; continue; }
	    bridge="br-$${nid:0:12}"
	    if ip link show "$$bridge" >/dev/null 2>&1; then
	        echo "  $$net -> $$bridge"
	        BRIDGES+=("$$bridge")
	    else
	        echo "  WARN: bridge $$bridge missing on host, skipping"
	    fi
	done
	if [ $${#BRIDGES[@]} -eq 0 ]; then
	    echo "ERROR: no bridge interfaces found - are the containers running? (make up)" >&2
	    exit 1
	fi
	echo "Capturing for $(CAPTURE_SECS)s on $${#BRIDGES[@]} bridge(s)..."
	PIDS=()
	for b in "$${BRIDGES[@]}"; do
	    tcpdump -i "$$b" -s 0 -Z root -w "$(PCAP_DIR)/$$b.pcap" -q 2>/dev/null &
	    PIDS+=($$!)
	    echo "  tcpdump pid $$! -> $(PCAP_DIR)/$$b.pcap"
	done
	sleep $(CAPTURE_SECS)
	echo "Stopping tcpdump..."
	for p in "$${PIDS[@]}"; do kill -SIGTERM "$$p" 2>/dev/null || true; done
	sleep 2
	for p in "$${PIDS[@]}"; do wait "$$p" 2>/dev/null || true; done
	echo "Merging pcaps -> $(MERGED_PCAP)"
	if command -v mergecap >/dev/null 2>&1; then
	    mergecap -w "$(MERGED_PCAP)" "$(PCAP_DIR)"/*.pcap
	else
	    echo "  (mergecap not found; concatenating with header strip)"
	    first=1
	    for pf in "$(PCAP_DIR)"/*.pcap; do
	        [ -s "$$pf" ] || continue
	        if [ $$first -eq 1 ]; then
	            cp "$$pf" "$(MERGED_PCAP)"
	            first=0
	        else
	            tail -c +25 "$$pf" >> "$(MERGED_PCAP)"
	        fi
	    done
	fi
	size=$$(du -sh "$(MERGED_PCAP)" 2>/dev/null | cut -f1)
	echo "Merged pcap: $(MERGED_PCAP) ($$size)"
	if [ "$(REAL_USER)" != "root" ] && [ -n "$(REAL_USER)" ]; then
	    chown -R "$(REAL_USER):$(REAL_USER)" "$(WORK_DIR)" 2>/dev/null || true
	fi

# =============================================================================
train:
	@if [ ! -f "$(MERGED_PCAP)" ]; then \
	    echo "ERROR: $(MERGED_PCAP) not found - run 'sudo make capture' first." >&2; exit 1; \
	fi
	@if [ ! -f "$(TRAIN_SCRIPT)" ]; then \
	    echo "ERROR: $(TRAIN_SCRIPT) not found." >&2; exit 1; \
	fi
	mkdir -p "$(WORK_DIR)"
	$(PYTHON) "$(TRAIN_SCRIPT)" \
	    --pcap         "$(MERGED_PCAP)" \
	    --model-out    "$(MODEL_PATH)" \
	    --scaler-out   "$(SCALER_PATH)" \
	    --features-csv "$(FEATURES_CSV)"
	@if [ "$(REAL_USER)" != "root" ] && [ -n "$(REAL_USER)" ]; then \
	    chown -R "$(REAL_USER):$(REAL_USER)" "$(WORK_DIR)" 2>/dev/null || true; \
	fi

# =============================================================================
all: up capture train

# =============================================================================
# Live (or replay) anomaly detection. Use this while launching the attack to
# observe flagged flows.
detect: check-trained
	@if [ -z "$(IFACE)" ] && [ -z "$(DETECT_PCAP)" ]; then \
	    echo "ERROR: pass IFACE=<bridge> for live, or DETECT_PCAP=<file> for replay." >&2; \
	    echo "       use 'make list-bridges' to find an interface." >&2; \
	    exit 1; \
	fi
	@if [ -n "$(IFACE)" ] && [ "$$(id -u)" -ne 0 ]; then \
	    echo "ERROR: live capture (IFACE=...) needs root - use 'sudo make detect IFACE=...'" >&2; \
	    exit 1; \
	fi
	mkdir -p "$(LOG_DIR)"
	SOURCE_ARG=""
	if [ -n "$(IFACE)" ]; then SOURCE_ARG="--iface $(IFACE)"; else SOURCE_ARG="--pcap $(DETECT_PCAP)"; fi
	THRESH_ARG=""
	if [ -n "$(THRESHOLD)" ]; then THRESH_ARG="--threshold $(THRESHOLD)"; fi
	$(PYTHON) "$(DETECT_SCRIPT)" \
	    $$SOURCE_ARG \
	    --model   "$(MODEL_PATH)" \
	    --scaler  "$(SCALER_PATH)" \
	    --log-dir "$(LOG_DIR)" \
	    $$THRESH_ARG

# =============================================================================
# Run the SYN flood. Run this in a second terminal (typically from inside an
# attacker container) while 'make detect' is running on the host.
attack:
	@if [ ! -f "$(ATTACK_SCRIPT)" ]; then \
	    echo "ERROR: $(ATTACK_SCRIPT) not found." >&2; exit 1; \
	fi
	$(PYTHON) "$(ATTACK_SCRIPT)" -r $(ATTACK_REPS) -n $(ATTACK_PKTS)

# =============================================================================
clean:
	rm -rf "$(WORK_DIR)"
