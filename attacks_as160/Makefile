# =============================================================================
#  Makefile — AS160 attacks, launched directly from the HOST VM
# =============================================================================
#
#  The SEED emulator (docker-compose project) lives in ../mini_emulator.
#  These attacks are NO LONGER baked into the containers — they run straight
#  from the host VM and drive the containers via `docker exec` / raw sockets
#  (see attacks.py and the per-attack scripts).
#
#  Typical flow:
#    make restart          Bring the emulator up fresh (clean baseline)
#    make synflood         Launch an attack from the host VM
#
#  Emulator lifecycle (delegates to ../mini_emulator/docker-compose.yml):
#    make build            Build all container images
#    make up               Start the emulator (detached)
#    make down             Stop and remove containers + networks
#    make restart          down + up
#
#  Run attacks from the host VM via attacks.py — pick which ones by setting
#  each to 1 (default 0). Each loops on its own interval; Ctrl+C stops.
#    make attack SYNFLOOD=1              TCP SYN flood only
#    make attack ARP=1 SYNFLOOD=1        ARP eclipse + SYN flood
#    make attack BGP=1                   BGP-hijack eclipse
#    make all                            Every attack (attacks.py --all)
#    Tuning:  make attack SYNFLOOD=1 ATTACK_ARGS="--synflood-interval 90 --cycles 5"
#
#  Double spend (host VM):
#    make fake-tx          Send fraudulent tx to the isolated victim
#    make real-tx          Broadcast the real tx to the main network
#
#  Capture (runs inside ../mini_emulator):
#    make capture                   Capture pcaps on all bridges (Ctrl+C to stop)
#    make capture CAPTURE_SECS=120  Capture, auto-stop after 120s
#    make capture-zeek              Capture Zeek JSON logs       (Ctrl+C to stop)
#
#  Observability:
#    make logs / ps / status
#
#  Cleanup:
#    make clean            Stop everything, remove images + capture dirs
#
# =============================================================================

# ---------- Configuration ----------

EMULATOR_DIR     ?= ../mini_emulator
COMPOSE_FILE     ?= $(EMULATOR_DIR)/docker-compose.yml
PROJECT          ?= mini_emulator
COMPOSE_CMD      := docker-compose -f $(COMPOSE_FILE) -p $(PROJECT)

# Attacks run from the host VM. synflood opens raw sockets and the ARP/BGP
# scripts touch container namespaces, so they need root.
PYTHON           ?= python3
SUDO             ?= sudo
ATTACKS          := ./attacks.py
SYNFLOOD_BIN     := synflood/synflood
ATTACK_ARGS      ?=

# Attack selectors — set each to 1 to enable it for `make attack`.
SYNFLOOD         ?= 0
ARP              ?= 0
BGP              ?= 0

# Assemble the attacks.py flags from the selectors above.
ATTACK_FLAGS     :=
ifeq ($(SYNFLOOD),1)
ATTACK_FLAGS     += --synflood
endif
ifeq ($(ARP),1)
ATTACK_FLAGS     += --arp
endif
ifeq ($(BGP),1)
ATTACK_FLAGS     += --bgp
endif

CAPTURE_LABEL    ?= capture
CAPTURE_SECS     ?=
ZEEK_IMAGE       ?= zeek/zeek:latest

# ---------- Phony targets ----------

.PHONY: build up down restart \
        attack all \
        fake-tx real-tx \
        capture capture-zeek \
        logs ps status clean help

.DEFAULT_GOAL := help

# ---------- Emulator lifecycle ----------

build:  ## Build all container images
	$(COMPOSE_CMD) build

up:  ## Start the emulator (detached)
	$(COMPOSE_CMD) up -d

down:  ## Stop and remove containers, networks
	$(COMPOSE_CMD) down

restart: down up  ## Restart the emulator (clean baseline for attacks)

# ---------- Attacks (launched from the host VM via attacks.py) ----------
# Select attacks with SYNFLOOD=1 / ARP=1 / BGP=1; attacks.py auto-detects the
# synflood binary and the per-attack scripts in this tree.

attack:  ## Run selected attacks (e.g. make attack SYNFLOOD=1 ARP=1)
	@if [ -z "$(strip $(ATTACK_FLAGS))" ]; then \
		echo "No attacks selected. Set one or more of SYNFLOOD=1 ARP=1 BGP=1 (or use 'make all')." >&2; \
		exit 1; \
	fi
	@[ -f $(SYNFLOOD_BIN) ] && chmod +x $(SYNFLOOD_BIN) || true
	$(SUDO) $(PYTHON) $(ATTACKS) $(ATTACK_FLAGS) $(ATTACK_ARGS)

all:  ## Run every attack (attacks.py --all)
	@[ -f $(SYNFLOOD_BIN) ] && chmod +x $(SYNFLOOD_BIN) || true
	$(SUDO) $(PYTHON) $(ATTACKS) --all $(ATTACK_ARGS)

# ---------- Double spend (host VM) ----------

fake-tx:  ## Send the fraudulent tx to the isolated victim (Node 160)
	$(PYTHON) fake_tx.py

real-tx:  ## Broadcast the real tx to the main network (Nodes 161 & 162)
	$(PYTHON) real_tx.py

# ---------- Traffic capture (runs inside $(EMULATOR_DIR)) ----------

capture:  ## Capture pcaps on all docker bridges (Ctrl+C, or CAPTURE_SECS=N to auto-stop)
	cd $(EMULATOR_DIR) && $(SUDO) bash ./capture_full.sh $(CAPTURE_LABEL) $(CAPTURE_SECS)

capture-zeek:  ## Capture Zeek JSON logs on all bridges (Ctrl+C to stop)
	cd $(EMULATOR_DIR) && $(SUDO) ZEEK_IMAGE=$(ZEEK_IMAGE) bash ./capture_zeek.sh $(CAPTURE_LABEL)

# ---------- Observability ----------

logs:  ## Tail logs from all containers
	$(COMPOSE_CMD) logs -f

ps:  ## Show running containers
	$(COMPOSE_CMD) ps

status:  ## Containers + networks overview
	@echo "=== Containers ==="
	@$(COMPOSE_CMD) ps
	@echo ""
	@echo "=== Networks ==="
	@docker network ls --filter "name=$(PROJECT)" --format "table {{.Name}}\t{{.Driver}}\t{{.Scope}}"

# ---------- Cleanup ----------

clean: down  ## Stop everything, remove images and capture dirs
	$(COMPOSE_CMD) down --rmi local --volumes --remove-orphans 2>/dev/null || true
	rm -rf $(EMULATOR_DIR)/captures_full/ $(EMULATOR_DIR)/captures_zeek/
	@echo "Clean complete."

# ---------- Help ----------

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
