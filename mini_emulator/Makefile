# =============================================================================
#  Makefile — SEED Emulator: network traffic capture setup
# =============================================================================
#
#  Lifecycle:
#    make build            Build all container images
#    make up               Build + start the emulator (detached)
#    make down             Stop and remove containers + networks
#    make restart          down + up
#
#  Attack toggles (persist in .env, mix and match freely):
#    make enable-synflood  /  make disable-synflood
#    make enable-arp       /  make disable-arp
#    make enable-bgp       /  make disable-bgp
#    make enable-all       /  make disable-all
#    make show-attacks     Show current attack configuration
#
#  Capture:
#    make capture                   Capture pcaps on all bridges (Ctrl+C to stop)
#    make capture CAPTURE_SECS=120  Capture, auto-stop after 120s
#    make capture-zeek              Capture Zeek JSON logs       (Ctrl+C to stop)
#
#  Observability:
#    make logs             Tail container logs
#    make ps               List running containers
#    make status           Containers + networks overview
#
#  Cleanup:
#    make clean            Stop everything, remove images + capture dirs
#
# =============================================================================

# ---------- Configuration ----------

COMPOSE_FILE     ?= docker-compose.yml
PROJECT          ?= mini_emulator
COMPOSE_CMD      := docker-compose -f $(COMPOSE_FILE) -p $(PROJECT)

CAPTURE_LABEL    ?= capture
CAPTURE_SECS     ?=
ZEEK_IMAGE       ?= zeek/zeek:latest
ENV_FILE         := .env

# ---------- Phony targets ----------

.PHONY: build up down restart \
        enable-synflood disable-synflood \
        enable-arp disable-arp \
        enable-bgp disable-bgp \
        enable-all disable-all show-attacks \
        capture capture-zeek \
        logs ps status clean help

.DEFAULT_GOAL := help

# ---------- .env bootstrap ----------
# Ensure .env exists with defaults so the toggle targets can always sed into it.

$(ENV_FILE):
	@echo "SYNFLOOD=false"  >  $(ENV_FILE)
	@echo "ECLIPSE_ARP=false" >> $(ENV_FILE)
	@echo "ECLIPSE_BGP=false" >> $(ENV_FILE)

# ---------- Core lifecycle ----------

build:  ## Build all container images
	$(COMPOSE_CMD) build

up: $(ENV_FILE) build  ## Build + start all containers (detached)
	$(COMPOSE_CMD) up -d

down:  ## Stop and remove containers, networks
	$(COMPOSE_CMD) down

restart: down up  ## Restart the emulator

# ---------- Attack toggles ----------
# Each toggle updates .env in-place. Changes take effect on next 'make up' / 'make restart'.

enable-synflood: $(ENV_FILE)  ## Enable SYN flood attack
	@sed -i 's/^SYNFLOOD=.*/SYNFLOOD=true/' $(ENV_FILE)
	@echo "SYNFLOOD enabled"

disable-synflood: $(ENV_FILE)  ## Disable SYN flood attack
	@sed -i 's/^SYNFLOOD=.*/SYNFLOOD=false/' $(ENV_FILE)
	@echo "SYNFLOOD disabled"

enable-arp: $(ENV_FILE)  ## Enable ARP eclipse attack
	@sed -i 's/^ECLIPSE_ARP=.*/ECLIPSE_ARP=true/' $(ENV_FILE)
	@echo "ECLIPSE_ARP enabled"

disable-arp: $(ENV_FILE)  ## Disable ARP eclipse attack
	@sed -i 's/^ECLIPSE_ARP=.*/ECLIPSE_ARP=false/' $(ENV_FILE)
	@echo "ECLIPSE_ARP disabled"

enable-bgp: $(ENV_FILE)  ## Enable BGP eclipse attack
	@sed -i 's/^ECLIPSE_BGP=.*/ECLIPSE_BGP=true/' $(ENV_FILE)
	@echo "ECLIPSE_BGP enabled"

disable-bgp: $(ENV_FILE)  ## Disable BGP eclipse attack
	@sed -i 's/^ECLIPSE_BGP=.*/ECLIPSE_BGP=false/' $(ENV_FILE)
	@echo "ECLIPSE_BGP disabled"

enable-all: $(ENV_FILE)  ## Enable all attacks
	@sed -i 's/^SYNFLOOD=.*/SYNFLOOD=true/'       $(ENV_FILE)
	@sed -i 's/^ECLIPSE_ARP=.*/ECLIPSE_ARP=true/'  $(ENV_FILE)
	@sed -i 's/^ECLIPSE_BGP=.*/ECLIPSE_BGP=true/'  $(ENV_FILE)
	@echo "All attacks enabled"

disable-all: $(ENV_FILE)  ## Disable all attacks (clean baseline)
	@sed -i 's/^SYNFLOOD=.*/SYNFLOOD=false/'        $(ENV_FILE)
	@sed -i 's/^ECLIPSE_ARP=.*/ECLIPSE_ARP=false/'   $(ENV_FILE)
	@sed -i 's/^ECLIPSE_BGP=.*/ECLIPSE_BGP=false/'   $(ENV_FILE)
	@echo "All attacks disabled"

show-attacks: $(ENV_FILE)  ## Show current attack configuration
	@echo "--- Attack config ($(ENV_FILE)) ---"
	@cat $(ENV_FILE)

# ---------- Traffic capture ----------

capture:  ## Capture pcaps on all docker bridges (Ctrl+C, or CAPTURE_SECS=N to auto-stop)
	sudo bash ./capture_full.sh $(CAPTURE_LABEL) $(CAPTURE_SECS)

capture-zeek:  ## Capture Zeek JSON logs on all bridges (Ctrl+C to stop)
	sudo ZEEK_IMAGE=$(ZEEK_IMAGE) bash ./capture_zeek.sh $(CAPTURE_LABEL)

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
	rm -rf captures/ captures_zeek/
	@echo "Clean complete."

# ---------- Help ----------

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
