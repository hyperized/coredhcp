# Versions used by the container-backed targets, override as needed.
GO_IMAGE       ?= golang:1.26
GOLANGCI_IMAGE ?= golangci/golangci-lint:v2.12.2

DOCKER_RUN = docker run --rm -v $(CURDIR):/src -w /src -e GOFLAGS=-buildvcs=false

# The docker-compose DHCPv4 test stack under test/compose/. Override the project
# name and the network prefix to run several stacks on one host at once.
COMPOSE_PROJECT  ?= coredhcp-dhcp4-itest
DHCP_NET_PREFIX  ?= 172.31.240
export DHCP_NET_PREFIX
COMPOSE_TEST = docker compose -p $(COMPOSE_PROJECT) -f test/compose/docker-compose.yml

# The redis plugin's integration tests under test/redis/: a real Redis and a Go
# container running the tagged tests against it.
REDIS_PROJECT ?= coredhcp-redis-itest
COMPOSE_REDIS = docker compose -p $(REDIS_PROJECT) -f test/redis/docker-compose.yml

# The ddns plugin's integration tests under test/ddns/: a real Knot DNS server
# taking TSIG-signed updates and a Go container running the tagged tests
# against it.
DDNS_PROJECT ?= coredhcp-ddns-itest
COMPOSE_DDNS = docker compose -p $(DDNS_PROJECT) -f test/ddns/docker-compose.yml

# The demo stack under test/demo/: the server with its terminal UI plus busybox
# clients that keep it busy. Its own project name and network prefix, so it can
# run next to the stacks above.
DEMO_PROJECT    ?= coredhcp-demo
DEMO_NET_PREFIX ?= 172.31.242
export DEMO_NET_PREFIX
COMPOSE_DEMO = docker compose -p $(DEMO_PROJECT) -f test/demo/docker-compose.yml

# The terminal UI is a module of its own under cmd/coredhcp-tui, so the root
# go.mod stays free of its dependencies. `go test ./...` from the root does not
# see it; the targets below run each step in both modules.
TUI_DIR = cmd/coredhcp-tui

.PHONY: all build generate test test-linux test-integration test-compose test-redis test-ddns demo lint cover bench fuzz fmt clean docker-image

all: build

build:
	go build ./...
	mkdir -p bin
	go build -o bin/coredhcp ./cmd/coredhcp
	go build -o bin/coredhcp-generator ./cmd/coredhcp-generator
	cd $(TUI_DIR) && go build -o ../../bin/coredhcp-tui .

# Both mains are rendered from templates in cmd/coredhcp-generator; edit the
# template, then regenerate. CI fails when a committed main.go drifts.
generate:
	cd cmd/coredhcp-generator && go run . -f core-plugins.txt -o ../coredhcp/main.go
	cd cmd/coredhcp-generator && go run . -t coredhcp-tui.go.template -f core-plugins.txt -o ../coredhcp-tui/main.go

test:
	go test -count=1 -race ./...
	cd $(TUI_DIR) && go test -count=1 -race ./...

# The raw-socket path and the integration tests are Linux-only; these targets
# run the same checks in a container so they work from any host.
test-linux:
	$(DOCKER_RUN) $(GO_IMAGE) go test -count=1 ./...
	$(DOCKER_RUN) -w /src/$(TUI_DIR) $(GO_IMAGE) go test -count=1 ./...

test-integration:
	$(DOCKER_RUN) --privileged $(GO_IMAGE) sh -c '\
		apt-get update -qq && apt-get install -y -qq iproute2 >/dev/null && \
		./test/integration/setup-netns.sh && \
		cd test/integration/server6 && \
		go build -tags=integration -race . && ./server6'

# End-to-end DHCPv4 test over a real broadcast domain: the server built from
# the Dockerfile, busybox clients with fixed MAC addresses, and a checker that
# asserts every offered lease. The stack is torn down whether it passes or not.
test-compose:
	@set -eu; \
	teardown() { $(COMPOSE_TEST) down --volumes --remove-orphans >/dev/null 2>&1 || true; }; \
	trap teardown EXIT INT TERM; \
	teardown; \
	$(COMPOSE_TEST) up --build --exit-code-from checker

# Integration tests for the redis plugin against a real Redis server, in
# compose. The netbox plugin's integration tests have no stack here: they run
# on demand against an existing NetBox, see plugins/netbox.
test-redis:
	@set -eu; \
	teardown() { $(COMPOSE_REDIS) down --volumes --remove-orphans >/dev/null 2>&1 || true; }; \
	trap teardown EXIT INT TERM; \
	teardown; \
	$(COMPOSE_REDIS) up --exit-code-from tester

# Integration tests for the ddns plugin against a real Knot DNS server, in
# compose.
test-ddns:
	@set -eu; \
	teardown() { $(COMPOSE_DDNS) down --volumes --remove-orphans >/dev/null 2>&1 || true; }; \
	trap teardown EXIT INT TERM; \
	teardown; \
	$(COMPOSE_DDNS) up --exit-code-from tester

# Watch the terminal UI against live traffic. The clients start detached and
# keep asking for leases; the server runs in the foreground with the UI on this
# terminal. Press q there to stop serving and tear the stack down.
demo:
	@set -eu; \
	teardown() { $(COMPOSE_DEMO) down --volumes --remove-orphans >/dev/null 2>&1 || true; }; \
	trap teardown EXIT INT TERM; \
	teardown; \
	$(COMPOSE_DEMO) build; \
	$(COMPOSE_DEMO) up -d config-render client-a client-b client-c client-renew client-dynamic client-denied client-churn; \
	$(COMPOSE_DEMO) run --rm server

lint:
	$(DOCKER_RUN) $(GOLANGCI_IMAGE) golangci-lint run
	$(DOCKER_RUN) -w /src/$(TUI_DIR) $(GOLANGCI_IMAGE) golangci-lint run

cover:
	go test -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1
	cd $(TUI_DIR) && go test -count=1 -coverprofile=coverage.out ./... && go tool cover -func=coverage.out | tail -1

bench:
	go test -run='^$$' -bench=. -benchmem ./...

# Runs every fuzz target for FUZZTIME each; override like: make fuzz FUZZTIME=5m
FUZZTIME ?= 30s
fuzz:
	@set -e; for pkg in $$(go list ./...); do \
		for target in $$(go test -list '^Fuzz' $$pkg 2>/dev/null | grep '^Fuzz' || true); do \
			echo "==> $$pkg $$target"; \
			go test -run='^$$' -fuzz="^$$target$$" -fuzztime=$(FUZZTIME) $$pkg; \
		done; \
	done

fmt:
	gofmt -w .

docker-image:
	docker build -t coredhcp .

clean:
	rm -rf bin coverage.out $(TUI_DIR)/coverage.out
