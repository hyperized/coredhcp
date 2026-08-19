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

.PHONY: all build test test-linux test-integration test-compose lint cover bench fuzz fmt clean docker-image

all: build

build:
	go build ./...
	mkdir -p bin
	go build -o bin/coredhcp ./cmd/coredhcp
	go build -o bin/coredhcp-generator ./cmd/coredhcp-generator

test:
	go test -count=1 -race ./...

# The raw-socket path and the integration tests are Linux-only; these targets
# run the same checks in a container so they work from any host.
test-linux:
	$(DOCKER_RUN) $(GO_IMAGE) go test -count=1 ./...

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

lint:
	$(DOCKER_RUN) $(GOLANGCI_IMAGE) golangci-lint run

cover:
	go test -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

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
	rm -rf bin coverage.out
