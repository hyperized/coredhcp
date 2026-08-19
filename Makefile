# Versions used by the container-backed targets, override as needed.
GO_IMAGE       ?= golang:1.26
GOLANGCI_IMAGE ?= golangci/golangci-lint:v2.12.2

DOCKER_RUN = docker run --rm -v $(CURDIR):/src -w /src -e GOFLAGS=-buildvcs=false

.PHONY: all build test test-linux test-integration lint cover fmt clean docker-image

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

lint:
	$(DOCKER_RUN) $(GOLANGCI_IMAGE) golangci-lint run

cover:
	go test -count=1 -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out | tail -1

fmt:
	gofmt -w .

docker-image:
	docker build -t coredhcp .

clean:
	rm -rf bin coverage.out
