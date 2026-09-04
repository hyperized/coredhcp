# Image for the demo stack: the server with its terminal UI, which is a module
# of its own under cmd/coredhcp-tui and so is not what the repo Dockerfile at
# the root builds.
#
# The build context is the repository root, so build it from there:
#   docker build -f test/demo/Dockerfile .
# or let `make demo` do it through compose.

# The build stage runs on the build host's architecture and cross-compiles,
# so multi-arch image builds don't emulate the Go compiler.
FROM --platform=$BUILDPLATFORM golang:1.26 AS build
ARG TARGETOS TARGETARCH
WORKDIR /src

# Both module files before the tree, so editing Go code does not invalidate the
# download layers. The UI module replaces github.com/coredhcp/coredhcp with
# ../.., which is why the root go.mod has to be in place for its download too.
COPY go.mod go.sum ./
COPY cmd/coredhcp-tui/go.mod cmd/coredhcp-tui/go.sum ./cmd/coredhcp-tui/
RUN go mod download
RUN cd cmd/coredhcp-tui && go mod download

COPY . .
RUN cd cmd/coredhcp-tui && CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /coredhcp-tui .

FROM debian:trixie-slim
COPY --from=build /coredhcp-tui /usr/local/bin/coredhcp-tui
EXPOSE 67/udp
EXPOSE 547/udp
ENTRYPOINT ["/usr/local/bin/coredhcp-tui"]
CMD ["--conf", "/etc/coredhcp/config.yaml"]
