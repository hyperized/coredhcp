# Image for the demo stack: the server with its terminal UI, which is a module
# of its own under cmd/coredhcp-tui and so is not what the repo Dockerfile at
# the root builds.
#
# The build context is the repository root, so build it from there:
#   docker build -f test/demo/Dockerfile .
# or let `make demo` do it through compose.

# The build stage runs on the build host's architecture and cross-compiles,
# so multi-arch image builds don't emulate the Go compiler.
FROM --platform=$BUILDPLATFORM golang:1.26@sha256:9d2f36f06329b2a141b9db99ffa32765cf695ee57b813ca29e245e8670bcbfff AS build
ARG TARGETOS TARGETARCH

# setcap, from libcap2-bin, only writes an extended attribute on the file, so
# it does not care which architecture the binary it marks was compiled for.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

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

# Same reasoning as the root Dockerfile: the UI runs the server in-process, so
# it binds udp/67 and opens an AF_PACKET socket, and it does that as an
# unprivileged user. Only capabilities on the file itself reach such a process.
RUN setcap cap_net_bind_service,cap_net_raw+ep /coredhcp-tui

# The range plugin creates its lease database at runtime, so the directory has
# to exist and belong to the runtime user. The final stage has no shell to
# mkdir with, so the directory is made here and copied across.
RUN mkdir -p /leasedb

# Distroless static, the same base as the root Dockerfile. tcell carries
# descriptions for xterm and its relatives inside the binary, so the UI draws
# without a terminfo database on disk. It cannot fall back to infocmp for a
# terminal it does not know, which is why the compose file pins TERM to
# xterm-256color when the operator's own is unset.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /coredhcp-tui /usr/local/bin/coredhcp-tui
COPY --from=build --chown=65532:65532 /leasedb /var/lib/coredhcp
USER 65532:65532
EXPOSE 67/udp
EXPOSE 547/udp
ENTRYPOINT ["/usr/local/bin/coredhcp-tui"]
CMD ["--conf", "/etc/coredhcp/config.yaml"]
