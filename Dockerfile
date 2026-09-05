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
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o /coredhcp ./cmd/coredhcp

# The server binds udp/67 and opens an AF_PACKET socket to answer clients that
# have no address yet, and it does that as an unprivileged user. For such a
# process --cap-add on the container only widens the bounding set: the kernel
# puts nothing in the permitted set unless the file carries the capabilities.
RUN setcap cap_net_bind_service,cap_net_raw+ep /coredhcp

# The range plugin creates its lease database at runtime, so the directory has
# to exist and belong to the runtime user. The final stage has no shell to
# mkdir with, so the directory is made here and copied across.
RUN mkdir -p /leasedb

# Distroless static: certificates, timezone data and a passwd file, which is
# all a static Go binary still wants from a base image. No shell to exec into
# and no package manager, and the default user is 65532 rather than root.
FROM gcr.io/distroless/static-debian13:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
COPY --from=build /coredhcp /usr/local/bin/coredhcp
COPY --from=build --chown=65532:65532 /leasedb /var/lib/coredhcp
USER 65532:65532
EXPOSE 67/udp
EXPOSE 547/udp
ENTRYPOINT ["/usr/local/bin/coredhcp"]
CMD ["--conf", "/etc/coredhcp/config.yaml"]
