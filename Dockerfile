FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /coredhcp ./cmd/coredhcp

FROM debian:trixie-slim
COPY --from=build /coredhcp /usr/local/bin/coredhcp
EXPOSE 67/udp
EXPOSE 547/udp
ENTRYPOINT ["/usr/local/bin/coredhcp"]
CMD ["--conf", "/etc/coredhcp/config.yaml"]
