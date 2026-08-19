# coredhcp

Fast, multithreaded, modular and extensible DHCP server written in Go.

This is a maintained fork of [coredhcp/coredhcp](https://github.com/coredhcp/coredhcp).
It diverges on purpose: standard library `log/slog` instead of logrus, a
pure-Go sqlite driver (no cgo), per-instance plugin state instead of package
globals, a strict golangci-lint config at zero issues, and near-total test
coverage. Commits stay small and per-concern so changes can flow back
upstream.

[![Build](https://github.com/hyperized/coredhcp/actions/workflows/build.yml/badge.svg)](https://github.com/hyperized/coredhcp/actions/workflows/build.yml)
[![Tests](https://github.com/hyperized/coredhcp/actions/workflows/tests.yml/badge.svg)](https://github.com/hyperized/coredhcp/actions/workflows/tests.yml)
[![Lint](https://github.com/hyperized/coredhcp/actions/workflows/lint.yml/badge.svg)](https://github.com/hyperized/coredhcp/actions/workflows/lint.yml)
[![Fuzz](https://github.com/hyperized/coredhcp/actions/workflows/fuzz.yml/badge.svg)](https://github.com/hyperized/coredhcp/actions/workflows/fuzz.yml)
[![Coverage](https://img.shields.io/badge/coverage-98.6%25-brightgreen)](https://github.com/hyperized/coredhcp/actions/workflows/tests.yml)
[![Go Version](https://img.shields.io/github/go-mod/go-version/hyperized/coredhcp)](go.mod)
[![License](https://img.shields.io/github/license/hyperized/coredhcp)](LICENSE)

## Example configuration

In CoreDHCP almost everything is implemented as a plugin. The order of plugins
in the configuration matters: every request is evaluated calling each plugin in
order, until one breaks the evaluation and responds to, or drops, the request.

The following configuration runs a DHCPv6-only server, listening on all the
interfaces, using a custom server ID and DNS, and reading the leases from a
text file.

```
server6:
    # this server will listen on all the available interfaces, on the default
    # DHCPv6 server port, and will join the default multicast groups. For more
    # control, see the `listen` directive in cmd/coredhcp/config.yml.example .
    plugins:
        - server_id: LL 00:de:ad:be:ef:00
        - file: "leases.txt"
        - dns: 8.8.8.8 8.8.4.4 2001:4860:4860::8888 2001:4860:4860::8844
```

For more complex examples, like how to listen on specific interfaces and
configure other plugins, see
[config.yml.example](cmd/coredhcp/config.yml.example).

## Build and run

Day-to-day tasks are wrapped in the Makefile:

```
$ make                  # build everything into bin/
$ make test             # unit tests with the race detector
$ make test-linux       # the same suite on Linux, in a container
$ make test-integration # DHCPv6 against a client in network namespaces
$ make test-compose     # DHCPv4 against clients on a docker bridge
$ make lint             # golangci-lint, pinned version, in a container
$ make cover            # coverage profile plus the total
$ make bench            # benchmark suite with allocation counts
$ make fuzz             # every fuzz target, 30s each (FUZZTIME=5m for longer)
```

To run the example server, put a working configuration in `config.yml` (start
from [config.yml.example](cmd/coredhcp/config.yml.example)) and:

```
$ cd cmd/coredhcp
$ go build
$ sudo ./coredhcp
time=2026-08-19T12:09:32.986+02:00 level=INFO msg="Setting log level to 'info'" prefix=main
time=2026-08-19T12:09:32.986+02:00 level=INFO msg="Loading configuration" prefix=config
time=2026-08-19T12:09:32.987+02:00 level=INFO msg="DHCPv6: found plugin `server_id` with 2 args: [LL 00:de:ad:be:ef:00]" prefix=config
time=2026-08-19T12:09:32.987+02:00 level=INFO msg="DHCPv6: found plugin `file` with 1 args: [leases.txt]" prefix=config
time=2026-08-19T12:09:32.987+02:00 level=INFO msg="Loading plugins..." prefix=plugins
time=2026-08-19T12:09:32.987+02:00 level=INFO msg="DHCPv6: loading plugin `server_id`" prefix=plugins
time=2026-08-19T12:09:32.987+02:00 level=INFO msg="using ll 00:de:ad:be:ef:00" prefix=plugins/server_id
time=2026-08-19T12:09:32.987+02:00 level=INFO msg="reading IPv6 leases from leases.txt" prefix=plugins/file
time=2026-08-19T12:09:32.987+02:00 level=INFO msg="loaded 1 leases from leases.txt" prefix=plugins/file
time=2026-08-19T12:09:32.988+02:00 level=INFO msg="Starting DHCPv6 server" prefix=server
time=2026-08-19T12:09:32.988+02:00 level=INFO msg="Listen [::]:547" prefix=server
```

The server shuts down cleanly on SIGINT/SIGTERM. `-h` lists the flags: config
path, log level, log file and a `-P` that prints the built-in plugin list.

Then try it with the test client in [cmd/client/](cmd/client), which runs one
solicit/advertise exchange against `[::1]:547` and logs the whole
conversation:

```
$ cd cmd/client
$ go build
$ sudo ./client -interface lo0   # defaults to lo, pick your loopback
```

## Integration tests

Two stacks exercise the protocol on the wire, one per address family.

`make test-integration` runs the DHCPv6 server and a client in a pair of
network namespaces ([test/integration/](test/integration/)). Namespaces are a
Linux feature, so the Makefile runs this in a container.

`make test-compose` runs DHCPv4 end to end over a docker bridge
([test/compose/](test/compose/)): the server built from the Dockerfile, four
busybox clients with fixed MAC addresses, and a checker that asserts every
offered lease. Three clients have a static lease in the `file` plugin, the
fourth falls through to the `range` plugin's pool. One sets the broadcast
flag, so both reply paths get used: UDP broadcast for that client, raw
layer-2 unicast for the others.

The clients never apply the address they are offered, because docker's IPAM
already owns their interface. A udhcpc script records the offer instead, and
the checker compares it against the server's own rendered configuration.
Docker assigns container addresses from a range the leases cannot reach, so
the two cannot collide even by accident.

A run takes a few seconds once the image is built, and the stack tears down
whether it passed or failed. Override the project name and network prefix to
run several copies on one host, as parallel CI jobs do:

```
$ make test-compose COMPOSE_PROJECT=coredhcp-mr123 DHCP_NET_PREFIX=172.31.241
```

## Docker

The [Dockerfile](./Dockerfile) builds a cgo-free binary and ships it on
debian-slim. `make docker-image` builds it, and the entrypoint reads its
configuration from `/etc/coredhcp/config.yaml`, so mount one there.

Running the container takes some care: a DHCP server has to share a broadcast
domain with its clients, so publishing ports out of a NAT network achieves
nothing. The compose stack in [test/compose/](test/compose/) is a working
example. It puts the server and its clients on one user-defined bridge and
grants `NET_BIND_SERVICE` and `NET_RAW` rather than running privileged.

# Plugins

CoreDHCP is heavily based on plugins: even the core functionalities are
implemented as plugins. Therefore, knowing how to write one is the key to add
new features to CoreDHCP.

Core plugins can be found under the [plugins](/plugins/) directory. Additional
plugins can also be found in the
[coredhcp/plugins](https://github.com/coredhcp/plugins) repository.

This fork adds four plugins upstream does not have:

* [options](plugins/options/) sets any DHCP option from config
  (`15:string:home.lan`), typed and validated, instead of one plugin per
  option
* [metrics](plugins/metrics/) serves request counters in Prometheus text
  format, with no new dependencies
* [macfilter](plugins/macfilter/) allows or denies clients by MAC, inline or
  from a file
* [ntp](plugins/ntp/) announces NTP servers, option 42 on DHCPv4 and the
  RFC 5908 option on DHCPv6

The `range` plugin also releases expired leases here (a pool on upstream
fills up forever: coredhcp/coredhcp#148).

## Server with custom plugins

To build a server with a custom set of plugins you can use the
[coredhcp-generator](/cmd/coredhcp-generator/) tool. Head there for
documentation on how to use it.

# How to write a plugin

The best way to learn is to read the comments and source code of the
[example plugin](plugins/example/), which guides you through the implementation
of a simple plugin that prints a packet every time it is received by the server.

# Authors

* [Andrea Barberio](https://github.com/insomniacslk)
* [Anatole Denis](https://github.com/natolumin)
* [Pablo Mazzini](https://github.com/pmazzini)
