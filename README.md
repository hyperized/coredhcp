# coredhcp

This is a maintained fork of [coredhcp/coredhcp](https://github.com/coredhcp/coredhcp).
It diverges deliberately: standard library `log/slog` instead of logrus, a
pure-Go sqlite driver (no cgo), per-instance plugin state instead of package
globals, a strict golangci-lint config at zero issues, and near-total test
coverage. Commits are kept small and per-concern so changes can flow back
upstream.

[![codecov](https://codecov.io/gh/coredhcp/coredhcp/branch/master/graph/badge.svg)](https://codecov.io/gh/coredhcp/coredhcp)
[![Go Report Card](https://goreportcard.com/badge/github.com/coredhcp/coredhcp)](https://goreportcard.com/report/github.com/coredhcp/coredhcp)

Fast, multithreaded, modular and extensible DHCP server written in Go

This is still a work-in-progress

## Example configuration

In CoreDHCP almost everything is implemented as a plugin. The order of plugins in the configuration matters: every request is evaluated calling each plugin in order, until one breaks the evaluation and responds to, or drops, the request.

The following configuration runs a DHCPv6-only server, listening on all the interfaces, using a custom server ID and DNS, and reading the leases from a text file.

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
configure other plugins, see [config.yml.example](cmd/coredhcp/config.yml.example).

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

### Integration tests

Two stacks exercise the protocol on the wire, one per address family.

`make test-integration` runs the DHCPv6 server and a client in a pair of
network namespaces ([test/integration/](test/integration/)). Namespaces are a
Linux feature, so the Makefile runs that one in a container.

`make test-compose` runs DHCPv4 end to end over a docker bridge
([test/compose/](test/compose/)): the server built from the Dockerfile, four
busybox clients with fixed MAC addresses, and a checker that asserts every
offered lease. Three of the clients have a static lease in the `file` plugin,
the fourth has none and falls through to the `range` plugin's pool. One of them
sets the broadcast flag, so both reply paths get used: a UDP broadcast for that
client and a raw layer-2 unicast for the others.

The clients never apply the address they are offered, because docker's IPAM
already owns their interface. A udhcpc script records the offer instead, and
the checker compares it against the server's own rendered configuration:
addresses, router, netmask, DNS, server id and lease time. Docker's own address
pool sits well above the static leases and the range pool, so container
addressing cannot collide with a lease even by accident.

A run takes a few seconds once the image has been built, and the stack is torn
down afterwards whether it passed or failed. Override the project name and the
network prefix to run more than one copy on a host, which is what parallel CI
jobs need:

```
$ make test-compose COMPOSE_PROJECT=coredhcp-mr123 DHCP_NET_PREFIX=172.31.241
```

An example server is located under [cmd/coredhcp/](cmd/coredhcp/), so enter that
directory first. To build a server with a custom set of plugins, see the "Server
with custom plugins" section below.

Once you have a working configuration in `config.yml` (see [config.yml.example](cmd/coredhcp/config.yml.example)), you can build and run the server:
```
$ cd cmd/coredhcp
$ go build
$ sudo ./coredhcp
time=2026-08-19T22:28:07Z level=INFO msg="Registering plugin \"file\"" prefix=plugins
time=2026-08-19T22:28:07Z level=INFO msg="Registering plugin \"server_id\"" prefix=plugins
time=2026-08-19T22:28:07Z level=INFO msg="Loading configuration" prefix=main
time=2026-08-19T22:28:07Z level=INFO msg="Found plugin: `server_id` with 2 args" prefix=config
INFO[2019-01-05T22:28:07Z] Found plugin: `file` with 1 args, `[leases.txt]`
INFO[2019-01-05T22:28:07Z] Loading plugins...
INFO[2019-01-05T22:28:07Z] Loading plugin `server_id`
INFO[2019-01-05T22:28:07Z] plugins/server_id: loading `server_id` plugin
INFO[2019-01-05T22:28:07Z] plugins/server_id: using ll 00:de:ad:be:ef:00
INFO[2019-01-05T22:28:07Z] Loading plugin `file`
INFO[2019-01-05T22:28:07Z] plugins/file: reading leases from leases.txt
INFO[2019-01-05T22:28:07Z] plugins/file: loaded 1 leases from leases.txt
INFO[2019-01-05T22:28:07Z] Starting DHCPv6 listener on [::]:547
INFO[2019-01-05T22:28:07Z] Waiting
2019/01/05 22:28:07 Server listening on [::]:547
2019/01/05 22:28:07 Ready to handle requests
...
```

Then try it with the local test client, that is located under
[cmd/client/](cmd/client):
```
$ cd cmd/client
$ go build
$ sudo ./client
INFO[2019-01-05T22:29:21Z] &{ReadTimeout:3s WriteTimeout:3s LocalAddr:[::1]:546 RemoteAddr:[::1]:547}
INFO[2019-01-05T22:29:21Z] DHCPv6Message
  messageType=SOLICIT
  transactionid=0x6d30ff
  options=[
    OptClientId{cid=DUID{type=DUID-LLT hwtype=Ethernet hwaddr=00:11:22:33:44:55}}
    OptRequestedOption{options=[DNS Recursive Name Server, Domain Search List]}
    OptElapsedTime{elapsedtime=0}
    OptIANA{IAID=[250 206 176 12], t1=3600, t2=5400, options=[]}
  ]
...
```

## Docker

The [Dockerfile](./Dockerfile) builds a cgo-free binary and ships it on
debian-slim. `make docker-image` builds it, and the entrypoint reads its
configuration from `/etc/coredhcp/config.yaml`, so mount one there. There is an
example configuration file [config.yml.example](./cmd/coredhcp/config.yml.example)
to start from.

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
