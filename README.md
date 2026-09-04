# coredhcp

Fast, multithreaded, modular and extensible DHCP server written in Go.

This is a maintained fork of [coredhcp/coredhcp](https://github.com/coredhcp/coredhcp).
It diverges on purpose: standard library `log/slog` instead of logrus, a
pure-Go sqlite driver (no cgo), per-instance plugin state instead of package
globals, a strict golangci-lint config at zero issues, near-total test
coverage, and a terminal UI that shows what the server is doing. Commits stay small and per-concern so changes can flow back
upstream.

[![Build](https://github.com/hyperized/coredhcp/actions/workflows/build.yml/badge.svg)](https://github.com/hyperized/coredhcp/actions/workflows/build.yml)
[![Tests](https://github.com/hyperized/coredhcp/actions/workflows/tests.yml/badge.svg)](https://github.com/hyperized/coredhcp/actions/workflows/tests.yml)
[![Lint](https://github.com/hyperized/coredhcp/actions/workflows/lint.yml/badge.svg)](https://github.com/hyperized/coredhcp/actions/workflows/lint.yml)
[![Fuzz](https://github.com/hyperized/coredhcp/actions/workflows/fuzz.yml/badge.svg)](https://github.com/hyperized/coredhcp/actions/workflows/fuzz.yml)
[![Coverage](https://img.shields.io/badge/coverage-99.1%25-brightgreen)](https://github.com/hyperized/coredhcp/actions/workflows/tests.yml)
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
$ make generate         # re-render both main.go files from their templates
$ make test             # unit tests with the race detector
$ make test-linux       # the same suite on Linux, in a container
$ make test-integration # DHCPv6 against a client in network namespaces
$ make test-compose     # DHCPv4 against clients on a docker bridge
$ make test-redis       # the redis plugin against a real Redis, in compose
$ make lint             # golangci-lint, pinned version, in a container
$ make cover            # coverage profile plus the total
$ make bench            # benchmark suite with allocation counts
$ make fuzz             # every fuzz target, 30s each (FUZZTIME=5m for longer)
$ make demo             # the terminal UI against busy DHCP clients in compose
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

Without `-c`, the server looks for `config.yml` in `$XDG_CONFIG_HOME/coredhcp/`,
`$HOME/.coredhcp/`, `/etc/coredhcp/` and the working directory, in that order.
The working directory is searched last so a file left lying around next to the
binary cannot quietly take precedence over the one an operator installed.

The server shuts down cleanly on SIGINT/SIGTERM and exits 0. It exits non-zero
when a listener dies under it or when the configuration names no address to
bind, so a service manager sees a failure instead of a silent stop. `-h` lists
the flags: config path, log level, log file and a `-P` that prints the built-in
plugin list.

## Terminal UI

`coredhcp-tui` is the same server with a screen in front of it. It shows the
sockets it bound, the plugin chain per family with how often each plugin
answered or dropped a request, every request as it is handled with the reply
that went out, the addresses that were offered and the ones that were
confirmed, per-family counters, the request rate over the last minute, and the
server's own log. It takes the flags `coredhcp` takes, minus `-N`: the console
log goes into a pane instead.

![coredhcp-tui on the demo stack: the traffic feed with offers, acks, releases and macfilter drops, the lease table, the plugin chain with per-plugin tallies, counters, the request rate and the server log](tui.png)

```
$ sudo ./bin/coredhcp-tui -c config.yml
```

`q` quits and stops the server with it. `p` freezes the traffic pane, `Tab`
and `1` to `4` move focus, the arrow keys scroll, `c` clears the counters and
`?` lists the keys. The lease table is read off the exchanges themselves, so it
says what the server sent on the wire, not what a plugin stored; the details
are in [cmd/coredhcp-tui/tui/](cmd/coredhcp-tui/tui/).

To look at it without a network to serve, `make demo` builds the binary into
a container and puts it on a docker bridge with busybox clients that keep
asking: three with static leases, one from the pool, one that renews, one that
is denied by `macfilter`, and one that changes its MAC address every few
seconds until the pool runs dry and leases start expiring. The UI draws in
your terminal; quitting it tears the stack down. See
[test/demo/](test/demo/).

The UI is a Go module of its own under `cmd/coredhcp-tui`, so the root
`go.mod` does not carry tview and tcell, and the plain `coredhcp` binary and
the container image do not link them. A generated server (see the generator
below) can use it too: render `coredhcp-tui.go.template` instead of the
default one.

The hooks it runs on are exported, for anyone embedding the server:
`server.WithObserver` reports every bound listener, every loaded plugin and
every handled request, with its outcome and the plugin that ended the chain,
to an [`events.Observer`](events/). With no observer attached the packet path
pays a nil check and nothing else.

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

`make test-redis` runs the redis plugin's integration tests against a real
Redis server ([test/redis/](test/redis/)): one container for Redis with a
password set, one `golang` container running the tests tagged `integration`
against it. The netbox plugin's integration tests have no stack here; they run
on demand against an existing NetBox instance with `NETBOX_URL`,
`NETBOX_TOKEN` and `NETBOX_TEST_MAC` set, see the package documentation.

## Docker

The [Dockerfile](./Dockerfile) builds a cgo-free binary and ships it on
distroless static. `make docker-image` builds it, and the entrypoint reads its
configuration from `/etc/coredhcp/config.yaml`, so mount one there.

The server runs as uid 65532, not as root, so the two things it needs from the
kernel have to be granted. Binding udp/67 needs `NET_BIND_SERVICE`, and
answering a client that has no address yet goes over an AF_PACKET socket, which
needs `NET_RAW`. The binary carries both as file capabilities, so granting
those two to the container is enough and privileged mode is never needed:

```
services:
  coredhcp:
    image: coredhcp
    cap_drop: [ALL]
    cap_add: [NET_BIND_SERVICE, NET_RAW]
    volumes:
      - ./config.yaml:/etc/coredhcp/config.yaml:ro
      - coredhcp-leasedb:/var/lib/coredhcp

volumes:
  coredhcp-leasedb:
```

The `range` plugin creates its lease database at the path the config gives it,
and uid 65532 has to be able to write there. `/var/lib/coredhcp` in the image
belongs to that user, and a named volume mounted over it inherits that owner. A
bind mount does not: the directory keeps the ownership it has on the host, and
the database fails to open. Either keep the lease database on a named
volume or chown the host directory to 65532 first.

Beyond the file system, running the container takes some care: a DHCP server
has to share a broadcast domain with its clients, so publishing ports out of a
NAT network achieves nothing. The compose stack in [test/compose/](test/compose/)
is a working example, with the server and its clients on one user-defined
bridge.

# Plugins

CoreDHCP is heavily based on plugins: even the core functionalities are
implemented as plugins. Therefore, knowing how to write one is the key to add
new features to CoreDHCP.

Core plugins can be found under the [plugins](/plugins/) directory.

This fork adds six plugins upstream does not have built in:

* [options](plugins/options/) sets any DHCP option from config
  (`15:string:home.lan`), typed and validated, instead of one plugin per
  option
* [metrics](plugins/metrics/) serves request counters in Prometheus text
  format, with no new dependencies
* [macfilter](plugins/macfilter/) allows or denies clients by MAC, inline or
  from a file
* [ntp](plugins/ntp/) announces NTP servers, option 42 on DHCPv4 and the
  RFC 5908 option on DHCPv6
* [netbox](plugins/netbox/) serves each client the address documented in
  NetBox on the interface that carries its MAC, devices and virtual machines
  alike, with a bounded cache in front of the API (NetBox 4.2 or newer)
* [redis](plugins/redis/) serves static leases, router, DNS and lease time
  from Redis hashes keyed by MAC, over a small RESP client of its own rather
  than a client library; `redis://` and `rediss://` URLs, AUTH and database
  selection are supported

The last two started as the `netbox` and `redis` plugins in the
[coredhcp/plugins](https://github.com/coredhcp/plugins) repository, which has
not moved since 2020. They are rewrites, not ports: both families are served,
results are cached, errors are bounded, and the NetBox one speaks the current
API. Tokens and passwords can be given as `env:NAME` instead of a literal,
which is the better option because it keeps the secret out of the config file.
A literal is not printed either way: the startup log and the terminal UI's
plugin pane replace the value of a `password:`, `token:` or `secret:` argument,
and the password in a `scheme://user:pass@host` URL, with `***`.

The `range` plugin also releases expired leases here (a pool on upstream
fills up forever: coredhcp/coredhcp#148). It frees a lease only when the
client names it in `ciaddr`, as RFC 2131 requires, so a forged DHCPRELEASE
can no longer drain the pool, and it keeps an address a client declined out
of circulation for `decline-probation` (24h by default) instead of handing
the next client into the same conflict.

The `file` plugin no longer stamps its static reservation onto a RELEASE or
DECLINE, and `server_id` decides whether a DHCPv4 request is addressed to
this server by option 54 rather than by `siaddr`, so two servers on one
segment stop both answering the same REQUEST.

## Server with custom plugins

To build a server with a custom set of plugins you can use the
[coredhcp-generator](/cmd/coredhcp-generator/) tool. Head there for
documentation on how to use it. Both `cmd/coredhcp/main.go` and
`cmd/coredhcp-tui/main.go` are rendered by it from templates in that
directory; edit the template, run `make generate`, and commit the result. CI
regenerates them and fails when a committed file has drifted.

The [sleep](plugins/sleep/) plugin is in the tree but not in either default
binary. It delays every response, which is a debugging aid rather than
something a running server wants; add it to `core-plugins.txt` when you need
it.

# How to write a plugin

The best way to learn is to read the comments and source code of the
[example plugin](plugins/example/), which guides you through the implementation
of a simple plugin that prints a packet every time it is received by the server.

# Authors

* [Andrea Barberio](https://github.com/insomniacslk)
* [Anatole Denis](https://github.com/natolumin)
* [Pablo Mazzini](https://github.com/pmazzini)
