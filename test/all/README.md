# Every core plugin, end to end

This stack runs coredhcp with all 29 core plugins in one configuration and
proves each of them does what its package documentation says. It is a
counterpart to [test/compose/](../compose/), which checks the DHCPv4 happy
path against real busybox clients: this one goes wide instead of deep, and
the clients are one Go program that can also play a relay.

```
$ make test-all
```

The stack tears itself down whether it passes or not. A run takes about two
minutes once the images are built, most of it the seven scenarios that prove
a request was dropped and have to wait three seconds each to be sure.

## Topology

Two bridges, and the server and the exerciser are on both.

```
            lan  172.31.246.0/24  fd00:c0de:246::/64
  .5 knot ──┬────────┬──────────┬─────────┬──────────┬── .1 gateway
  .6 redis ─┘        │          │         │          │
  .4 helper ─────────┘          │         │          │
  .7 redis-seed ────────────────┘         │          │
                             .2 server  .3 exerciser
                                │          │
  ──────────────────────────────┴──────────┴───────────────────────
            relay  172.31.247.0/24  fd00:c0de:247::/64
                             .2 server  .3 exerciser     .1 gateway
```

The second bridge is what lets one container be both the client and the
relay. On `lan` the exerciser is an ordinary DHCP client: a raw AF_PACKET
socket for DHCPv4, because the server answers a client with no address as a
layer 2 unicast, and an ordinary UDP socket on port 546 for DHCPv6. On
`relay` it is a relay agent: it puts `172.31.247.3` in giaddr, or wraps a
DHCPv6 message in a Relay-forward from `fd00:c0de:247::3`, and listens on
port 67 and port 547 for what comes back.

Which bridge docker calls `eth0` is not fixed, and nothing depends on it. The
server binds a listener on both, and the exerciser finds each interface by
the address the compose file pinned on it.

The two relay-facing plugins gate on different things, and the stack leans on
that:

- `relay` matches **giaddr** on DHCPv4 and the **datagram source** on DHCPv6.
- `relayinfo` matches the **datagram source** in both families.

So a request sent to the server's `lan` address with giaddr still naming the
allowed relay passes the first gate and fails the second, which is how the
two allow lists are told apart without a third host.

## Services

| service | what it is |
| --- | --- |
| `config-render` | renders `config/*.tmpl` into the config volume and opens up the two volumes a non-root process writes into, then idles |
| `builder` | compiles the exerciser, the mock and the leasehook exec target into a shared volume, then idles |
| `knot` | Knot DNS with the ddns plugin's TSIG key, the `all.test` zone and both reverse zones |
| `redis` | Redis with a password set, so the plugin's AUTH path is used |
| `redis-seed` | writes the one client hash the redis plugin answers from, then idles |
| `helper` | mock NetBox and webhook receiver, and it records every request it gets |
| `server` | coredhcp, built from the repository Dockerfile, `NET_RAW` and `NET_BIND_SERVICE` only |
| `server-ready` | shares the server's network namespace and reports when udp/67 and udp/547 are bound |
| `exerciser` | the test, and the only service that ever exits |

Everything but the exerciser idles on purpose: compose stops honouring
`--exit-code-from exerciser` as soon as some other container exits first, and
the run then never ends.

The lease API and the metrics endpoint bind unix sockets in a shared volume
rather than loopback ports, which is what the plugins' `endpoint` package
calls the whole of their access control. The exerciser reads both over the
socket.

## Scenarios

One line per scenario; 49 of them across the 29 plugins. The exerciser prints
this table with its verdict per line.

| plugin | what it proves |
| --- | --- |
| `metrics` | the exposition counts both families, and the discover counter moves between two scrapes |
| `ratelimit` | a burst of 1200 INFORMs from rotating MAC addresses comes back partly answered |
| `relay` | a relayed DISCOVER naming a giaddr off the allow list is dropped; a Relay-forward from a link-local source is dropped |
| `serverid` | option 54 carries the configured identifier; a REQUEST naming another server is ignored while the same one naming this server is answered; the DHCPv6 reply carries the configured DUID-LL |
| `macfilter` | a denied MAC gets nothing, in either family |
| `leasetime` | option 51 is the configured duration |
| `dns` | option 6 and the DHCPv6 resolvers match the configuration |
| `router` | option 3 matches |
| `netmask` | option 1 matches |
| `mtu` | option 26 matches |
| `ntp` | option 42 and the DHCPv6 NTP server suboption match |
| `searchdomains` | option 119 and the DHCPv6 search list match |
| `staticroute` | option 121 carries the configured route |
| `options` | the generic option 252 is set unconditionally |
| `bootfile` | two client architectures on the same wire get two different files |
| `autoconfigure` | option 116 comes back with the configured value, and a DISCOVER without one is dropped |
| `ipv6only` | option 108 appears only for a client that asked, and that client gets no address |
| `relayinfo` | a circuit-id and an interface-id in the mapping files get their fixed addresses, and the same keys from a source off the allow list are dropped |
| `netbox` | a documented MAC gets the address on its interface in both families, a MAC the API answers 404 for is dropped, and the mock recorded both authenticated lookups |
| `redis` | a MAC with a hash gets its address and the hash's own lease time, in both families |
| `file` | a MAC in each static lease file gets exactly that address |
| `range` | a fresh client gets an address from the pool; RELEASE frees it and DECLINE puts one in probation |
| `subnet` | a relayed DISCOVER is served from the scope mapped to its relay, with that scope's router rather than the top-level one; a relayed DHCPv6 request gets the scope's resolvers |
| `range6` | an IA_NA is answered from the pool, and RELEASE gives the binding back |
| `prefix` | an IA_PD is answered with a prefix of the configured size out of the configured pool |
| `nbp` | option 59 appears exactly once for an ORO that repeats its code a hundred times |
| `ddns` | the A, AAAA, PTR and DHCID records reach the zone; a name another client holds is left alone, and so is a protected one |
| `leasehook` | the webhook arrives with a signature that verifies, for both families, and the exec target writes its line |
| `leaseapi` | the leases are listed under their source names, a released one is gone, and the pool counts the declined address as held back |

`sleep` and `example` are not core plugins and are not here.

Expectations come from the configuration the server was started with. The
exerciser parses the mounted `config.yaml` and compares each reply against
what the plugin line says, so a configuration change the clients do not see
fails a scenario rather than going unchecked.

## Three things the chain order had to work around

**`nbp` ends the chain from every path.** It returns "chain ended" whether it
wrote option 59, wrote nothing because the client did not ask, or was
configured with no URL at all (`plugins/nbp/nbp.go:114,133,140,150`). Any
plugin behind it never runs, allocators included, so it is the last entry in
the DHCPv6 section here. `bootfile`, which documents that it does not end the
chain, serves DHCPv4.

**`autoconfigure` has to sit ahead of the allocators, and then it drops
clients.** It only acts on an OFFER that carries no address, which is every
OFFER until an allocator has run, so behind `range` it can never fire at all:
`range` drops a request it cannot serve rather than offering `0.0.0.0`. Ahead
of the allocators it does fire, and then RFC 2563 section 2.3 has it drop
every DISCOVER that does not carry option 116
(`plugins/autoconfigure/plugin.go:76-94`). Every DHCPv4 client in this stack
sends one. A chain with both `autoconfigure` and `range` is hard to write
sensibly, which is worth knowing before putting one in production.

**`ipv6only` and a release.** `dhcpv4.IsOptionRequested` reads an absent
parameter request list as "the client wants everything", and a DHCPRELEASE
carries no list, so `ipv6only` sees a client asking for option 108, answers
it and ends the chain (`plugins/ipv6only/plugin.go:61-70`). The release never
reaches the allocator and the lease stays until it expires. The exerciser
sends its release with a one-code parameter list to get past that; a real
client cannot.

Two more things worth knowing, which the stack works with rather than around:

- `subnet` is listed after `range`, not before it. Its own documentation says
  to use one or the other; running both, as this stack does to cover on-link
  and relayed clients at once, means the later one wins, because neither ends
  the chain when it allocates.
- On DHCPv6 `relayinfo` adds its IA_NA with `AddOption` and lets the chain
  continue, so `range6` adds a second one behind it and the reply carries two
  IA_NA options for the same IAID. The scenario asserts the mapped address is
  among them rather than that it is the only one.

## Reading a failure

The exerciser prints one line per scenario and then, for each failure, what
it expected, what it got and any notes that scenario collected:

```
  subnet / a relayed DISCOVER is served from the scope mapped to its relay
    the relayed address: 172.31.246.113 is outside 172.31.247.100-172.31.247.120, …
    note: the relayed client was offered 172.31.246.113, router 172.31.247.1
```

Exit codes: 0 all passed, 1 a scenario failed, 2 the stack could not be
reached well enough to start, which usually means a volume or a socket is
missing rather than a plugin misbehaving.

When a run fails, the first thing to do is turn the server's logging up:

```
$ make test-all COREDHCP_LOGLEVEL=debug
```

Every plugin that drops a request says why at that level, which is the
quickest way to find the one that ended the chain. The compose file also
leaves its evidence behind in the `results` volume: `netbox.jsonl` and
`webhook.jsonl` from the mock, and `exec-hook.jsonl` from the leasehook exec
target.

To keep a stack up and poke at it, drive compose directly:

```
$ docker compose -p coredhcp-all-dbg -f test/all/docker-compose.yml up -d server-ready
$ docker compose -p coredhcp-all-dbg -f test/all/docker-compose.yml run --rm exerciser
$ docker compose -p coredhcp-all-dbg -f test/all/docker-compose.yml logs server
$ docker compose -p coredhcp-all-dbg -f test/all/docker-compose.yml down --volumes
```

## Running more than one at a time

The project name and both network prefixes are variables, so parallel CI jobs
and two terminals do not collide:

```
$ make test-all ALL_PROJECT=coredhcp-mr123 ALL_LAN_PREFIX=172.31.248 ALL_RELAY_PREFIX=172.31.249
```

The IPv6 prefixes (`ALL_V6_LAN`, `ALL_V6_RELAY`) and the prefix delegation
pool (`ALL_V6_PD`) are separate variables and have to be moved with them.
Docker allocates container addresses out of an `ip_range` at the top of each
subnet in both families, so nothing it hands out can collide with a static
lease, a DHCP pool or a pinned service address.

## The Go programs

All three live in the root module and are built once, by the `builder`
service, into a volume the other services run them from.

- `exerciser/` is the test. It is the DHCP client, the relay, and the reader
  of the lease API, the metrics socket, Knot and the mock.
- `helper/` stands in for NetBox and for the webhook endpoint, and records
  every request so the exerciser can assert the plugins really called out.
- `leaseexec/` is what the `leasehook` plugin execs. It has to be a static
  binary: it runs inside the distroless server image, which has no shell, so
  the "script" the plugin documentation talks about is not an option there.

The logic worth testing on its own sits in `internal/`: `serverconf` reads
the plugin chain out of the rendered configuration, `dnsquery` is enough of
RFC 1035 to ask Knot for a DHCID record, which `net.Resolver` cannot do, and
`hookverify` is the leasehook signature. All three have unit tests and run
with `go test ./...` like anything else in the repository.
