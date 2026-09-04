# demo stack

A docker compose stack for looking at the terminal UI while something is
actually happening. The server runs in the foreground with the UI on your
terminal, and seven busybox clients on the same bridge keep it fed with
requests: leases taken and released, a client that renews, one that is denied
by MAC, and one that changes its address until the pool is empty.

Nothing here decides pass or fail. For that there is `test/compose`, which runs
the same kind of stack with a checker in it and is what `make test-compose`
uses.

## Running it

    make demo

That builds the image (the first build takes a few minutes, later ones are
cached), starts the clients detached, and then runs the server in the
foreground. Press `q`, `Esc` or `Ctrl-C` in the UI to quit. The server process
is the UI, so quitting it stops serving DHCP, and the Makefile tears the whole
stack down afterwards whether it ended on `q` or on an error.

The clients start before the server does. The first thing you see is a few
seconds of retries, which is worth watching once: it is the same traffic a
client sends when a server has just gone away.

## The clients

| service | what it shows |
| --- | --- |
| `client-a` | static lease from the `file` plugin: discover, offer, request, ack, five seconds of holding it, release, then seven seconds of quiet |
| `client-b` | the same on an eleven second cycle, but with the broadcast flag set, so the reply comes back as a UDP broadcast instead of a layer-2 unicast |
| `client-c` | the same on a thirteen second cycle |
| `client-renew` | takes one lease and keeps it, renewing at half the lease time, so every 30 seconds |
| `client-dynamic` | no static lease for its MAC, so it falls through to `range` and gets a pool address, on a nine second cycle |
| `client-denied` | its MAC is on the `macfilter` deny list. Every request is dropped, and the UI names macfilter as the plugin that ended the chain |
| `client-churn` | a new random MAC every 4 seconds and never a release. It empties the ten address pool in well under a minute, after which `range` has nothing left to give until the leases expire |

The intervals are coprime on purpose, so the clients drift in and out of step
instead of settling into one repeating pattern.

Give it a minute and a half before you judge what you are looking at. That is
long enough for the pool to run dry, for the sweep to reclaim the expired
leases, and for the churn client to start getting addresses again.

## The address plan

Everything follows one prefix, `172.31.242` by default.

| address | what it is |
| --- | --- |
| `.1` | the bridge, advertised as the router and the NTP server |
| `.2` | the server, and the server id in the replies |
| `.11` to `.13` | the static leases for client-a, client-b and client-c |
| `.100` to `.109` | the `range` plugin's pool |
| `.192/26` | what docker's own IPAM hands the containers, kept away from the rest |

The MAC addresses live in the compose file as YAML anchors and are passed to
the config renderer from there, so a client's hardware address, its static
lease and the deny list cannot drift apart. The churn client is the exception:
compose gives it a starting address and the client script rewrites it, always
keeping the `02:00:00:cb` prefix so its requests are recognisable in the UI.

## Knobs

All of them have defaults, so `make demo` needs no setup.

| variable | default | what it does |
| --- | --- | --- |
| `DEMO_PROJECT` | `coredhcp-demo` | compose project name |
| `DEMO_NET_PREFIX` | `172.31.242` | the /24 the stack runs on. Change it to run next to `test/compose`, which uses `172.31.240` |
| `DHCP_LEASE_TIME` | `60s` | lease time. Longer makes the pool last, and makes you wait for a renewal |
| `COREDHCP_LOGLEVEL` | `info` | the server's log level, which the UI's log pane shows. `debug` is worth a look |
| `BUSYBOX_TAG` | `1.37.0` | the client image tag |
| `TERM` | your terminal's, or `xterm-256color` | passed into the server container so the UI knows what it is drawing on |

The rendered config also puts the `metrics` plugin on `127.0.0.1:9754` inside
the server container. Nothing scrapes it and nothing is published to the host;
it is in the chain so the plugins pane has it to show.

## What is in here

    Dockerfile              builds cmd/coredhcp-tui, which the repo Dockerfile does not
    docker-compose.yml      the stack: config renderer, server, seven clients
    config/*.tmpl           server config and static lease file, rendered at startup
    scripts/render-config.sh    fills the templates in from the environment
    scripts/run-client.sh       one client, behaviour set by CLIENT_MODE
    scripts/udhcpc-noop.sh      udhcpc event script that configures nothing
    scripts/udhcpc-hold.sh      the same, but keeps the leased address on eth0

Two things a DHCP client does are sent from the address it was given: the
unicast request that renews a lease, and the release that gives one back. So
every client that renews or releases has to actually hold its address, which is
what `udhcpc-hold.sh` is for and why those clients have `NET_ADMIN`. Skip it
and the renewal is answered by unicast to an address nobody owns (RFC 2131
section 4.1), the client decides the lease is lost, and the release never
leaves the machine at all. client-churn also has `NET_ADMIN`, for the different
reason that it rewrites its own MAC. client-denied has neither: it is refused
before it is ever offered anything.
