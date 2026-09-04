# tui

The terminal interface for the DHCP server. It shows what the server is doing
right now: the sockets it bound, the plugin chain per family, every request it
handled with the reply that went out, the addresses that were offered and
acknowledged, per-family counters, a request rate over the last minute, and the
server's own log.

The package implements `events.Observer`, so the server reports to it directly.
`Request` is called on the packet path from one goroutine per packet, so it
takes a single lock, folds the event into the model and returns. Rendering runs
on its own ticker from a snapshot of that model, and only when something
changed.

## Keys

| key | what it does |
| --- | --- |
| `q`, `Esc`, `Ctrl-C` | quit |
| `p` | freeze the traffic pane, collection keeps running |
| `Tab`, `Shift-Tab` | move focus between panes |
| `1` `2` `3` `4` | focus traffic, leases, plugins, log |
| `↑` `↓` `PgUp` `PgDn` | scroll the focused pane |
| `Home`, `End` | jump to the oldest or newest row, `End` resumes following |
| `c` | clear the traffic ring, the counters and the rate history |
| `?` | help overlay, any key closes it |

The focused pane is the one whose title is yellow. The traffic and log panes
follow their newest row until you scroll away from it.

## Where the lease states come from

The server does not tell the UI what a plugin wrote to its lease database, and
a plugin only sees the requests that reach its position in the chain. So the
lease table is read out of the exchange itself, keyed on the family and the
client identifier. On DHCPv4 a DISCOVER answered with an OFFER is *issued*, a
REQUEST acknowledged with an address is *confirmed*, a REQUEST answered with a
NAK is *refused*, a RELEASE is *released*, and a DECLINE is *declined*. On
DHCPv6 a SOLICIT answered with an ADVERTISE is issued, a REPLY carrying
addresses confirms one (including the rapid-commit REPLY to a SOLICIT), a REPLY
with no addresses to a REQUEST, RENEW or REBIND is refused, and a RELEASE is
released. An INFORM or an INFORMATION-REQUEST carries no lease and is ignored.

That means the table is what the server said on the wire, not what any plugin
believes it stored. A lease handed out by a plugin before the UI started, or by
a different server, is not in it. The countdown in the lease column is the
event's own timestamp plus the lease time the reply carried, so it goes stale
the same way a client's does.

## Bounds

Everything the UI keeps is bounded, and the defaults are set with
`WithHistory`, `WithMaxLeases` and `WithLogLines`. The traffic and log rings
drop their oldest entry; the lease table drops the client it has not seen for
the longest. Hostnames, client identifiers and error strings come off the wire,
so they are cut to a display length before they are stored and escaped before
they are drawn.
