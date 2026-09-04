#!/bin/sh
# udhcpc event script for the clients that do more with a lease than look at
# it: the ones that release it and the one that renews it.
#
# client-denied and client-churn use udhcpc-noop.sh and never touch the
# interface, because docker has already addressed eth0 and they have nothing to
# hold on to. The other two things a client does with a lease both go out from
# the leased address, so they need it to be there:
#
#   renewal  at half the lease time udhcpc sends a unicast REQUEST from the
#            address, and a request carrying a ciaddr is answered by unicast to
#            that address (RFC 2131 section 4.1). Without the address the reply
#            never lands, the client decides the lease is lost, and it starts
#            over with a discover every minute.
#   release  the DHCPRELEASE is unicast to the server from the address as well.
#            Without it udhcpc says "sending release" and then fails to bind
#            the socket, and the server never hears about it.
#
# So this script puts the leased address on eth0 next to the one docker gave
# it, and takes it off again when the lease goes. It is why those clients have
# NET_ADMIN.
# busybox ash implements pipefail even though POSIX does not define it.
# shellcheck disable=SC3040
set -euo pipefail

name="${CLIENT_NAME:-client}"
iface="${interface:-eth0}"
# What we added last, so a changed lease does not leave a stale address behind.
state=/tmp/held-address

drop_held() {
    if [ -s "$state" ]; then
        ip addr del "$(cat "$state")" dev "$iface" 2>/dev/null || true
        : >"$state"
    fi
}

# prefix_len <dotted netmask>: 255.255.255.0 becomes 24, by counting bits.
prefix_len() {
    bits=0
    for octet in $(echo "${1:-255.255.255.0}" | tr '.' ' '); do
        while [ "$octet" -gt 0 ]; do
            bits=$((bits + octet % 2))
            octet=$((octet / 2))
        done
    done
    echo "$bits"
}

# The variables below are exported by udhcpc: $ip is the assigned address,
# $subnet the netmask, $lease the lease time in seconds, $serverid option 54.
case "${1:-}" in
bound | renew)
    [ -n "${ip:-}" ] || exit 0

    held="${ip}/$(prefix_len "${subnet:-255.255.255.0}")"
    if [ "$held" != "$(cat "$state" 2>/dev/null || true)" ]; then
        drop_held
        ip addr add "$held" dev "$iface"
        echo "$held" >"$state"
    fi

    echo "${name}: $1 ${ip} for ${lease:-?}s from ${serverid:-?}"
    ;;
deconfig | leasefail)
    drop_held
    ;;
nak)
    drop_held
    echo "${name}: NAK from ${serverid:-?}" >&2
    ;;
esac
