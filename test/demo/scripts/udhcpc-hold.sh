#!/bin/sh
# Puts the leased address on eth0 next to docker's, because a renewal and a
# release both go out from it (RFC 2131 4.1). Hence NET_ADMIN on those clients.
# busybox ash implements pipefail even though POSIX does not define it.
# shellcheck disable=SC3040
set -euo pipefail

name="${CLIENT_NAME:-client}"
iface="${interface:-eth0}"
# What we added last, so a changed lease does not leave a stale address.
state=/tmp/held-address

drop_held() {
    if [ -s "$state" ]; then
        ip addr del "$(cat "$state")" dev "$iface" 2>/dev/null || true
        : >"$state"
    fi
}

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

# These variables are exported into the environment by udhcpc.
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
