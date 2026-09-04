#!/bin/sh
# udhcpc event script for the demo clients.
#
# Docker's IPAM has already addressed eth0, so this deliberately does not
# configure the interface the way the stock /usr/share/udhcpc/default.script
# would: the demo wants the DHCP conversation, not a reconfigured container.
# It prints one line per event, which shows up in `docker compose logs` for the
# client; the server's side of the same exchange is what the UI draws.
# busybox ash implements pipefail even though POSIX does not define it.
# shellcheck disable=SC3040
set -euo pipefail

name="${CLIENT_NAME:-client}"

# The variables below are exported by udhcpc: $ip is the assigned address,
# $lease the lease time in seconds, $serverid option 54.
case "${1:-}" in
bound | renew)
    echo "${name}: $1 ${ip:-} for ${lease:-?}s from ${serverid:-?}"
    ;;
leasefail)
    echo "${name}: no lease offered" >&2
    ;;
nak)
    echo "${name}: NAK from ${serverid:-?}" >&2
    ;;
*)
    # deconfig fires before the first request and on the way out.
    ;;
esac
