#!/bin/sh
# udhcpc event script. Docker's IPAM has already addressed eth0, so unlike the
# stock default.script this only logs the conversation.
# busybox ash implements pipefail even though POSIX does not define it.
# shellcheck disable=SC3040
set -euo pipefail

name="${CLIENT_NAME:-client}"

# These variables are exported into the environment by udhcpc.
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
