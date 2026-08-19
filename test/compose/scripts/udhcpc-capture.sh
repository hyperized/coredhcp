#!/bin/sh
# udhcpc event script.
#
# Docker's IPAM has already addressed eth0, so this deliberately does not
# configure the interface the way the stock /usr/share/udhcpc/default.script
# would. It only records what the server offered, for the checker to assert on.
# busybox ash implements pipefail even though POSIX does not define it.
# shellcheck disable=SC3040
set -euo pipefail

case "${1:-}" in
bound | renew) ;;
*)
    # deconfig, leasefail and nak carry no lease worth recording.
    exit 0
    ;;
esac

: "${CLIENT_NAME:?set by the compose service}"

out="/results/${CLIENT_NAME}.env"
tmp="${out}.tmp"

# The variables below are exported by udhcpc: $ip is the assigned address,
# $subnet the netmask, $lease the lease time in seconds, $serverid option 54.
{
    printf 'status=%s\n' "$1"
    printf 'mac=%s\n' "$(cat "/sys/class/net/${interface:-eth0}/address")"
    printf 'ip=%s\n' "${ip:-}"
    printf 'subnet=%s\n' "${subnet:-}"
    printf 'router=%s\n' "${router:-}"
    printf 'dns=%s\n' "${dns:-}"
    printf 'serverid=%s\n' "${serverid:-}"
    printf 'lease=%s\n' "${lease:-}"
    printf 'siaddr=%s\n' "${siaddr:-}"
} >"$tmp"

# Rename into place so the checker can never read a half-written file.
mv "$tmp" "$out"
