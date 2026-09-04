#!/bin/sh
# Render the coredhcp configuration and the static lease file from the
# templates in config/ into the shared /etc/coredhcp volume. This runs to
# completion before the server container starts.
# busybox ash implements pipefail even though POSIX does not define it.
# shellcheck disable=SC3040
set -euo pipefail

: "${NET:?the /24 network prefix, for example 172.31.242}"
: "${LEASE_TIME:?the lease duration, for example 60s}"
: "${MAC_A:?the MAC address of client-a}"
: "${MAC_B:?the MAC address of client-b}"
: "${MAC_C:?the MAC address of client-c}"
: "${MAC_DENIED:?the MAC address macfilter must deny}"

src=/src/config
dst=/etc/coredhcp

render() {
    sed -e "s|@NET@|${NET}|g" \
        -e "s|@LEASE_TIME@|${LEASE_TIME}|g" \
        -e "s|@MAC_A@|${MAC_A}|g" \
        -e "s|@MAC_B@|${MAC_B}|g" \
        -e "s|@MAC_C@|${MAC_C}|g" \
        -e "s|@MAC_DENIED@|${MAC_DENIED}|g" \
        "$1" >"$2"

    # A marker left in the output means the template asks for a value this
    # script does not substitute. Fail here instead of letting coredhcp parse a
    # half-rendered config.
    if grep -q '@[A-Z_]\{1,\}@' "$2"; then
        echo "render-config: unsubstituted markers in $2:" >&2
        grep -n '@[A-Z_]\{1,\}@' "$2" >&2
        exit 1
    fi
}

render "$src/config.yml.tmpl" "$dst/config.yaml"
render "$src/leases-v4.txt.tmpl" "$dst/leases-v4.txt"

echo "render-config: network ${NET}.0/24, lease time ${LEASE_TIME}, denying ${MAC_DENIED}"
grep -v '^[[:space:]]*#' "$dst/leases-v4.txt" | grep -v '^[[:space:]]*$'
