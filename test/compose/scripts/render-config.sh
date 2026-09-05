#!/bin/sh
# Render the coredhcp config and the static lease file from the templates in
# config/ into the shared /etc/coredhcp volume.
# busybox ash implements pipefail even though POSIX does not define it.
# shellcheck disable=SC3040
set -euo pipefail

: "${NET:?the /24 network prefix, for example 172.31.240}"
: "${LEASE_TIME:?the lease duration, for example 300s}"
: "${MAC_A:?the MAC address of client-a}"
: "${MAC_B:?the MAC address of client-b}"
: "${MAC_C:?the MAC address of client-c}"

src=/src/config
dst=/etc/coredhcp

render() {
    sed -e "s|@NET@|${NET}|g" \
        -e "s|@LEASE_TIME@|${LEASE_TIME}|g" \
        -e "s|@MAC_A@|${MAC_A}|g" \
        -e "s|@MAC_B@|${MAC_B}|g" \
        -e "s|@MAC_C@|${MAC_C}|g" \
        "$1" >"$2"

    # Fail here instead of letting coredhcp parse a half-rendered config.
    if grep -q '@[A-Z_]\{1,\}@' "$2"; then
        echo "render-config: unsubstituted markers in $2:" >&2
        grep -n '@[A-Z_]\{1,\}@' "$2" >&2
        exit 1
    fi
}

render "$src/config.yml.tmpl" "$dst/config.yaml"
render "$src/leases-v4.txt.tmpl" "$dst/leases-v4.txt"

echo "render-config: static leases for network ${NET}.0/24"
grep -v '^[[:space:]]*#' "$dst/leases-v4.txt" | grep -v '^[[:space:]]*$'
