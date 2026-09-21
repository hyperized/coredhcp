#!/bin/sh
# Render every configuration file the all-plugins stack needs from the
# templates in config/, and open up the two volumes that a non-root process
# writes into.
#
# This runs to completion before the server, Knot or the exerciser start; each
# of them waits on this container's healthcheck rather than on its exit, so
# that the exerciser stays the only service that ever exits (see the compose
# file for why that matters).
# busybox ash implements pipefail even though POSIX does not define it.
# shellcheck disable=SC3040
set -euo pipefail

: "${LAN:?the client-side /24 prefix, for example 172.31.246}"
: "${RELAY:?the relay-side /24 prefix, for example 172.31.247}"
: "${V6LAN:?the client-side IPv6 /64 prefix without ::, for example fd00:c0de:246}"
: "${V6RELAY:?the relay-side IPv6 /64 prefix without ::, for example fd00:c0de:247}"
: "${V6PD:?the prefix delegation pool, for example fd00:c0de:2460::/48}"
: "${LEASE_TIME:?the lease duration, for example 5m}"
: "${RATE:?the per-client rate, for example 100/s}"
: "${RATE_BURST:?the per-client bucket size, for example 200}"
: "${RATE_GLOBAL:?the shared rate, for example 100/s}"
: "${V6ONLY_WAIT:?the RFC 8925 v6-only-wait, for example 300s}"
: "${MAC_DENIED:?the MAC the macfilter plugin denies}"
: "${MAC_FILE:?the MAC with a static DHCPv4 lease}"
: "${MAC_FILE6:?the MAC with a static DHCPv6 lease}"
: "${CIRCUIT_ID:?the option 82 circuit-id relayinfo maps}"
: "${INTERFACE_ID:?the DHCPv6 interface-id relayinfo maps}"
: "${HELPER_HOST:?the hostname of the NetBox and webhook mock}"
: "${HELPER_PORT:?the port the mock listens on}"
: "${REDIS_HOST:?the hostname of the Redis server}"
: "${KNOT_IP:?the address of the Knot DNS server, a literal}"
: "${SERVER_DUID_MAC:?the link-layer address the DHCPv6 server identifier is built from}"
: "${DDNS_TSIG_SECRET:?the base64 TSIG secret shared with Knot}"

src=/src/config

# v4_reverse turns a three-octet prefix into its in-addr.arpa zone name.
v4_reverse() {
    echo "$1" | awk -F. '
        NF != 3 { print "render-config: " $0 " is not a three-octet prefix" > "/dev/stderr"; exit 1 }
        { print $3 "." $2 "." $1 ".in-addr.arpa" }
    '
}

# v6_reverse turns an IPv6 /64 prefix written as one to four colon-separated
# groups into its ip6.arpa zone name. A "::" in the input is rejected rather
# than guessed at: the zone name depends on every nibble, and an elided run
# does not say how many of them there are.
v6_reverse() {
    echo "$1" | awk '
        /::/ { print "render-config: write the prefix without ::, as fd00:c0de:246" > "/dev/stderr"; exit 1 }
        {
            n = split($0, g, ":")
            if (n < 1 || n > 4) {
                print "render-config: " $0 " is not one to four IPv6 groups" > "/dev/stderr"
                exit 1
            }
            s = ""
            for (i = 1; i <= 4; i++) {
                v = (i <= n && g[i] != "") ? g[i] : "0"
                if (length(v) > 4) {
                    print "render-config: " v " is not a hex group" > "/dev/stderr"
                    exit 1
                }
                s = s substr("0000", 1, 4 - length(v)) v
            }
            out = ""
            for (i = length(s); i >= 1; i--) out = out substr(s, i, 1) "."
            print tolower(out) "ip6.arpa"
        }
    '
}

REV4_ZONE=$(v4_reverse "$LAN")
REV6_ZONE=$(v6_reverse "$V6LAN")

# render <template> <destination>: substitute every marker, then refuse to
# hand over a file that still holds one. A half-rendered config is worse than
# no config: coredhcp would parse it and fail somewhere unrelated.
render() {
    sed -e "s|@LAN@|${LAN}|g" \
        -e "s|@RELAY@|${RELAY}|g" \
        -e "s|@V6LAN@|${V6LAN}|g" \
        -e "s|@V6RELAY@|${V6RELAY}|g" \
        -e "s|@V6PD@|${V6PD}|g" \
        -e "s|@LEASE_TIME@|${LEASE_TIME}|g" \
        -e "s|@RATE@|${RATE}|g" \
        -e "s|@RATE_BURST@|${RATE_BURST}|g" \
        -e "s|@RATE_GLOBAL@|${RATE_GLOBAL}|g" \
        -e "s|@V6ONLY_WAIT@|${V6ONLY_WAIT}|g" \
        -e "s|@MAC_DENIED@|${MAC_DENIED}|g" \
        -e "s|@MAC_FILE6@|${MAC_FILE6}|g" \
        -e "s|@MAC_FILE@|${MAC_FILE}|g" \
        -e "s|@CIRCUIT_ID@|${CIRCUIT_ID}|g" \
        -e "s|@INTERFACE_ID@|${INTERFACE_ID}|g" \
        -e "s|@HELPER_HOST@|${HELPER_HOST}|g" \
        -e "s|@HELPER_PORT@|${HELPER_PORT}|g" \
        -e "s|@REDIS_HOST@|${REDIS_HOST}|g" \
        -e "s|@KNOT_IP@|${KNOT_IP}|g" \
        -e "s|@SERVER_DUID_MAC@|${SERVER_DUID_MAC}|g" \
        -e "s|@DDNS_TSIG_SECRET@|${DDNS_TSIG_SECRET}|g" \
        -e "s|@REV4_ZONE@|${REV4_ZONE}|g" \
        -e "s|@REV6_ZONE@|${REV6_ZONE}|g" \
        "$1" >"$2"

    if grep -q '@[A-Z0-9_]\{1,\}@' "$2"; then
        echo "render-config: unsubstituted markers in $2:" >&2
        grep -n '@[A-Z0-9_]\{1,\}@' "$2" >&2
        exit 1
    fi
}

render "$src/leases-v4.txt.tmpl" /etc/coredhcp/leases-v4.txt
render "$src/leases-v6.txt.tmpl" /etc/coredhcp/leases-v6.txt
render "$src/relayinfo-v4.txt.tmpl" /etc/coredhcp/relayinfo-v4.txt
render "$src/relayinfo-v6.txt.tmpl" /etc/coredhcp/relayinfo-v6.txt
render "$src/subnets.yml.tmpl" /etc/coredhcp/subnets.yml

render "$src/all.test.zone.tmpl" /zones/all.test.zone
render "$src/rev.zone.tmpl" /zones/rev4.zone
render "$src/rev.zone.tmpl" /zones/rev6.zone
render "$src/knot.conf.tmpl" /etc/knot/knot.conf

# Knot drops to knot:knot and reads these; they carry no secret of their own.
chmod 0644 /zones/*.zone
# knot.conf carries the TSIG secret, so it stays readable by its own user
# only. Knot reads it as root before dropping privileges.
chmod 0640 /etc/knot/knot.conf

# Named volumes arrive owned by root, and both the server (uid 65532) and the
# program the leasehook plugin execs have to write into these. A test stack,
# not a deployment: nothing here is reachable from outside the compose
# network.
chmod 0777 /run/coredhcp /results

# The config is rendered last, because the server's healthcheck dependency
# waits on exactly this file: when it exists, everything above it is done.
render "$src/config.yml.tmpl" /etc/coredhcp/config.yaml

echo "render-config: client network ${LAN}.0/24 ${V6LAN}::/64, relay network ${RELAY}.0/24 ${V6RELAY}::/64"
echo "render-config: reverse zones ${REV4_ZONE} and ${REV6_ZONE}"
