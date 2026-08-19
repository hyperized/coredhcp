#!/bin/sh
# Reads what the clients captured and asserts it against the server's own
# rendered configuration: every MAC with a static lease must have been offered
# exactly that address, every other client an address out of the range pool,
# and all of them the same router, netmask, DNS, server id and lease time the
# server was configured with.
#
# Prints a table and exits non-zero on any mismatch.
# busybox ash implements pipefail even though POSIX does not define it.
# shellcheck disable=SC3040
set -euo pipefail

conf=/etc/coredhcp/config.yaml
leases=/etc/coredhcp/leases-v4.txt
results=/results
timeout="${CHECK_TIMEOUT:-90}"
details=/tmp/checker-details

: "${EXPECTED_CLIENTS:?space separated list of client service names}"
# Padded with spaces so a plain substring test cannot match a partial name.
dynamic_clients=" ${DYNAMIC_CLIENTS:-} "

for f in "$conf" "$leases"; do
    [ -f "$f" ] || {
        echo "checker: $f is missing, did config-render run?" >&2
        exit 1
    }
done

# Expectations come from the server's configuration rather than a second copy
# of the same values, so a config change that the clients do not see shows up
# as a failure here. This is a narrow parse of the "- <plugin>: <args>" lines
# of a file rendered from a template in this directory, not a YAML parser.
plugin_args() {
    sed -n "s/^[[:space:]]*-[[:space:]]*$1:[[:space:]]*//p" "$conf" | head -n 1
}

want_serverid=$(plugin_args server_id)
want_dns=$(plugin_args dns)
want_router=$(plugin_args router)
want_subnet=$(plugin_args netmask)
want_lease=$(plugin_args lease_time | tr -d 's')
pool_start=$(plugin_args range | awk '{print $2}')
pool_end=$(plugin_args range | awk '{print $3}')

# value <file> <key>: reads one key from a captured result file.
value() {
    sed -n "s/^$2=//p" "$1" | head -n 1
}

# lease_for_mac <mac>: the statically configured address for a MAC, empty if
# the MAC has no static lease.
lease_for_mac() {
    awk -v mac="$1" '
        { sub(/#.*/, "") }
        NF >= 2 && tolower($1) == tolower(mac) { print $2; exit }
    ' "$leases"
}

ip_to_int() {
    echo "$1" | awk -F. '{ printf "%d\n", ($1 * 16777216) + ($2 * 65536) + ($3 * 256) + $4 }'
}

in_pool() {
    [ -n "$1" ] || return 1
    _ip=$(ip_to_int "$1")
    [ "$_ip" -ge "$(ip_to_int "$pool_start")" ] && [ "$_ip" -le "$(ip_to_int "$pool_end")" ]
}

echo "checker: expectations read from $conf"
printf '  %-10s %s\n' \
    "server id" "$want_serverid" \
    "router" "$want_router" \
    "netmask" "$want_subnet" \
    "dns" "$want_dns" \
    "lease" "${want_lease}s" \
    "pool" "$pool_start - $pool_end"
echo

# Wait for every client to report. A client that failed to get a lease writes a
# result too, so this normally only waits for the DHCP exchange itself.
deadline=$(($(date +%s) + timeout))
while :; do
    missing=
    for client in $EXPECTED_CLIENTS; do
        [ -f "$results/$client.env" ] || missing="$missing $client"
    done
    [ -n "$missing" ] || break
    if [ "$(date +%s)" -ge "$deadline" ]; then
        echo "checker: timed out after ${timeout}s waiting for:$missing" >&2
        break
    fi
    sleep 1
done

: >"$details"
failures=0
offered_ips=

printf '%-15s %-18s %-16s %-16s %-22s %s\n' CLIENT MAC EXPECTED OFFERED OPTIONS RESULT
printf '%s\n' "----------------------------------------------------------------------------------------------------"

for client in $EXPECTED_CLIENTS; do
    file="$results/$client.env"
    if [ ! -f "$file" ]; then
        printf '%-15s %-18s %-16s %-16s %-22s %s\n' "$client" - - - no-result FAIL
        echo "$client: no result file, the client never reported" >>"$details"
        failures=$((failures + 1))
        continue
    fi

    status=$(value "$file" status)
    mac=$(value "$file" mac)
    ip=$(value "$file" ip)
    problems=

    case "$dynamic_clients" in
    *" $client "*)
        expected="<pool>"
        in_pool "$ip" || problems="${problems},ip-outside-pool"
        ;;
    *)
        expected=$(lease_for_mac "$mac")
        if [ -z "$expected" ]; then
            expected="<none>"
            problems="${problems},no-static-lease"
        elif [ "$ip" != "$expected" ]; then
            problems="${problems},ip"
        fi
        ;;
    esac

    [ "$status" = bound ] || problems="${problems},status=${status:-empty}"
    [ "$(value "$file" router)" = "$want_router" ] || problems="${problems},router"
    [ "$(value "$file" subnet)" = "$want_subnet" ] || problems="${problems},netmask"
    [ "$(value "$file" dns)" = "$want_dns" ] || problems="${problems},dns"
    [ "$(value "$file" serverid)" = "$want_serverid" ] || problems="${problems},serverid"
    [ "$(value "$file" lease)" = "$want_lease" ] || problems="${problems},lease"

    if [ -z "$problems" ]; then
        result=PASS
        problems=ok
    else
        result=FAIL
        problems=${problems#,}
        failures=$((failures + 1))
        {
            echo "$client: $problems"
            sed 's/^/    /' "$file"
        } >>"$details"
    fi

    printf '%-15s %-18s %-16s %-16s %-22s %s\n' \
        "$client" "${mac:--}" "$expected" "${ip:--}" "$problems" "$result"
    [ -z "$ip" ] || offered_ips="$offered_ips $ip"
done

# Two clients holding the same address means the server handed out a lease
# twice, which the per-client checks above cannot see on their own.
# Unquoted on purpose: the list is split into one address per line.
# shellcheck disable=SC2086
duplicates=$(printf '%s\n' $offered_ips | sort | uniq -d)
if [ -n "$duplicates" ]; then
    failures=$((failures + 1))
    # shellcheck disable=SC2086
    echo "duplicate addresses offered: $(echo $duplicates | tr '\n' ' ')" >>"$details"
fi

echo
if [ "$failures" -eq 0 ]; then
    # shellcheck disable=SC2086
    echo "checker: PASS, all $(echo $EXPECTED_CLIENTS | wc -w) clients got the lease their MAC maps to"
    exit 0
fi

echo "checker: FAIL, $failures problem(s)" >&2
cat "$details" >&2
exit 1
