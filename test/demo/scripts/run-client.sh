#!/bin/sh
# One demo DHCP client. CLIENT_MODE picks what it does, and none of the modes
# stop on their own: the stack ends when the operator quits the UI.
#
#   cycle  take a lease, hold it for CLIENT_HOLD seconds, release it, wait
#          CLIENT_INTERVAL seconds, start over. That is the whole round trip:
#          discover, offer, request, ack, release.
#   renew  take one lease and keep it. udhcpc renews at half the lease time,
#          so a 60 second lease means a renewal every 30 seconds.
#   churn  a new random MAC every CHURN_INTERVAL seconds, one lease per MAC,
#          never released. The pool runs dry, the range plugin starts saying
#          no, and the addresses only come back as the leases expire.
#
# The release is why cycle mode does not use udhcpc's -q. udhcpc only releases
# a lease it currently holds, so the run is ended with SIGTERM after the hold
# instead of quitting the moment the ACK lands. It also has to own the address
# it was given, or the release cannot be sent from it: see udhcpc-hold.sh.
#
# busybox ash implements pipefail even though POSIX does not define it.
# shellcheck disable=SC3040
set -euo pipefail

: "${CLIENT_NAME:?set by the compose service}"
mode="${CLIENT_MODE:-cycle}"

# The event script udhcpc runs on every lease event. Most clients get the one
# that configures nothing; the ones that renew or release ask for
# udhcpc-hold.sh instead. Copied out of the read-only bind mount so that the
# executable bit does not depend on how the repository was checked out on the
# host.
script=/tmp/udhcpc-event.sh
cp "/src/scripts/${UDHCPC_SCRIPT:-udhcpc-noop.sh}" "$script"
chmod +x "$script"

log() { echo "${CLIENT_NAME}: $*"; }

kill_quietly() {
    [ -n "${1:-}" ] || return 0
    kill "$1" 2>/dev/null || true
}

# Everything that takes time runs in the background and is waited on, so a
# teardown signal is acted on right away instead of after the current udhcpc or
# sleep has run its course. Without it every `docker compose down` would sit
# out the ten second kill timeout, once per client.
dhcp=
waiting=

quit() {
    kill_quietly "$dhcp"
    kill_quietly "$waiting"
    exit 0
}
trap quit TERM INT

nap() {
    sleep "$1" &
    waiting=$!
    wait "$waiting" || true
    waiting=
}

# udhcpc_start <extra args...>: start one udhcpc run.
# -f keeps it from daemonizing, -s names the event script. The -t/-T retry
# budget has to cover the server's startup: the clients are started before it
# on purpose, so those retries are part of what there is to see.
# UDHCPC_EXTRA_ARGS is deliberately unquoted: it carries flags, not a filename.
udhcpc_start() {
    # shellcheck disable=SC2086
    udhcpc -i eth0 -f -s "$script" \
        -t "${UDHCPC_TRIES:-10}" -T "${UDHCPC_INTERVAL:-2}" \
        ${UDHCPC_EXTRA_ARGS:-} "$@" &
    dhcp=$!
}

# udhcpc_stop: SIGTERM is what makes a bound udhcpc release its lease and go,
# which is the last message of a cycle. A run that already ended on its own is
# simply reaped here.
udhcpc_stop() {
    [ -n "$dhcp" ] || return 0
    kill_quietly "$dhcp"
    wait "$dhcp" 2>/dev/null || true
    dhcp=
}

# udhcpc_wait: for the runs that end by themselves. Returns their status.
udhcpc_wait() {
    status=0
    wait "$dhcp" || status=$?
    dhcp=
    return "$status"
}

# random_mac: a locally administered address with a fixed prefix, so the churn
# client's requests are recognisable at a glance in the UI, and two random
# octets after it. /dev/urandom rather than $RANDOM, which busybox ash only has
# when it was built with it.
random_mac() {
    printf '%s:%02x:%02x\n' "${CHURN_MAC_PREFIX:-02:00:00:cb}" \
        "$(od -An -N1 -tu1 /dev/urandom | tr -d ' ')" \
        "$(od -An -N1 -tu1 /dev/urandom | tr -d ' ')"
}

# set_mac <address>: needs NET_ADMIN. The interface goes down and up around the
# change; the address docker gave it survives that, and udhcpc asks over a raw
# socket, so the routes that do not survive are not missed.
set_mac() {
    ip link set dev eth0 down
    ip link set dev eth0 address "$1"
    ip link set dev eth0 up
}

log "mode ${mode}, mac $(cat /sys/class/net/eth0/address)"

case "$mode" in
cycle)
    while :; do
        # -R releases the lease when udhcpc is told to stop, which is what
        # udhcpc_stop does once the hold is over.
        udhcpc_start -R
        nap "${CLIENT_HOLD:-5}"
        udhcpc_stop
        nap "${CLIENT_INTERVAL:-7}"
    done
    ;;
renew)
    # No -q and no -n: udhcpc stays up, renews on its own, and keeps trying if
    # the server is not there yet. -R so the teardown ends with a release.
    while :; do
        udhcpc_start -R
        udhcpc_wait || log "udhcpc exited, starting over"
        nap "${CLIENT_INTERVAL:-5}"
    done
    ;;
churn)
    while :; do
        mac=$(random_mac)
        set_mac "$mac"
        # -q quit once bound, -n give up rather than retrying forever, and no
        # -R: the lease is abandoned, which is what fills the pool.
        udhcpc_start -q -n
        if udhcpc_wait; then
            log "took a lease as ${mac}"
        else
            log "no lease as ${mac}, the pool is full or the server is not up yet"
        fi
        nap "${CHURN_INTERVAL:-4}"
    done
    ;;
*)
    echo "${CLIENT_NAME}: unknown CLIENT_MODE '${mode}'" >&2
    exit 1
    ;;
esac
