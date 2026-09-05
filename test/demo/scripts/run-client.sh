#!/bin/sh
# One demo DHCP client; CLIENT_MODE picks what it does and no mode stops on its
# own. cycle avoids udhcpc -q, because only a held lease can be released.
#
# busybox ash implements pipefail even though POSIX does not define it.
# shellcheck disable=SC3040
set -euo pipefail

: "${CLIENT_NAME:?set by the compose service}"
mode="${CLIENT_MODE:-cycle}"

# Copied out of the read-only mount so the exec bit does not depend on how the
# repository was checked out on the host.
script=/tmp/udhcpc-event.sh
cp "/src/scripts/${UDHCPC_SCRIPT:-udhcpc-noop.sh}" "$script"
chmod +x "$script"

log() { echo "${CLIENT_NAME}: $*"; }

kill_quietly() {
    [ -n "${1:-}" ] || return 0
    kill "$1" 2>/dev/null || true
}

# Everything slow runs in the background and is waited on, so a teardown signal
# is acted on at once instead of after the current udhcpc or sleep.
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

# The -t/-T retry budget has to cover the server's startup: the clients start
# first on purpose. UDHCPC_EXTRA_ARGS is unquoted deliberately, it carries flags.
udhcpc_start() {
    # shellcheck disable=SC2086
    udhcpc -i eth0 -f -s "$script" \
        -t "${UDHCPC_TRIES:-10}" -T "${UDHCPC_INTERVAL:-2}" \
        ${UDHCPC_EXTRA_ARGS:-} "$@" &
    dhcp=$!
}

# SIGTERM is what makes a bound udhcpc release its lease and go.
udhcpc_stop() {
    [ -n "$dhcp" ] || return 0
    kill_quietly "$dhcp"
    wait "$dhcp" 2>/dev/null || true
    dhcp=
}

udhcpc_wait() {
    status=0
    wait "$dhcp" || status=$?
    dhcp=
    return "$status"
}

# A fixed prefix, so churn requests are recognisable in the UI. /dev/urandom
# rather than $RANDOM, which busybox ash only has when it was built with it.
random_mac() {
    printf '%s:%02x:%02x\n' "${CHURN_MAC_PREFIX:-02:00:00:cb}" \
        "$(od -An -N1 -tu1 /dev/urandom | tr -d ' ')" \
        "$(od -An -N1 -tu1 /dev/urandom | tr -d ' ')"
}

# The interface goes down and up around the change: docker's address survives,
# and udhcpc asks over a raw socket, so the lost routes are not missed.
set_mac() {
    ip link set dev eth0 down
    ip link set dev eth0 address "$1"
    ip link set dev eth0 up
}

log "mode ${mode}, mac $(cat /sys/class/net/eth0/address)"

case "$mode" in
cycle)
    while :; do
        # -R releases the lease when udhcpc is told to stop.
        udhcpc_start -R
        nap "${CLIENT_HOLD:-5}"
        udhcpc_stop
        nap "${CLIENT_INTERVAL:-7}"
    done
    ;;
renew)
    # No -q and no -n, so udhcpc stays up and renews on its own; -R so the
    # teardown still ends with a release.
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
        # No -R: the lease is abandoned, which is what fills the pool.
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
