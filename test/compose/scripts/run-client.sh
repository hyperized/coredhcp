#!/bin/sh
# One DHCP client: ask for a lease, record what came back, then stay alive
# until the checker has had its look.
# busybox ash implements pipefail even though POSIX does not define it.
# shellcheck disable=SC3040
set -euo pipefail

: "${CLIENT_NAME:?set by the compose service}"

script=/tmp/udhcpc-capture.sh
# Copied out of the read-only bind mount so that the executable bit does not
# depend on how the repository was checked out on the host.
cp /src/scripts/udhcpc-capture.sh "$script"
chmod +x "$script"

mac=$(cat /sys/class/net/eth0/address)
echo "${CLIENT_NAME}: mac ${mac}, asking for a lease"

# -f foreground, -q exit once bound, -n give up rather than backgrounding.
# The -t/-T retry budget has to cover the server's startup, since compose only
# waits for its container to start, not for the socket to be bound.
# UDHCPC_EXTRA_ARGS is deliberately unquoted: it carries flags, not a filename.
# shellcheck disable=SC2086
if udhcpc -i eth0 -f -q -n \
    -t "${UDHCPC_TRIES:-10}" -T "${UDHCPC_INTERVAL:-2}" \
    -s "$script" ${UDHCPC_EXTRA_ARGS:-}; then
    echo "${CLIENT_NAME}: lease captured"
else
    # Record the failure so the checker reports it straight away instead of
    # sitting out its timeout waiting for a file that will never appear.
    printf 'status=nolease\nmac=%s\n' "$mac" >"/results/${CLIENT_NAME}.env"
    echo "${CLIENT_NAME}: no lease obtained" >&2
fi

# Idle rather than exit: compose stops honouring `up --exit-code-from checker`
# once any other container has exited first, and the run then never ends. The
# checker must be the only service that exits; teardown kills this sleep.
exec sleep "${SERVICE_LINGER:-3600}"
