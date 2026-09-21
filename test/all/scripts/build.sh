#!/bin/sh
# Build the three Go programs the stack runs into the shared /out volume.
#
# They are built once here rather than per service because three containers
# need them and one of them, the leasehook exec target, runs inside the
# distroless server image, which has no toolchain and no shell. A static
# binary is the only thing that image can execute.
set -eu

: "${OUT:=/out}"

cd /src

for prog in helper exerciser leaseexec; do
    echo "build: ./test/all/${prog}"
    CGO_ENABLED=0 go build -o "${OUT}/${prog}" "./test/all/${prog}"
done

# The server runs as uid 65532 and execs lease-exec, so it has to be readable
# and executable by everyone. The name differs from the package directory
# because the plugin's exec: argument is what an operator reads.
mv "${OUT}/leaseexec" "${OUT}/lease-exec"
chmod 0755 "${OUT}/helper" "${OUT}/exerciser" "${OUT}/lease-exec"

echo "build: done"
