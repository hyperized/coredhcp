#!/bin/bash
set -ex

# Probe for CAP_NET_ADMIN instead of assuming root is required
if ip link add __capprobe type dummy 2>/dev/null; then
    ip link delete __capprobe
else
    sudo "$0" "$@"
    exit $?
fi

# Topology: with one or 3 netns
#
# * 3-netns, for relay operations
#  --------------------------------
# | server (cdhcp_srv  <---------) | Upper netns
#  -----------------------------|--
#                               | (veth pair)
#  -----------------------------|---
# | relay upper (cdhcp_relay_u <-) |
# |                                | Relay netns
# | relay lower (cdhcp_relay_d <-) |
#  -----------------------------|--
#                               | (veth pair)
# ------------------------------|--
# |  client (cdhcp_cli <---------) | Lower netns
# ---------------------------------
#
# For 2-netns operation, remove the entire middle layer:
#
#  --------------------------------
# | server (cdhcp_srv  <---------) | Upper netns
#  -----------------------------|--
#                               | (veth pair)
# ------------------------------|--
# |  client (cdhcp_cli <---------) | Lower netns
# ---------------------------------
#


# Interface names are limited to 15 chars (IFNAMSIZ=16)
if_server=cdhcp_srv
if_relay_up=cdhcp_relay_u
if_relay_down=cdhcp_relay_d
if_client=cdhcp_cli

netns_server=coredhcp-upper
netns_relay=coredhcp-middle
netns_client=coredhcp-lower

netns_direct_server=coredhcp-direct-upper
netns_direct_client=coredhcp-direct-lower

ula_prefix=${ULA_PREFIX:-fd4f:6b37:542c:b643}

all_ns=("$netns_server" "$netns_relay" "$netns_client" "$netns_direct_server" "$netns_direct_client")

for netns in "${all_ns[@]}"; do
    ip netns delete "$netns" || true
done
[[ $1 == teardown ]] && exit

for netns in "${all_ns[@]}"; do
    ip netns add "$netns"
done

# Create the links inside a relevant netns, so the main netns isn't polluted
ip -n "$netns_client" link add "$if_client" type veth peer name "$if_relay_down"
ip -n "$netns_client" link set "$if_relay_down" netns "$netns_relay"
ip -n "$netns_server" link add "$if_server" type veth peer name "$if_relay_up"
ip -n "$netns_server" link set "$if_relay_up" netns "$netns_relay"

ip -n "$netns_server" addr add "${ula_prefix}:a::1/80" dev "$if_server"
ip -n "$netns_server" addr add "10.0.1.1/24" dev "$if_server"
ip -n "$netns_server" link set "$if_server" up

ip -n "$netns_client" addr add "${ula_prefix}:b::1/80" dev "$if_client"
ip -n "$netns_client" addr add "10.0.2.1/24" dev "$if_client"
ip -n "$netns_client" link set "$if_client" up

ip -n "$netns_relay" addr add "${ula_prefix}:b::2/80" dev "$if_relay_down"
ip -n "$netns_relay" addr add "${ula_prefix}:a::2/80" dev "$if_relay_up"
ip -n "$netns_relay" addr add "10.0.2.2/24" dev "$if_relay_down"
ip -n "$netns_relay" addr add "10.0.1.2/24" dev "$if_relay_up"
ip -n "$netns_relay" link set "$if_relay_down" up
ip -n "$netns_relay" link set "$if_relay_up" up

# The direct-attach namespaces, addressed like the relay scenario
ip -n "$netns_direct_client" link add "$if_client" type veth peer name "$if_server"
ip -n "$netns_direct_client" link set "$if_server" netns "$netns_direct_server"

# A larger subnet than the relay scenario uses, so these two link directly
ip -n "$netns_direct_server" addr add "${ula_prefix}:a::1/64" dev "$if_server"
ip -n "$netns_direct_server" addr add "10.0.1.1/16" dev "$if_server"
ip -n "$netns_direct_server" link set "$if_server" up

ip -n "$netns_direct_client" addr add "${ula_prefix}:b::1/64" dev "$if_client"
ip -n "$netns_direct_client" addr add "10.0.2.1/16" dev "$if_client"
ip -n "$netns_direct_client" link set "$if_client" up

set +x
for netns in "${all_ns[@]}"; do
    echo "# Addresses in $netns:"
    ip -n "$netns" address list
done
