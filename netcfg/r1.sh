#!/bin/bash
IF_A=$1
IF_B=$2

ip addr add 10.10.1.1/24 dev "$IF_A"
ip addr add 10.10.2.1/24 dev "$IF_B"
ip link set "$IF_A" up
ip link set "$IF_B" up

# Enable IP forwarding to act as a router.
sysctl -w net.ipv4.ip_forward=1

# Use a single default route to reach LAN C and Link D via r2.
ip route add default via 10.10.2.2 dev "$IF_B"