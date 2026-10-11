#!/bin/bash
IF_A=$1
IF_D=$2

ip addr add 10.10.1.10/24 dev "$IF_A"
ip addr add 10.10.4.2/30 dev "$IF_D"
ip link set "$IF_A" up
ip link set "$IF_D" up

# Send outbound traffic to r1 to satisfy the client -> r1 -> r2 -> server path.
ip route add default via 10.10.1.1 dev "$IF_A"

# Ensure the client is a host and does not forward packets (A4).
sysctl -w net.ipv4.ip_forward=0

# Relax reverse-path filtering to allow incoming server replies on Link D 
# despite the default route pointing out of LAN A.
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf."$IF_D".rp_filter=2