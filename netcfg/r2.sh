#!/bin/bash
IF_B=$1
IF_C=$2
IF_D=$3

ip addr add 10.10.2.2/24 dev "$IF_B"
ip addr add 10.10.3.1/24 dev "$IF_C"
ip addr add 10.10.4.1/30 dev "$IF_D"
ip link set "$IF_B" up
ip link set "$IF_C" up
ip link set "$IF_D" up

# Enable IP forwarding to act as a router.
sysctl -w net.ipv4.ip_forward=1

# Route standard LAN A traffic backwards through r1.
ip route add 10.10.1.0/24 via 10.10.2.1 dev "$IF_B"

# Use a longest-prefix match (/32) to force server replies destined 
# specifically for the client to travel over Link D.
ip route add 10.10.1.10/32 via 10.10.4.2 dev "$IF_D"

# Relax reverse-path filtering on LAN B because client traffic arrives here, 
# but the routing table dictates the return path is out of Link D.
sysctl -w net.ipv4.conf.all.rp_filter=2
sysctl -w net.ipv4.conf."$IF_B".rp_filter=2