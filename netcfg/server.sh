#!/bin/bash
IF_C=$1

ip addr add 10.10.3.10/24 dev "$IF_C"
ip link set "$IF_C" up

# Ensure the server is a host and does not forward packets (A4).
sysctl -w net.ipv4.ip_forward=0

# Route all outbound non-local traffic to r2 to reach the rest of the network.
ip route add default via 10.10.3.1 dev "$IF_C"