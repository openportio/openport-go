#!/bin/bash
set -ex

# This blocks outgoing port 22
iptables -A OUTPUT -p tcp --dport 22 -j DROP
sleep 1
#  Check that is is blocked
nc -zw 2 $SERVER 22 && exit 1 || echo "port blocked"

# Start socat to forward the port to the docker host (where the tests are running).
socat tcp-l:$PORT,fork,reuseaddr tcp:host.docker.internal:$PORT &

openport "$@"
