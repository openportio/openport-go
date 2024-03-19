#!/bin/bash
set -ex
iptables -A OUTPUT -p tcp --dport 22 -j DROP
sleep 1
nc -zw 2 $SERVER 22 && exit 1 || echo "port blocked"
openport "$@"
