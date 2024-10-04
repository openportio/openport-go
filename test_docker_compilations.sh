#!/bin/bash
set -ex

# amd64
./docker_compile.sh amd64
./openport-amd64 selftest

# armv6
./docker_compile.sh armv6
scp openport-armv6 pi-zero:
ssh pi-zero ./openport-armv6 selftest

# armv7
./docker_compile.sh armv7
scp openport-armv7 router:
ssh router ./openport-armv7 selftest

# arm64
./docker_compile.sh arm64
scp openport-arm64 mk4:
ssh mk4 ./openport-arm64 selftest
