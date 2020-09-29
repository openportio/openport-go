#!/usr/bin/env bash
set -ex
cd "$(dirname "$0")"
./compile.sh
./docker_compile.sh amd64
./docker_compile.sh windows-amd64
./docker_compile.sh armv6
./docker_compile.sh snapcraft
