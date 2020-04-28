#!/usr/bin/env bash
set -ex
cd "$(dirname "$0")"

ARCH=${1:-amd64}

docker run -it -v "$(pwd):/apps/go/" openport-go-$ARCH bash
