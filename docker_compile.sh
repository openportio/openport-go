#!/usr/bin/env bash
INTERACTIVE=$([ -t 0 ] && echo "-t")
set -ex
cd "$(dirname "$0")"

ARCH=${1:-amd64}

docker build . -f Dockerfile-$ARCH -t openport-go-$ARCH
docker run -i $INTERACTIVE --user=$(id -u):$(id -g) -v $(pwd):/app openport-go-$ARCH bash -c 'cp /openport* /app'
