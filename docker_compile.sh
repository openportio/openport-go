#!/usr/bin/env bash
set -ex
cd "$(dirname "$0")"
INTERACTIVE=$([ -t 0 ] && echo "-t")


ARCH=${1:-amd64}

docker build . -f Dockerfile-$ARCH -t openport-go-$ARCH
docker run -i $INTERACTIVE -v $(pwd):/app openport-go-$ARCH bash -c 'cp openport* /app'