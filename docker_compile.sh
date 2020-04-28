#!/usr/bin/env bash
set -ex
cd "$(dirname "$0")"

ARCH=${1:-amd64}

docker build . -f Dockerfile-$ARCH -t openport-go-$ARCH
docker run -it -v $(pwd):/tmp openport-go-$ARCH cp openport-$ARCH /tmp