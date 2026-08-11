#!/usr/bin/env bash
INTERACTIVE=$([ -t 0 ] && echo "-t")
set -ex
cd "$(dirname "$0")"

ARCH=${1:-amd64}

GIT_SHA=$(git rev-parse --short HEAD)
if ! git diff --quiet HEAD; then
  GIT_SHA="$GIT_SHA-dirty"
fi

docker build . -f Dockerfile-$ARCH -t openport-go-$ARCH --build-arg GIT_SHA=$GIT_SHA
docker run -i $INTERACTIVE --user=$(id -u):$(id -g) -v $(pwd):/app openport-go-$ARCH bash -c 'cp /openport* /app'
