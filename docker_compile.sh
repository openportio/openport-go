#!/usr/bin/env bash
INTERACTIVE=$([ -t 0 ] && echo "-t")
set -ex
cd "$(dirname "$0")"

ARCH=${1:-amd64}

GIT_SHA=$(git rev-parse --short HEAD)
if ! git diff --quiet HEAD; then
  GIT_SHA="$GIT_SHA-dirty"
fi

# VERSION (e.g. 2.2.4) is set by the release pipeline; unset means a dev
# build that keeps the version compiled into the source.
docker build . -f Dockerfile-$ARCH -t openport-go-$ARCH --build-arg GIT_SHA=$GIT_SHA ${VERSION:+--build-arg VERSION=$VERSION}
docker run -i $INTERACTIVE --user=$(id -u):$(id -g) -v $(pwd):/app openport-go-$ARCH bash -c 'cp /openport* /app'
