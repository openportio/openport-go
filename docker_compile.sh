#!/usr/bin/env bash
# Builds the CI test image (Dockerfile-amd64) and copies the linux amd64
# binary it contains to ./openport-amd64. run_tests.sh and the python e2e
# tests rely on both.
#
# This is the only per-arch docker build left: all release binaries come
# from goreleaser (packaging/release.sh), which cross-compiles without a
# docker image per target.
INTERACTIVE=$([ -t 0 ] && echo "-t")
set -ex
cd "$(dirname "$0")"

ARCH=${1:-amd64}
if [ "$ARCH" != amd64 ]; then
  echo "ERROR: only amd64 remains (the test image)." >&2
  echo "Release binaries for other targets: SNAPSHOT=1 ./packaging/release.sh -> dist/" >&2
  exit 1
fi

GIT_SHA=$(git rev-parse --short HEAD)
if ! git diff --quiet HEAD; then
  GIT_SHA="$GIT_SHA-dirty"
fi

# VERSION (e.g. 2.2.4) unset means a dev build that keeps the version
# compiled into the source.
docker build . -f Dockerfile-$ARCH -t openport-go-$ARCH --build-arg GIT_SHA=$GIT_SHA ${VERSION:+--build-arg VERSION=$VERSION}
docker run -i $INTERACTIVE --user=$(id -u):$(id -g) -v $(pwd):/app openport-go-$ARCH bash -c 'cp /openport* /app'
