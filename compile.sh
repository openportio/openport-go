#!/bin/bash
# Builds the openport binary that python_tests exercises.
#
# Prefer goreleaser so the tests run the *exact* binary we ship: same build
# flags, same CGO_ENABLED=0 modernc sqlite driver, same ./apps/openport main
# package. --snapshot allows a non-tagged / dirty tree; --single-target builds
# only the host arch; --skip=before skips the apt-keyring hook (release-only).
#
# Falls back to `go build` when goreleaser is not installed so a local dev can
# still run the suite -- the invocation is kept aligned (CGO off, the package,
# not a single file), but this is NOT the shipped artifact, hence the warning.
set -e
cd "$(dirname "$0")"
export PATH=$PATH:/usr/local/go/bin
export HOME

if command -v goreleaser >/dev/null 2>&1; then
  set -x
  goreleaser build --snapshot --clean --single-target --id openport --skip=before -o src/openport
else
  echo "WARNING: goreleaser not found; falling back to 'go build'. This is NOT" >&2
  echo "         the binary we ship -- install goreleaser to test the real one." >&2
  GIT_SHA=$(git rev-parse --short HEAD)
  if ! git diff --quiet HEAD; then
    GIT_SHA="$GIT_SHA-dirty"
  fi
  set -x
  ( cd src && CGO_ENABLED=0 go build -v \
      -ldflags "-X github.com/openportio/openport-go.GitSha=$GIT_SHA" \
      -o openport ./apps/openport )
fi

./src/openport --help
