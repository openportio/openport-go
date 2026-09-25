#!/bin/bash
set -ex
cd "$(dirname "$0")/src"
export PATH=$PATH:/usr/local/go/bin
export HOME
export CGO_ENABLED=1
GIT_SHA=$(git rev-parse --short HEAD)
if ! git diff --quiet HEAD; then
  GIT_SHA="$GIT_SHA-dirty"
fi
go build -v -ldflags "-X github.com/openportio/openport-go.GitSha=$GIT_SHA" -o openport apps/openport/main.go

./openport --help
#./openport selftest --help
#./openport selftest --ws -v --no-ssl
