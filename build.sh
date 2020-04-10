#!/bin/bash
cd "$(dirname "$1")"
set -ex
export PATH=$PATH:/usr/local/go/bin
export HOME

go build -v -o openport cmd/openport/main.go
