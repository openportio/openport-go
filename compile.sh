#!/bin/bash
set -ex
cd "$(dirname "$0")/src"
export PATH=$PATH:/usr/local/go/bin
export HOME

go build -v -o openport apps/openport/main.go

./openport --help