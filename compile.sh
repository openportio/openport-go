#!/bin/bash
set -ex
cd "$(dirname "$0")"
export PATH=$PATH:/usr/local/go/bin
export HOME

go build -v -o openport main.go

./openport help