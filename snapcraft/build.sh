#!/usr/bin/env bash
set -ex
cd $(dirname $0)

docker run -it -v $(pwd)/../../openport-go-client/:/app -w /app snapcore/snapcraft:stable bash