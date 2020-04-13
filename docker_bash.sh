#!/usr/bin/env bash
set -ex
cd $(dirname $0)

docker run -it -v $(pwd):/apps/go/ openport-client-go bash
