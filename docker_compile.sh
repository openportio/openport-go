#!/usr/bin/env bash
set -ex
cd "$(dirname "$0")"

docker build . -t openport-client
docker run -it openport-client ./openport 22
