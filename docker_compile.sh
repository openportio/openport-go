#!/usr/bin/env bash
set -ex
cd "$(dirname "$0")"

docker build . -t openport-client-go
#docker run -it openport-client-go ./openport 22

docker-compose -f /Users/jan/swprojects/openport-client/docker-compose/proxy-test.yaml run openport-go bash
