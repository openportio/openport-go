#!/usr/bin/env bash
set -ex
cd $(dirname $0)
docker build -f Dockerfile-snapcraft-stable -t snapcraft-stable .
docker build -f Dockerfile-snapcraft -t openport-snapcraft .
docker run -it -v $(pwd):/app openport-snapcraft snapcraft
