#!/bin/bash
set -ex
cd $(dirname $0)

# TODO: move to docker-compose file

docker run -it -v $(pwd)/..:/apps/distribution/ jandebleser/openport-distribution ./debian/docker/create_deb.sh
