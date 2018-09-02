#!/bin/bash
set -ex
cd $(dirname $0)

docker run -it -v $(pwd)/..:/apps/distribution/ jandebleser/openport-distribution ./debian/docker/create_exe.sh
