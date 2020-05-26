#!/bin/bash
set -ex
cd "$(dirname "$0")"/..
source client_folder.sh
cd -
$CLIENTDIR/docker_compile.sh amd64
cp $CLIENTDIR/openport-amd64 openport

bash -ex docker-create-deb.sh
