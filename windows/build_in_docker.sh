#!/usr/bin/env bash
set -ex
cd "$(dirname "$1")"

VERSION=$($(pwd)/../../openport-go-client/openport version)
cp $(pwd)/../../openport-go-client/openport-windows-amd64 openport.exe
cp $(pwd)/../../openport-go-client/openportw-windows-amd64 openportw.exe
#    --entrypoint bash \

docker run -it \
    -v $(pwd):/code \
    -w /code \
    hp41/nsis:3.01-1 \
    "-DVERSION=$VERSION" /code/clean.nsi


cp Openport_2.0.0.exe ../deploy/windows10