#!/bin/bash
set -ex
cd $(dirname $0)

MACHINE=$(uname -m)
DOCKERARGS=
if [ "$MACHINE" == armv* ] ; then
	DOCKERARGS="--build-arg FROMIMAGE=arm32v7/python:3.6.10-stretch"
	EXTRATAG="-tmp"
fi
export DOCKER_API_VERSION=1.23

cd ../
docker build $DOCKERARGS -t jandebleser/openport-distribution${EXTRATAG} .

if [ "$MACHINE" == "armv7l" ] ; then
    docker build -f Dockerfile-arm -t jandebleser/openport-distribution .
fi
