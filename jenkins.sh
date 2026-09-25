#!/bin/bash
set -ex
cd "$(dirname $0)" || exit

if [ -z "$UID" ]; then
  UID=$(id -u)
fi

export UID
export GID=$(id -g)

rm -rf test-results/*
# CI passes a deterministic PROJECT_NAME so its after_script can run
# "docker compose -p $PROJECT_NAME down" when the job is cancelled mid-run.
# Local runs keep a random name so concurrent invocations don't collide.
PROJECT_NAME="${PROJECT_NAME:-$(openssl rand -hex 6)}"

#GO tests
yq 'del(.services[].ports)' docker-compose.yaml > docker-compose-no-ports.yaml
COMPOSE_ARGS="-f docker-compose-no-ports.yaml -p $PROJECT_NAME"
rc=0
docker compose $COMPOSE_ARGS up --build --abort-on-container-exit --exit-code-from client_tests || rc=$?
docker compose $COMPOSE_ARGS down --remove-orphans
if [ "$rc" -ne 0 ]; then exit "$rc"; fi

# Python tests
./docker_compile.sh
cd python_tests || exit
yq 'del(.services[].ports)' docker-compose/docker-compose-test.yaml > docker-compose/docker-compose-test-no-ports.yaml
COMPOSE_ARGS="-f docker-compose/docker-compose-test-no-ports.yaml -p $PROJECT_NAME"

rc=0
docker compose $COMPOSE_ARGS up --build --abort-on-container-exit --exit-code-from openport-test || rc=$?
docker compose $COMPOSE_ARGS down --remove-orphans
exit "$rc"
