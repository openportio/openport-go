#!/bin/bash
set -ex
cd "$(dirname $0)" || exit

if [ -z "$UID" ]; then
  UID=$(id -u)
fi

export UID
export GID=$(id -g)

rm -rf test-results/*
PROJECT_NAME=$(openssl rand -hex 6)

#GO tests
yq 'del(.services[].ports)' docker-compose.yaml -y > docker-compose-no-ports.yaml
COMPOSE_ARGS="-f docker-compose-no-ports.yaml -p $PROJECT_NAME"
docker compose $COMPOSE_ARGS up --build --abort-on-container-exit
docker compose $COMPOSE_ARGS down --remove-orphans

# Python tests
./docker_compile.sh
cd python_tests || exit
COMPOSE_ARGS="-f docker-compose/docker-compose-test.yaml -p $PROJECT_NAME"
docker compose $COMPOSE_ARGS up --build --abort-on-container-exit
