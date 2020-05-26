#!/bin/bash
set -ex
cd "$(dirname "$0")"
docker build -t distribution-debian .
docker run -it -v "$(pwd)":/app distribution-debian /app/entrypoint.sh
