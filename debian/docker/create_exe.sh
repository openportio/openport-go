#!/usr/bin/env bash
set -ex

pip install -e /apps/openport-client/
cd $(dirname $0)/../..

sudo -u docker ./create_exes.sh --no-gui
./dist/openport/openport --list  # creates openport/alembic/versions/*.pyc files
cd dist/openport
python -m compileall . -b
cd -
./dist/openport/openport --version
