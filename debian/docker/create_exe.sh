#!/usr/bin/env bash
set -ex

#pip install -e /apps/openport-client/
cd $(dirname $0)/../..

sudo -u docker ./create_exes.sh --no-gui
./dist/openport/openport --list  # creates openport/alembic/versions/*.pyc files
./dist/openport/openport --version
