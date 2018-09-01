#!/usr/bin/env bash
set -ex
cd $(dirname $0)/../..

sudo -u docker ./create_exes.sh --no-gui
./dist/openport/openport --list  # creates openport/alembic/versions/*.pyc files
./dist/openport/openport --version
bash -ex ./debian/createdeb.sh --no-gui
dpkg -i ./debian/*.deb
openport 22