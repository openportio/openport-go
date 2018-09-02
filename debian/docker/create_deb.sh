#!/usr/bin/env bash
set -ex
cd $(dirname $0)/../..

bash -ex ./debian/createdeb.sh --no-gui
dpkg -i ./debian/*.deb
python -m SimpleHTTPServer 9000 &
openport 9000
