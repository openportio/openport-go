#!/usr/bin/env bash
set -ex
cd "$(dirname "$0")"

bash -ex ./createdeb.sh
dpkg -i *.deb
python -m http.server 9000 &
openport 9000
