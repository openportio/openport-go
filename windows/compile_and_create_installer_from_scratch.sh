#!/bin/bash
set -ex

cd "$(dirname "$0")"
start_dir=$(pwd)
git pull
cd ..
virtualenv env
env/scripts/pip install -r requirements.dist.txt
cd "$start_dir"
pwd
bash -ex compile_and_create_installer.sh