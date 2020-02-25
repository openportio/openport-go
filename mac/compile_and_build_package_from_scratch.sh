#!/bin/sh

cd $(dirname $0)

git pull

start_dir=$(pwd)

cd ../openport
virtualenv env
env/bin/pip install -e .

cd $start_dir

bash -ex compile_and_build_package.sh

