#!/bin/bash
set -ex
cd "$(dirname "$0")"
git pull
bash -ex create_exes_win.sh
c:/python27/python create_installer.py
