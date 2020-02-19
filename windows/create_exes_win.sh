#!/bin/bash
set -ex
cd ..
export PATH="$PATH;./windows/"

env/Scripts/pip install ../openport-client/
env/Scripts/pyinstaller --clean openport.spec -y
env/Scripts/pyinstaller --clean windows/openport_win_no_console.spec -y
#env/Scripts/pyinstaller --clean openport-gui.spec -y

./dist/openport/openport.exe --version
./dist/openport/openport.exe 22 -v
