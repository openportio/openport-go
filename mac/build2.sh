#!/bin/sh

cd $(dirname $0)

export PATH="$PATH:/usr/local/bin"


printenv
#security unlock-keychain /Users/jan/Library/Keychains/login.keychain


packagesbuild -v packages/Openport.pkgproj.tmp

codesign --force --sign "Developer ID Application: Jan De Bleser" packages/build/Openport.pkg

