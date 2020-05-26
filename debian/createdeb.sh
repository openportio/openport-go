#!/bin/bash
set -ex
export DEBFULLNAME="Jan De Bleser"
export DEBEMAIL="jan@openport.io"
cd $(dirname $0)

VERSION=$(./openport version 2>&1 )
echo $VERSION

#sudo apt-get --yes install build-essential autoconf automake autotools-dev dh-make debhelper devscripts fakeroot xutils lintian pbuilder
# if you have errors from locale: sudo dpkg-reconfigure locales

function create_deb {
    start_dir=$(pwd)
    PACKAGE=$APPLICATION-$VERSION
    TARBALL=${APPLICATION}_$VERSION.orig.tar.gz
#    sudo dpkg --remove $APPLICATION || echo "$APPLICATION not installed"
    # If the uninstall keeps giving errors:
    # rm -rf /var/lib/dpkg/info/$APPLICATION.*

    rm -rf tmp/
    mkdir -p tmp/$PACKAGE/usr/bin/
    cp openport tmp/$PACKAGE/usr/bin/

    cd tmp
    mkdir -p package
    tar -czf package/$TARBALL $PACKAGE
    cd package
    tar -xf $TARBALL

    cp -r ../../debian_openport $PACKAGE/debian

    create_include_binaries
    cd $PACKAGE

   # read -p "Press [Enter] key to continue..."

    echo "9" > debian/compat
    ls debian/
    DEB_BUILD_OPTIONS="noopt nostrip"
    pwd
    dch --create -v $(echo $VERSION)-1 --package $APPLICATION "TODO 12321"
    #debuild -S # For ppa
    dpkg-buildpackage -us -uc

    cd $start_dir
    cp tmp/package/$(echo $APPLICATION)_$(echo $VERSION)-1_*.deb .
}

rm -f *.deb

export APPLICATION=openport
function create_include_binaries {
    pwd
    ls ../package/
    ls ../package/openport-*/usr/bin/openport > $PACKAGE/debian/source/include-binaries
}

create_deb

md5sum *.deb > hash-$(uname -m).md5
