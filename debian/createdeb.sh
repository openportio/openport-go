#!/bin/bash
set -ex
export DEBFULLNAME="Jan De Bleser"
export DEBEMAIL="jan@openport.io"
cd $(dirname $0)
source ../openport/openport/apps/openport_app_version.py
echo $VERSION

#sudo apt-get --yes install build-essential autoconf automake autotools-dev dh-make debhelper devscripts fakeroot xutils lintian pbuilder python-dev python-pip python-virtualenv libsqlite3-dev
#sudo apt-get --yes install python-dev libffi-dev libssl-dev

# if you have errors from locale: sudo dpkg-reconfigure locales

function create_deb {
    start_dir=$(pwd)
    PACKAGE=$APPLICATION-$VERSION
    TARBALL=${APPLICATION}_$VERSION.orig.tar.gz
#    sudo dpkg --remove $APPLICATION || echo "$APPLICATION not installed"
    # If the uninstall keeps giving errors:
    # rm -rf /var/lib/dpkg/info/$APPLICATION.*

    rm -rf tmp/
    mkdir -p tmp/$PACKAGE/usr/lib/$APPLICATION
    cp ../dist/$APPLICATION/* tmp/$PACKAGE/usr/lib/$APPLICATION -r

    cd tmp
    mkdir -p package
    tar -czf package/$TARBALL $PACKAGE
    cd package
    tar -xf $TARBALL

    cp -r ../../debian_$APPLICATION $PACKAGE/debian

    create_include_binaries
    cd $PACKAGE


   # read -p "Press [Enter] key to continue..."

    echo "8" > debian/compat
    ls debian/
    DEB_BUILD_OPTIONS="noopt nostrip"
    pwd
    dch --create -v $(echo $VERSION)-1 --package $APPLICATION "TODO 12321"
    #debuild -S # For ppa
    dpkg-buildpackage -us -uc

    cd $start_dir

    #sudo rm -rf /usr/bin/openport
    #if [ -e /etc/init.d/openport ] ; then
    #	sudo rm -f /etc/init.d/openport
    #fi
    #sudo rm -f /etc/init.d/openport-manager
    cp tmp/package/$(echo $APPLICATION)_$(echo $VERSION)-1_*.deb .
}

rm -f *.deb

export APPLICATION=openport
function create_include_binaries {
    pwd
    ls ../package/
    ls ../package/openport-*/usr/lib/openport/*.so* > $PACKAGE/debian/source/include-binaries
    ls ../package/openport-*/usr/lib/openport/openport >> $PACKAGE/debian/source/include-binaries
    ls ../package/openport-*/usr/lib/openport/alembic/versions/*.pyc >> $PACKAGE/debian/source/include-binaries
}

create_deb

#######sudo killall python || echo "no python process found"
#sudo dpkg -i openport_$(echo $VERSION)-1_*.deb
#openport -h

export APPLICATION=openport-gui
function create_include_binaries {
    ls ../package/openport-gui-*/usr/lib/openport-gui/*.so > $PACKAGE/debian/source/include-binaries
    ls ../package/openport-gui-*/usr/lib/openport-gui/openport-gui >> $PACKAGE/debian/source/include-binaries
}
no_gui=0
for i in "$@" ; do
    if [[ $i = "--no-gui" ]] ; then
        no_gui=1
        break
    fi
done

if [[ $no_gui != 1 ]]
then
	create_deb
	#sudo dpkg -i openport-gui_$(echo $VERSION)-1_*.deb
	#openport-gui
fi

md5sum *.deb > hash-$(uname -m).md5
