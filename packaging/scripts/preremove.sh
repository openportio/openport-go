#!/bin/sh
# dpkg runs this with $1="remove" on removal and $1="upgrade" on upgrade.
# Only tear the service down on a real removal -- upgrades are handled by
# postinstall.sh, which restarts the unit onto the new binary.
set -e

if [ "$1" = "remove" ] && [ -d /run/systemd/system ]; then
    systemctl disable --now openport.service || true
fi
