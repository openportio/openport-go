#!/bin/sh
# Openport installer: configures the signed apt repository and installs the
# client. Published at https://openport.io/apt/install.sh -- usage:
#
#   curl -fsSL https://openport.io/apt/install.sh | sudo sh
#
# Future updates then arrive through "apt upgrade" (or unattended-upgrades).
set -e

[ "$(id -u)" = 0 ] || { echo "Please run as root: curl -fsSL https://openport.io/apt/install.sh | sudo sh" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }

curl -fsSL https://openport.io/apt/openport-archive-keyring.gpg \
  -o /usr/share/keyrings/openport-archive-keyring.gpg
# Fetch the canonical sources file rather than writing our own: the openport
# package ships this exact file as a conffile, and dpkg only stays quiet on
# install if the bytes on disk are identical.
curl -fsSL https://openport.io/apt/openport.list \
  -o /etc/apt/sources.list.d/openport.list

apt-get update
apt-get install -y openport

echo
echo "openport installed: $(openport version). Try: openport 22"
