#!/usr/bin/env bash
#
# Builds the unsigned mac installer (dist/Openport_<version>.dmg, with the
# flat Openport.pkg inside and beside it) from the darwin tar.gz archives
# packaging/release.sh already produced in dist/ — run it after release.sh.
# The CI release job does exactly that, so the dmg is uploaded to the package
# registry with everything else and the offline signer attaches it to the
# GitHub release (packaging/sign-release.sh).
#
# Only docker is required on the host; the xar/bomutils/libdmg toolchain is
# built as an image from packaging/macos/Dockerfile. See mkdmg.sh for what
# happens inside.
#
# Usage:
#   ./packaging/macos/build-dmg.sh [version]
# VERSION env wins over the argument; with neither, the version is derived
# from the single dist/openport_*_darwin_amd64.tar.gz.

set -euo pipefail
cd "$(dirname "$0")/../.."

VERSION="${VERSION:-${1:-}}"
if [ -z "$VERSION" ]; then
  set -- dist/openport_*_darwin_amd64.tar.gz
  [ "$#" -eq 1 ] && [ -e "$1" ] || {
    echo "ERROR: pass a version or have exactly one darwin archive in dist/" >&2
    exit 1
  }
  VERSION="$(basename "$1")"
  VERSION="${VERSION#openport_}"
  VERSION="${VERSION%_darwin_amd64.tar.gz}"
fi

IMAGE=openport-macos-dmg
docker build -q -f packaging/macos/Dockerfile -t "$IMAGE" packaging/macos >/dev/null

run() {
  docker run --rm -v "$PWD":/repo -w /repo "$IMAGE" "$@"
}
# Root inside the container writes into dist/; chown back even on failure so
# the next run's --clean does not hit root-owned files (same as release.sh).
trap 'run chown -R "$(id -u):$(id -g)" /repo/dist 2>/dev/null || true' EXIT

run bash packaging/macos/mkdmg.sh "$VERSION"
