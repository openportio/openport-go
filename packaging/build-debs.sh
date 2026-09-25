#!/usr/bin/env bash
#
# Builds the openport .deb packages (amd64, armhf, arm64) with nfpm, plus a
# SHA-256 checksum file and CycloneDX/SPDX SBOMs per package (CRA Annex I
# Part II(1)). Output lands in dist/.
#
# Prerequisites:
#   - VERSION set, e.g. VERSION=2.2.4 (in CI: derived from the vX.Y.Z tag)
#   - compiled binaries at the repo root: openport-amd64, openport-armv6,
#     openport-arm64 (./docker_compile.sh <arch>)
#   - packaging/openport-archive-keyring.asc committed (the apt repo public
#     key -- see packaging/generate-apt-key.sh)
#   - docker

set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=${VERSION:?set VERSION, e.g. VERSION=2.2.4}
NFPM_IMAGE=${NFPM_IMAGE:-goreleaser/nfpm:v2.43.0}
SYFT_IMAGE=${SYFT_IMAGE:-anchore/syft:latest}
KEYRING_ASC=packaging/openport-archive-keyring.asc

[ -f "$KEYRING_ASC" ] || {
  echo "ERROR: $KEYRING_ASC is missing." >&2
  echo "The apt repo public key must be committed; run packaging/generate-apt-key.sh once." >&2
  exit 1
}

rm -rf dist packaging/build
mkdir -p dist packaging/build

# The deb ships the keyring in binary form. Derive it from the committed
# armored key; use dockerized gpg when the host has none (the CI runner
# only guarantees docker).
if command -v gpg >/dev/null; then
  gpg --dearmor < "$KEYRING_ASC" > packaging/build/openport-archive-keyring.gpg
else
  docker run --rm -v "$PWD":/repo -w /repo debian:bookworm-slim \
    sh -ec "apt-get -qq update >/dev/null && apt-get -qq install -y gnupg >/dev/null &&
            gpg --dearmor < $KEYRING_ASC" > packaging/build/openport-archive-keyring.gpg
fi

build_deb() {
  local deb_arch=$1 bin_arch=$2
  [ -f "openport-$bin_arch" ] || {
    echo "ERROR: openport-$bin_arch not built. Run ./docker_compile.sh $bin_arch" >&2
    exit 1
  }
  # nfpm only expands env vars in a few fields (not in contents src globs),
  # so render the whole config ourselves.
  sed -e "s/\${VERSION}/$VERSION/g" \
      -e "s/\${DEB_ARCH}/$deb_arch/g" \
      -e "s/\${BIN_ARCH}/$bin_arch/g" \
      packaging/nfpm.yaml > "packaging/build/nfpm-$deb_arch.yaml"
  docker run --rm -v "$PWD":/repo -w /repo \
    "$NFPM_IMAGE" package -f "packaging/build/nfpm-$deb_arch.yaml" -p deb -t /repo/dist/
}

build_deb amd64 amd64
build_deb armhf armv6 # pi zero needs the armv6 binary under the armhf arch
build_deb arm64 arm64

# Checksums (bare filenames so "sha256sum -c" works next to the download)
# and per-package SBOMs.
cd dist
for deb in *.deb; do
  sha256sum "$deb" > "$deb.sha256"
  docker run --rm --user "$(id -u):$(id -g)" -v "$PWD":/dist -w /dist "$SYFT_IMAGE" \
    scan "file:/dist/$deb" \
    --source-name openport-client --source-version "$VERSION" \
    -o "cyclonedx-json=$deb.cdx.json" \
    -o "spdx-json=$deb.spdx.json" -q
done

echo
echo "Built packages:"
ls -1
