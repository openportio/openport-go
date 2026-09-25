#!/usr/bin/env bash
#
# Publishes the .debs in dist/ to the signed apt repository on the web server
# and refreshes the "latest" symlinks the download page points at.
#
# The repository is a plain static tree under releases/apt/ on the server,
# served at https://openport.io/apt (and /static/releases/apt). It is
# regenerated from scratch on every publish -- stateless, so a failed or
# re-run job cannot corrupt repo state:
#
#   releases/apt/
#     openport-archive-keyring.{asc,gpg}   public key
#     install.sh                           curl | sh convenience installer
#     dists/stable/{InRelease,Release,Release.gpg}
#     dists/stable/main/binary-{amd64,armhf,arm64}/Packages{,.gz}
#     pool/main/o/openport/openport_<version>_<arch>.deb
#
# Environment:
#   VERSION               required, e.g. 2.2.4
#   APT_SIGNING_KEY_FILE  armored GPG private key
#                         (default ~/.openport-release/apt-signing-key.asc;
#                         in CI: set to $APT_SIGNING_KEY, a GitLab file var)
#   RELEASE_HOST          ssh/rsync target (default "openport", an ssh alias)
#   RELEASE_SSH_PORT      optional; defaults to ssh config / 22
#   RELEASE_SSH_KEY_FILE  optional identity file (in CI: $RELEASE_SSH_KEY)
#   SKIP_UPLOAD=1         build + sign locally, skip all server interaction
#                         (for testing; repo tree left in packaging/build/apt)

set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=${VERSION:?set VERSION, e.g. VERSION=2.2.4}
APT_SIGNING_KEY_FILE=${APT_SIGNING_KEY_FILE:-$HOME/.openport-release/apt-signing-key.asc}
RELEASE_HOST=${RELEASE_HOST:-openport}
SKIP_UPLOAD=${SKIP_UPLOAD:-0}
KEYRING_ASC=packaging/openport-archive-keyring.asc
ARCHES="amd64 armhf arm64"

[ -f "$APT_SIGNING_KEY_FILE" ] || {
  echo "ERROR: signing key not found at $APT_SIGNING_KEY_FILE" >&2
  echo "Run packaging/generate-apt-key.sh once, or point APT_SIGNING_KEY_FILE at it." >&2
  exit 1
}
command -v rsync >/dev/null || { echo "ERROR: rsync is required" >&2; exit 1; }
ls dist/openport_*.deb >/dev/null 2>&1 || {
  echo "ERROR: no debs in dist/ -- run packaging/build-debs.sh first" >&2
  exit 1
}

SSH="ssh ${RELEASE_SSH_PORT:+-p $RELEASE_SSH_PORT} ${RELEASE_SSH_KEY_FILE:+-i $RELEASE_SSH_KEY_FILE -o IdentitiesOnly=yes} -o StrictHostKeyChecking=accept-new"

APT=packaging/build/apt
POOL=$APT/pool/main/o/openport
# A previous failed run can leave root-owned files behind (the container
# chowns on exit, but docker itself may have died); fall back to a container
# for the cleanup rather than requiring sudo.
if [ -e "$APT" ] && ! rm -rf "$APT" 2>/dev/null; then
  docker run --rm -v "$PWD/packaging/build":/b alpine rm -rf /b/apt
fi
mkdir -p "$POOL" "$APT/dists/stable"

# Older releases stay available (and installable) after a new one is
# published: start from the pool that is already on the server.
if [ "$SKIP_UPLOAD" != 1 ]; then
  rsync -e "$SSH" -a "$RELEASE_HOST:releases/apt/pool/" "$APT/pool/" \
    || echo "NOTE: no existing pool on the server (first publish?), starting empty"
fi

cp dist/openport_*.deb "$POOL/"

# Index and sign inside a container: only docker is guaranteed on the runner.
# The tree is regenerated in full from the pool on every run.
docker run --rm \
  -v "$PWD/$APT":/apt -w /apt \
  -v "$(readlink -f "$APT_SIGNING_KEY_FILE")":/signing-key.asc:ro \
  -v "$PWD/$KEYRING_ASC":/keyring.asc:ro \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  debian:bookworm-slim bash -ec '
    # Give the files back to the host user even when a step fails, or the
    # next run cannot clean packaging/build/apt up.
    trap "chown -R $HOST_UID:$HOST_GID /apt" EXIT
    apt-get -qq update >/dev/null
    apt-get -qq install -y apt-utils gnupg >/dev/null

    for arch in '"$ARCHES"'; do
      mkdir -p dists/stable/main/binary-$arch
      apt-ftparchive --arch $arch packages pool > dists/stable/main/binary-$arch/Packages
      gzip -kf dists/stable/main/binary-$arch/Packages
    done

    rm -f dists/stable/Release dists/stable/Release.gpg dists/stable/InRelease
    apt-ftparchive \
      -o APT::FTPArchive::Release::Origin=Openport \
      -o APT::FTPArchive::Release::Label=Openport \
      -o APT::FTPArchive::Release::Suite=stable \
      -o APT::FTPArchive::Release::Codename=stable \
      -o "APT::FTPArchive::Release::Architectures='"$ARCHES"'" \
      -o APT::FTPArchive::Release::Components=main \
      release dists/stable > Release.tmp
    mv Release.tmp dists/stable/Release

    export GNUPGHOME=$(mktemp -d)
    # loopback pinentry: no tty in the container, and the key has no
    # passphrase by design (see generate-apt-key.sh).
    GPG="gpg --batch --yes --pinentry-mode loopback --passphrase="
    $GPG --quiet --import /signing-key.asc
    $GPG --armor --detach-sign -o dists/stable/Release.gpg dists/stable/Release
    $GPG --clearsign -o dists/stable/InRelease dists/stable/Release

    # Public key, in both armored and keyring form, next to the repo.
    cp /keyring.asc openport-archive-keyring.asc
    gpg --dearmor < /keyring.asc > openport-archive-keyring.gpg
  '

cp packaging/apt-install.sh "$APT/install.sh"
# Canonical sources file, fetched by install.sh; must stay byte-identical to
# the conffile inside the deb (see apt-install.sh).
cp packaging/openport.list "$APT/openport.list"

if [ "$SKIP_UPLOAD" = 1 ]; then
  echo "SKIP_UPLOAD=1 -- repo generated in $APT, nothing uploaded"
  exit 0
fi

$SSH "$RELEASE_HOST" "mkdir -p releases/apt releases/sbom"

# Order matters: pool before dists, so clients never see an index that
# references a deb that is not there yet. The pool is never pruned here.
rsync -e "$SSH" -a "$APT/pool/" "$RELEASE_HOST:releases/apt/pool/"
rsync -e "$SSH" -a --delete "$APT/dists/" "$RELEASE_HOST:releases/apt/dists/"
rsync -e "$SSH" -a "$APT"/openport-archive-keyring.asc "$APT"/openport-archive-keyring.gpg \
  "$APT/install.sh" "$APT/openport.list" "$RELEASE_HOST:releases/apt/"

# Checksums + SBOMs next to the release, as before (CRA plan items 17/18).
rsync -e "$SSH" -a dist/*.deb.sha256 "$RELEASE_HOST:releases/"
rsync -e "$SSH" -a dist/*.cdx.json dist/*.spdx.json "$RELEASE_HOST:releases/sbom/"

# Stable "latest" names for the website: the Django download views redirect to
# these, so shipping a release no longer requires touching or redeploying the
# server. Versioned symlinks keep the old wget URLs working without
# duplicating the debs outside the pool.
for deb in dist/openport_*.deb; do
  name=$(basename "$deb")
  arch=$(echo "$name" | sed -n 's/.*_\([a-z0-9]*\)\.deb/\1/p')
  $SSH "$RELEASE_HOST" "cd releases &&
    ln -sfn apt/pool/main/o/openport/$name $name &&
    ln -sfn apt/pool/main/o/openport/$name openport_latest_$arch.deb"
done

echo
echo "Published to $RELEASE_HOST:releases/apt (version $VERSION)"
