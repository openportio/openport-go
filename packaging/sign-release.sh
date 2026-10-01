#!/usr/bin/env bash
#
# Offline release signer. Run by a human on a trusted workstation, once per
# release, with the apt signing key at ~/.openport-release/. It is the only
# place the signing key is ever used. See openport-distribution's
# docs/release-architecture.md for the full picture.
#
# What it does, for a tag vX.Y.Z that CI has already built:
#   1. downloads the UNSIGNED build CI uploaded to the GitLab package registry
#      (openport-build/<version>) and verifies its SHA-256 checksums,
#   2. VERIFIES REPRODUCIBILITY: rebuilds locally in the same pinned image and
#      checks the binary inside each .deb matches CI's byte-for-byte, refusing
#      to sign on any mismatch,
#   3. builds + signs the apt repository from the locally rebuilt binaries
#      (via publish-apt.sh SKIP_UPLOAD=1 — same signing logic as before),
#   4. packs the signed tree + checksums + SBOMs into openport-apt-<ver>.tar.gz,
#   5. pushes ONLY the vX.Y.Z tag to GitHub and creates a DRAFT release with
#      that tarball attached. Publishing the draft (the go-live gate) is a
#      separate manual step; the prod pull agent only sees published releases.
#
# The host reaches out to GitLab (read, own credentials) and GitHub (write,
# own token). It never connects to a production server.
#
# Requirements on the workstation: docker, git, gh (authenticated), curl,
# python3, rsync, gpg, dpkg-deb.
#
# Environment:
#   VERSION               release version, e.g. 2.2.4 (default: strip the
#                         leading v from the current HEAD tag)
#   GITLAB_URL            required: the GitLab instance holding the CI builds
#   GITLAB_TOKEN          read_api token for the client project (NOT echoed)
#   GITLAB_PROJECT        url-encoded path (default openport%2Fopenport-go-client)
#   GITHUB_REPO           default openportio/openport-go
#   GITHUB_REMOTE         git remote name for GitHub (default github)
#   APT_SIGNING_KEY_FILE  default ~/.openport-release/apt-signing-key.asc
#   PKG_NAME              generic package name (default openport-build)
#   POOL_ARCHIVE          dir of previously-released debs, kept so the apt
#                         index lists every version (default
#                         ~/.openport-release/pool). The push model used to
#                         fetch the old pool off the server; with no server
#                         access the signer keeps it locally instead.

set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-}"
if [ -z "$VERSION" ]; then
  _tag="$(git describe --tags --exact-match 2>/dev/null || true)"
  VERSION="${_tag#v}"
fi
: "${VERSION:?set VERSION=x.y.z, or run with HEAD on a vX.Y.Z tag}"
TAG="v$VERSION"

: "${GITLAB_URL:?set GITLAB_URL to the GitLab instance holding the CI builds}"
GITLAB_PROJECT="${GITLAB_PROJECT:-openport%2Fopenport-go-client}"
GITHUB_REPO="${GITHUB_REPO:-openportio/openport-go}"
GITHUB_REMOTE="${GITHUB_REMOTE:-github}"
PKG_NAME="${PKG_NAME:-openport-build}"
POOL_ARCHIVE="${POOL_ARCHIVE:-$HOME/.openport-release/pool}"
APT_SIGNING_KEY_FILE="${APT_SIGNING_KEY_FILE:-$HOME/.openport-release/apt-signing-key.asc}"
: "${GITLAB_TOKEN:?set GITLAB_TOKEN to a read_api token for the client project}"

API="$GITLAB_URL/api/v4"
CURL=(curl --fail --silent --show-error --header "PRIVATE-TOKEN: $GITLAB_TOKEN")

for tool in docker git gh curl python3 rsync gpg dpkg-deb; do
  command -v "$tool" >/dev/null || { echo "ERROR: $tool is required" >&2; exit 1; }
done
[ -f "$APT_SIGNING_KEY_FILE" ] || {
  echo "ERROR: signing key not found at $APT_SIGNING_KEY_FILE" >&2; exit 1; }
[ "$(git describe --tags --exact-match 2>/dev/null || true)" = "$TAG" ] || {
  echo "ERROR: HEAD is not on tag $TAG — check out the tag you are signing" >&2
  exit 1; }

WORK="$(mktemp -d)"
CI_DIR="$WORK/ci"           # CI's unsigned artifacts
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$CI_DIR"

echo "==> 1. download CI build openport-build/$VERSION from GitLab"
# Find the package, then list and fetch its files.
pkg_id="$("${CURL[@]}" -G \
  --data-urlencode "package_name=$PKG_NAME" \
  --data-urlencode "package_version=$VERSION" \
  "$API/projects/$GITLAB_PROJECT/packages" \
  | python3 -c 'import json,sys; p=[x for x in json.load(sys.stdin) if x["version"]==sys.argv[1]]; print(p[0]["id"] if p else "")' "$VERSION")"
[ -n "$pkg_id" ] || { echo "ERROR: no $PKG_NAME package for version $VERSION" >&2; exit 1; }
files="$("${CURL[@]}" "$API/projects/$GITLAB_PROJECT/packages/$pkg_id/package_files" \
  | python3 -c 'import json,sys; [print(f["file_name"]) for f in json.load(sys.stdin)]')"
for name in $files; do
  "${CURL[@]}" -o "$CI_DIR/$name" \
    "$API/projects/$GITLAB_PROJECT/packages/generic/$PKG_NAME/$VERSION/$name"
done
echo "    downloaded: $(echo "$files" | wc -w) files"

echo "==> 2a. verify CI checksums"
( cd "$CI_DIR" && for s in *.sha256; do [ -e "$s" ] && sha256sum -c "$s"; done )

echo "==> 2b. reproducibility: rebuild locally and compare binaries"
./packaging/release.sh >/dev/null
# Compare the Go binary inside each .deb CI shipped against our local rebuild.
mismatch=0
for ci_deb in "$CI_DIR"/openport_*.deb; do
  [ -e "$ci_deb" ] || continue
  name="$(basename "$ci_deb")"
  local_deb="dist/$name"
  [ -f "$local_deb" ] || { echo "    MISSING local rebuild of $name" >&2; mismatch=1; continue; }
  a="$WORK/a"; b="$WORK/b"; rm -rf "$a" "$b"; mkdir -p "$a" "$b"
  dpkg-deb -x "$ci_deb" "$a"; dpkg-deb -x "$local_deb" "$b"
  ha="$(sha256sum "$a/usr/bin/openport" | cut -d' ' -f1)"
  hb="$(sha256sum "$b/usr/bin/openport" | cut -d' ' -f1)"
  if [ "$ha" = "$hb" ]; then
    echo "    OK   $name  ($ha)"
  else
    echo "    FAIL $name  ci=$ha local=$hb" >&2; mismatch=1
  fi
done
if [ "$mismatch" != 0 ]; then
  echo "ERROR: rebuild did not reproduce CI's binaries — refusing to sign." >&2
  echo "       Investigate with diffoscope before proceeding." >&2
  exit 1
fi
echo "    reproducibility verified"

echo "==> 3. build + sign the apt repository (key stays local)"
# Seed dist/ with every previously-released deb so the signed index lists all
# versions (publish-apt.sh indexes dist/*.deb; -n keeps the just-built ones).
mkdir -p "$POOL_ARCHIVE"
cp -n "$POOL_ARCHIVE"/*.deb dist/ 2>/dev/null || true
# publish-apt.sh reads dist/*.deb (verified rebuild + archived prior versions)
# and writes the signed tree to packaging/build/apt without uploading anything.
SKIP_UPLOAD=1 VERSION="$VERSION" APT_SIGNING_KEY_FILE="$APT_SIGNING_KEY_FILE" \
  ./packaging/publish-apt.sh
# Archive this release's debs for the next run's index.
cp -n dist/openport_*.deb "$POOL_ARCHIVE"/ 2>/dev/null || true

echo "==> 4. pack the signed release tarball"
STAGE="$WORK/openport-apt"; mkdir -p "$STAGE/apt" "$STAGE/checksums" "$STAGE/sbom"
rsync -a packaging/build/apt/ "$STAGE/apt/"
cp dist/*.deb.sha256 "$STAGE/checksums/" 2>/dev/null || true
cp dist/*.cdx.json dist/*.spdx.json "$STAGE/sbom/" 2>/dev/null || true
TARBALL="openport-apt-$VERSION.tar.gz"
tar -C "$STAGE/.." -czf "$TARBALL" openport-apt
echo "    wrote $TARBALL"

echo "==> 5. push tag to GitHub and create a DRAFT release"
git push "$GITHUB_REMOTE" "$TAG"
gh release create "$TAG" "$TARBALL" \
  --repo "$GITHUB_REPO" \
  --draft \
  --title "Openport $VERSION" \
  --notes "Signed apt repository for openport $VERSION. Published automatically to the apt repo by the pull agent once this draft is published."

echo
echo "Done. Review the DRAFT release at https://github.com/$GITHUB_REPO/releases"
echo "Publish it (un-draft) to go live; the prod pull agent converges within ~2 min."
