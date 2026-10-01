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

# Local config: packaging/.env (gitignored, see packaging/.env.example) is
# sourced if present. Write entries as VAR="${VAR:-value}" so explicitly
# exported values still win.
[ -f packaging/.env ] && { set -a; . ./packaging/.env; set +a; }

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
# Drop the signed mac .pkg / Windows installer .exe here to attach them to the
# release (option (b): do it later and re-run this script; it re-signs
# SHA256SUMS and re-uploads with --clobber).
EXTRA_ASSETS_DIR="${EXTRA_ASSETS_DIR:-$HOME/.openport-release/assets/$VERSION}"
RPM_SIGN_IMAGE="${RPM_SIGN_IMAGE:-fedora:40}"
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

echo "==> 3b. GPG-sign the rpm(s) with the openport key"
# rpmsign stores a header-signature so `rpm --checksig` / dnf verify the rpm
# against the same key as the apt repo. Done in a container because rpm-sign is
# not on a Debian signer. The key has no passphrase (see generate-apt-key.sh),
# so gpg runs with loopback and an empty passphrase.
if ls dist/*.rpm >/dev/null 2>&1; then
  docker run --rm \
    -v "$PWD/dist":/dist \
    -v "$(readlink -f "$APT_SIGNING_KEY_FILE")":/signing-key.asc:ro \
    "$RPM_SIGN_IMAGE" bash -ec '
      dnf -yq install rpm-sign gnupg2 >/dev/null
      export GNUPGHOME=$(mktemp -d)
      gpg --batch --quiet --import /signing-key.asc
      fpr=$(gpg --list-secret-keys --with-colons | awk -F: "/^fpr:/{print \$10; exit}")
      cat > /root/.rpmmacros <<RPMMACROS
%_gpg_name $fpr
%_gpg_path $GNUPGHOME
%__gpg_sign_cmd %{__gpg} gpg --batch --pinentry-mode loopback --passphrase "" --no-armor --no-secmem-warning -u "%{_gpg_name}" -sbo %{__signature_filename} --digest-algo sha256 %{__plaintext_filename}
RPMMACROS
      rpmsign --addsign /dist/*.rpm
      # Self-check: import the PUBLIC half (derived from the secret key) and
      # verify. rpm --import needs the public key, not the secret-key file.
      gpg --batch --armor --export "$fpr" > /tmp/openport-pub.asc
      rpm --import /tmp/openport-pub.asc
      for r in /dist/*.rpm; do echo "  checksig $r:"; rpm --checksig "$r"; done
    '
  # host owns dist/ already (release.sh chowned it); re-checksum signed rpms
  ( cd dist && for r in *.rpm; do sha256sum "$r" > "$r.sha256"; done )
else
  echo "    (no rpm in dist/)"
fi

echo "==> 4. assemble release assets + a GPG-signed SHA256SUMS"
ASSETS="$WORK/assets"; mkdir -p "$ASSETS"
# 4a. the signed apt tree, packed as one tarball (what the pull agent unpacks)
STAGE="$WORK/openport-apt"; mkdir -p "$STAGE/apt" "$STAGE/checksums" "$STAGE/sbom"
rsync -a packaging/build/apt/ "$STAGE/apt/"
cp dist/*.deb.sha256 "$STAGE/checksums/" 2>/dev/null || true
cp dist/*.cdx.json dist/*.spdx.json "$STAGE/sbom/" 2>/dev/null || true
tar -C "$STAGE/.." -czf "$ASSETS/openport-apt-$VERSION.tar.gz" openport-apt
# 4b. the signed rpms, as-is
cp dist/*.rpm "$ASSETS/" 2>/dev/null || true
# 4c. mac .pkg / Windows installer .exe, if they have been dropped in
if [ -d "$EXTRA_ASSETS_DIR" ]; then
  find "$EXTRA_ASSETS_DIR" -maxdepth 1 -type f \( -name '*.pkg' -o -name '*.exe' \) \
    -exec cp {} "$ASSETS/" \;
fi
# 4d. one SHA256SUMS over every asset, clearsigned with the apt key. The pull
# agent verifies THIS against the committed key, then checks each file — so the
# same committed-key trust that protects the deb covers rpm/pkg/exe too.
export GNUPGHOME="$WORK/sumsgpg"; mkdir -p "$GNUPGHOME"; chmod 700 "$GNUPGHOME"
gpg --batch --quiet --import "$APT_SIGNING_KEY_FILE"
sums_fpr="$(gpg --list-secret-keys --with-colons | awk -F: '/^fpr:/{print $10; exit}')"
# Exclude SHA256SUMS* from its own listing (the > would otherwise glob it in).
( cd "$ASSETS"
  mapfile -t _f < <(find . -maxdepth 1 -type f ! -name 'SHA256SUMS*' -printf '%P\n' | sort)
  sha256sum -- "${_f[@]}" > SHA256SUMS )
gpg --batch --yes --pinentry-mode loopback --passphrase "" -u "$sums_fpr" \
  --clearsign -o "$ASSETS/SHA256SUMS.asc" "$ASSETS/SHA256SUMS"
unset GNUPGHOME
echo "    assets:"; ls -1 "$ASSETS" | sed 's/^/      /'

echo "==> 5. push tag to GitHub and create/update the DRAFT release"
git push "$GITHUB_REMOTE" "$TAG"
if gh release view "$TAG" --repo "$GITHUB_REPO" >/dev/null 2>&1; then
  gh release upload "$TAG" "$ASSETS"/* --repo "$GITHUB_REPO" --clobber
else
  gh release create "$TAG" "$ASSETS"/* \
    --repo "$GITHUB_REPO" --draft \
    --title "Openport $VERSION" \
    --notes "Signed release for openport $VERSION (deb repo + rpm, and mac/windows installers when attached). The web server pulls and verifies these against the committed signing key once this draft is published."
fi

echo
echo "Done. Review the DRAFT release at https://github.com/$GITHUB_REPO/releases"
echo "To add the mac .pkg / Windows .exe later: drop the signed files in"
echo "  $EXTRA_ASSETS_DIR"
echo "and re-run this script (it re-signs SHA256SUMS and re-uploads). Publish the"
echo "draft to go live; the prod pull agent converges within ~2 min."
