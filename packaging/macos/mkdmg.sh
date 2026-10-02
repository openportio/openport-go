#!/usr/bin/env bash
#
# Assembles the UNSIGNED mac installer from the darwin archives goreleaser
# already put in dist/: a flat distribution Openport.pkg (universal
# amd64+arm64 binary, /etc/users.conf, the io.openport LaunchDaemon — the
# same payload the signed 2.2.1 pkg shipped) wrapped in a UDZO
# Openport_<version>.dmg.
#
# Runs INSIDE the packaging/macos/Dockerfile image — use build-dmg.sh on the
# host. The pkg is built with cpio+mkbom+xar and the dmg with
# mkfs.hfsplus+libdmg-hfsplus, so no step needs macOS. Nothing is signed or
# notarized here: macOS shows the Gatekeeper "unidentified developer" prompt,
# exactly like the (expired-certificate, never-notarized) 2.2.1 installer
# effectively did. Signing, when it returns, happens offline like every other
# signature (see docs in openport-distribution/docs/release-architecture.md).

set -euo pipefail
VERSION="${1:?usage: mkdmg.sh <version>}"
cd /repo

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

echo "==> universal binary from the darwin archives"
for arch in amd64 arm64; do
  mkdir -p "$work/$arch"
  tar -xzf "dist/openport_${VERSION}_darwin_${arch}.tar.gz" -C "$work/$arch"
done
makefat "$work/openport" "$work/amd64/openport" "$work/arm64/openport"

echo "==> payload"
root="$work/root"
install -d -m 755 "$root/usr/local/bin" "$root/etc" "$root/Library/LaunchDaemons"
install -m 755 "$work/openport" "$root/usr/local/bin/openport"
install -m 644 packaging/macos/pkgroot/etc/users.conf "$root/etc/users.conf"
install -m 644 packaging/macos/pkgroot/Library/LaunchDaemons/io.openport.plist \
  "$root/Library/LaunchDaemons/io.openport.plist"

flat="$work/flat"
mkdir -p "$flat/Openport.pkg" "$flat/Resources"
# odc is the cpio format Installer expects; the container runs as root, so
# the payload records root:wheel (0:0) ownership like the 2.2.1 pkg did.
# gzip -n keeps the timestamp out of the stream.
( cd "$root" && find . | LC_ALL=C sort \
    | cpio -o --format odc --quiet | gzip -9 -n \
) > "$flat/Openport.pkg/Payload"
mkbom -u 0 -g 0 "$root" "$flat/Openport.pkg/Bom"

numfiles="$(find "$root" | wc -l)"
kbytes="$(du -sk "$root" | cut -f1)"

cat > "$flat/Openport.pkg/PackageInfo" <<EOF
<pkg-info format-version="2" identifier="openport.io.openport" version="$VERSION" relocatable="false" overwrite-permissions="false" followSymLinks="false" install-location="/" auth="root">
<payload installKBytes="$kbytes" numberOfFiles="$numfiles"/>
</pkg-info>
EOF

# hostArchitectures: the binary is universal, so Installer must not demand
# Rosetta on Apple Silicon (without it, a pkg defaults to x86_64-only).
cat > "$flat/Distribution" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<installer-gui-script minSpecVersion="1.0">
    <options hostArchitectures="x86_64,arm64"/>
    <title>Openport</title>
    <license file="license.txt"/>
    <conclusion file="conclusion.rtfd"/>
    <choices-outline>
        <line choice="installer_choice_1"/>
    </choices-outline>
    <choice id="installer_choice_1" title="Openport" description="">
        <pkg-ref id="openport.io.openport"/>
    </choice>
    <pkg-ref id="openport.io.openport" version="$VERSION" auth="Root" installKBytes="$kbytes">#Openport.pkg</pkg-ref>
</installer-gui-script>
EOF

cp -a packaging/macos/resources/en.lproj "$flat/Resources/en.lproj"
# The installer's license pane shows the project license, not a vendored copy
# that can drift from LICENSE.
cp LICENSE "$flat/Resources/en.lproj/license.txt"

echo "==> flat pkg (xar)"
( cd "$flat" && xar -cf "$work/Openport_$VERSION.pkg" \
    Distribution Resources Openport.pkg )

echo "==> dmg"
vol="$work/vol"
mkdir -p "$vol"
cp "$work/Openport_$VERSION.pkg" "$vol/Openport.pkg"
# -apple hybrid image + libdmg compression: Bitcoin's old deterministic mac
# dmg recipe. hfsprogs is gone from bookworm, so no real hfsplus filesystem.
genisoimage -quiet -no-cache-inodes -D -l -probe -no-pad -r -dir-mode 0755 \
  -apple -V "Openport_$VERSION" -o "$work/uncompressed.dmg" "$vol"
dmg "$work/uncompressed.dmg" "dist/Openport_$VERSION.dmg" >/dev/null

cp "$work/Openport_$VERSION.pkg" "dist/Openport_$VERSION.pkg"
( cd dist && for f in "Openport_$VERSION.pkg" "Openport_$VERSION.dmg"; do
    sha256sum "$f" > "$f.sha256"
  done )
echo "==> done: dist/Openport_$VERSION.dmg (pkg inside; bare pkg kept beside it)"
