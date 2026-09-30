#!/usr/bin/env bash
#
# Builds all release artifacts with goreleaser (binaries for every target,
# .deb/.rpm packages, archives, per-artifact SHA-256 checksums and
# CycloneDX/SPDX SBOMs — see .goreleaser.yaml). Output lands in dist/.
#
# Publishing stays separate: run packaging/publish-apt.sh afterwards to
# regenerate and upload the signed apt repo.
#
# Usage:
#   ./packaging/release.sh              # real release: requires HEAD == a vX.Y.Z tag
#   SNAPSHOT=1 ./packaging/release.sh   # local test build from any commit
#
# Only docker is required on the host; the goreleaser/syft/gpg environment
# is built as an image from packaging/Dockerfile-goreleaser.

set -euo pipefail
cd "$(dirname "$0")/.."

SNAPSHOT=${SNAPSHOT:-0}
IMAGE=openport-goreleaser

ARGS=(release --clean)
if [ "$SNAPSHOT" = 1 ]; then
  ARGS+=(--snapshot)
fi

docker build -q -f packaging/Dockerfile-goreleaser -t "$IMAGE" packaging >/dev/null

# Root inside the container: the named cache volumes and the go build need
# write access. dist/ is chowned back to the host user afterwards, even on
# failure, so the next run's --clean does not hit root-owned files.
run() {
  docker run --rm \
    -v "$PWD":/repo -w /repo \
    -v openport-goreleaser-gocache:/root/.cache/go-build \
    -v openport-goreleaser-gomod:/go/pkg/mod \
    "$IMAGE" "$@"
}
trap 'run chown -R "$(id -u):$(id -g)" /repo/dist /repo/packaging/build 2>/dev/null || true' EXIT

run goreleaser "${ARGS[@]}"

# goreleaser's split checksum files hold the bare digest; rewrite them to
# "digest  filename" so "sha256sum -c <file>.sha256" works next to the
# download, as the previous release tooling produced. In the container:
# dist/ is root-owned until the trap below chowns it.
run sh -ec '
  for f in dist/*.sha256; do
    [ -e "$f" ] || continue
    # No trailing newline in the file: read fills the variable but
    # returns non-zero at EOF.
    read -r digest _ < "$f" || true
    [ -n "$digest" ] || continue
    printf "%s  %s\n" "$digest" "$(basename "${f%.sha256}")" > "$f"
  done
'

echo
echo "Artifacts in dist/:"
ls -1 dist | grep -v '^[^.]*$' || true
