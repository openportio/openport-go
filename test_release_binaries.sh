#!/bin/bash
# Runs "openport selftest" with the goreleaser-built binaries: locally for
# amd64, and on real hardware over ssh for the arm variants (the armv6
# binary on the pi zero is exactly the case that once segfaulted with
# armv7 builds). Replaces test_docker_compilations.sh.
#
# Run SNAPSHOT=1 ./packaging/release.sh first to fill dist/.
set -ex
cd "$(dirname "$0")"

# goreleaser names the per-target dirs with micro-arch suffixes (v1, v8.0)
# that depend on defaults, hence the globs.
bin() {
  local glob="dist/$1/openport"
  # shellcheck disable=SC2086
  set -- $glob
  [ -f "$1" ] || { echo "ERROR: no binary at $glob -- run SNAPSHOT=1 ./packaging/release.sh first" >&2; exit 1; }
  echo "$1"
}

# amd64
"$(bin 'openport_linux_amd64*')" selftest

# armv6
scp "$(bin 'openport-armv6_linux_arm_6')" pi-zero:openport-armv6
ssh pi-zero ./openport-armv6 selftest

# armv7
scp "$(bin 'openport-armv7_linux_arm_7')" router:openport-armv7
ssh router ./openport-armv7 selftest

# arm64
scp "$(bin 'openport_linux_arm64*')" mk4:openport-arm64
ssh mk4 ./openport-arm64 selftest
