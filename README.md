# Openport Client v2

The official client for https://openport.io.

See https://openport.readthedocs.io/en/latest/usage.html for all information.

Note:
The repo replaces the previous client: https://github.com/openportio/openport

## Installation

**Debian / Ubuntu** (recommended — the repo self-enrolls, so `apt upgrade`
and unattended-upgrades keep openport current):

```sh
curl -fsSL https://openport.io/apt/install.sh | sudo sh
```

or add the repository by hand — `https://openport.io/apt stable main`, signing
key at `https://openport.io/apt/openport-archive-keyring.gpg`:

```sh
sudo curl -fsSL https://openport.io/apt/openport-archive-keyring.gpg \
  -o /usr/share/keyrings/openport-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/openport-archive-keyring.gpg] https://openport.io/apt stable main" \
  | sudo tee /etc/apt/sources.list.d/openport.list
sudo apt-get update && sudo apt-get install openport
```

The older `wget https://openport.io/download/debian64/latest.deb && sudo dpkg -i latest.deb`
path still works and enrols you in the repo on first install.

**Other platforms** — `.rpm`, the Windows installer, the macOS `.pkg`, and the
snap are built from the
openport-distribution repo. Full usage docs: https://openport.readthedocs.io/en/latest/usage.html

## Repo commands

**Local setup**: copy each `.env.example` to `.env` next to it and fill it in —
the repo root and `python_tests/docker-compose/` ones feed the docker-compose
test stacks, `packaging/` feeds the release scripts. The `.env` files are
gitignored; never commit them.

What builds what, and where the output lands:

| Command | What it does | Output |
| --- | --- | --- |
| `./compile.sh` | Builds the host-arch binary the python e2e tests use. Uses goreleaser so it matches a release build (same flags, sqlite driver, `./apps/openport` main); falls back to a plain `go build` if goreleaser is absent | `src/openport` |
| `./docker_compile.sh` | Builds the CI test image (`Dockerfile-amd64`) and copies the linux amd64 binary out of it | `openport-amd64` + docker image `openport-go-amd64` |
| `SNAPSHOT=1 ./packaging/release.sh` | Full release build with goreleaser, from any commit: all binaries, `.deb`/`.rpm` packages, archives, checksums, SBOMs. Extra flags pass through (e.g. `--skip=validate`, `--single-target`) | `dist/` |
| `./packaging/release.sh` | Same, but a real release: requires HEAD to be a `vX.Y.Z` tag (normally done by CI — see `RELEASE.md` in the openport-distribution repo) | `dist/` |
| `VERSION=x.y.z SKIP_UPLOAD=1 ./packaging/publish-apt.sh` | Builds the signed apt repository from the debs in `dist/` without uploading | `packaging/build/apt/` |
| `VERSION=x.y.z ./packaging/publish-apt.sh` | Publishes that apt repo + checksums + SBOMs to the web server and refreshes the `openport_latest_*` symlinks | `releases/` on the server |
| `./run_tests.sh` | The full CI test run: Go test suite + python e2e tests, both in docker compose | `test-results/` |
| `cd python_tests && make test` | Python e2e tests only | terminal |
| `./test_release_binaries.sh` | `openport selftest` with the goreleaser binaries: amd64 locally, armv6/armv7/arm64 on real hardware over ssh (pi-zero, router, mk4) | terminal |
| `./generate-sbom.sh [--source]` | SBOMs for the source tree and local dev builds (release SBOMs come from `release.sh`) | `sbom/` |
| `./create_snap.sh` / `./test-snap.sh` | Snap package (dormant) | `*.snap` |

### Build a single architecture

To produce just one binary for one target (no packaging), use goreleaser's
`--single-target`, which honours `GOOS`/`GOARCH` (defaulting to the host). The
binary matches a release build — same ldflags, version and modernc sqlite
driver — and lands at the `-o` path. Everything cross-compiles with
`CGO_ENABLED=0`, so no C toolchain is needed for other architectures.

```sh
# Host architecture (what ./compile.sh does, output to src/openport):
goreleaser build --snapshot --clean --single-target --id openport -o openport

# A specific 64-bit target, e.g. linux/arm64 or darwin/arm64
# (amd64/arm64 + linux/darwin all come from --id openport):
GOOS=linux GOARCH=arm64 goreleaser build --snapshot --clean --single-target --id openport -o openport

# 32-bit arm ships from its own build ids (goarm 6 and 7):
GOOS=linux GOARCH=arm goreleaser build --snapshot --clean --single-target --id openport-armv6 -o openport
```

For a quick throwaway build of one arch without goreleaser (skips the release
flags, but still cross-compiles thanks to `CGO_ENABLED=0`):

```sh
cd src && CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o openport ./apps/openport
```

Releasing = pushing a `vX.Y.Z` tag, then signing offline; the full procedure
lives in openport-distribution's `RELEASE.md`
(spec: `docs/release-architecture.md`).
