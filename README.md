# Openport Client v2

The official client for https://openport.io.

See https://openport.readthedocs.io/en/latest/usage.html for all information.

Note:
The repo replaces the previous client: https://github.com/openportio/openport

## Repo commands

What builds what, and where the output lands:

| Command | What it does | Output |
| --- | --- | --- |
| `./compile.sh` | Quick native build on the host (needs Go) | `src/openport` |
| `./docker_compile.sh` | Builds the CI test image (`Dockerfile-amd64`) and copies the linux amd64 binary out of it | `openport-amd64` + docker image `openport-go-amd64` |
| `SNAPSHOT=1 ./packaging/release.sh` | Full release build with goreleaser, from any commit: all binaries, `.deb`/`.rpm` packages, archives, checksums, SBOMs. Extra flags pass through (e.g. `--skip=validate`, `--single-target`) | `dist/` |
| `./packaging/release.sh` | Same, but a real release: requires HEAD to be a `vX.Y.Z` tag (normally done by CI — see `RELEASE.md`) | `dist/` |
| `VERSION=x.y.z SKIP_UPLOAD=1 ./packaging/publish-apt.sh` | Builds the signed apt repository from the debs in `dist/` without uploading | `packaging/build/apt/` |
| `VERSION=x.y.z ./packaging/publish-apt.sh` | Publishes that apt repo + checksums + SBOMs to the web server and refreshes the `openport_latest_*` symlinks | `releases/` on the server |
| `./run_tests.sh` | The full CI test run: Go test suite + python e2e tests, both in docker compose | `test-results/` |
| `cd python_tests && make test` | Python e2e tests only | terminal |
| `./test_release_binaries.sh` | `openport selftest` with the goreleaser binaries: amd64 locally, armv6/armv7/arm64 on real hardware over ssh (pi-zero, router, mk4) | terminal |
| `./generate-sbom.sh [--source]` | SBOMs for the source tree and local dev builds (release SBOMs come from `release.sh`) | `sbom/` |
| `./create_snap.sh` / `./test-snap.sh` | Snap package (dormant) | `*.snap` |

Releasing = pushing a `vX.Y.Z` tag; `RELEASE.md` has the full story.
