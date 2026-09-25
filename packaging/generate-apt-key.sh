#!/usr/bin/env bash
#
# One-time setup: generates the GPG key pair that signs the apt repository.
#
#   private key -> ~/.openport-release/apt-signing-key.asc  (mode 600)
#       * upload as GitLab CI/CD *file* variable APT_SIGNING_KEY
#         (Settings -> CI/CD -> Variables; protected, so it is only exposed
#         to protected tags/branches)
#       * back it up somewhere offline -- if this key is lost, every
#         installed client stops trusting the repo until it is re-keyed
#   public key  -> packaging/openport-archive-keyring.asc
#       * commit this file; it ships inside the deb as
#         /usr/share/keyrings/openport-archive-keyring.gpg
#
# RSA-4096 rather than ed25519: the install base includes old Debian/Raspbian
# releases whose apt cannot verify EdDSA signatures. No expiry date -- an
# expired repo key bricks updates for every client; rotate deliberately
# instead (generate a new key, ship it in a release signed by the old one,
# then switch the repo signature).
#
# Refuses to overwrite an existing key.

set -euo pipefail
cd "$(dirname "$0")"

OUTDIR=${1:-$HOME/.openport-release}
PRIVATE_KEY=$OUTDIR/apt-signing-key.asc
PUBLIC_KEY=$PWD/openport-archive-keyring.asc
UID_STRING="Openport Archive Signing Key <jan@openport.io>"

for f in "$PRIVATE_KEY" "$PUBLIC_KEY"; do
  [ ! -e "$f" ] || { echo "ERROR: $f already exists -- refusing to overwrite a signing key" >&2; exit 1; }
done

mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"

GNUPGHOME=$(mktemp -d)
export GNUPGHOME
trap 'rm -rf "$GNUPGHOME"' EXIT

# No passphrase: the key lives in a CI variable, where a passphrase stored
# right next to it adds nothing. publish-apt.sh relies on this (loopback
# pinentry with an empty passphrase).
gpg --batch --quiet --pinentry-mode loopback --passphrase '' \
  --quick-generate-key "$UID_STRING" rsa4096 sign never

umask 077
gpg --batch --armor --export-secret-keys > "$PRIVATE_KEY"
umask 022
gpg --batch --armor --export > "$PUBLIC_KEY"

echo
gpg --batch --fingerprint
echo "Private key: $PRIVATE_KEY  (upload as CI file variable APT_SIGNING_KEY + back up offline)"
echo "Public key:  $PUBLIC_KEY  (commit this)"
