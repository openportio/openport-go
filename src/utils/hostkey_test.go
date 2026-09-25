package utils

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// newTestKey returns a fresh Ed25519 SSH public key and its authorized_keys
// representation.
func newTestKey(t *testing.T) (ssh.PublicKey, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %s", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("converting key: %s", err)
	}
	return sshPub, string(ssh.MarshalAuthorizedKey(sshPub))
}

// withTempKnownHosts points KnownHostsPath at a temp file for the duration of
// a test, and resets the once-per-run warning so tests do not interfere.
func withTempKnownHosts(t *testing.T) string {
	t.Helper()
	original := KnownHostsPath
	dir := t.TempDir()
	KnownHostsPath = path.Join(dir, "known_hosts")
	t.Cleanup(func() { KnownHostsPath = original })
	return KnownHostsPath
}

func TestAcceptsMatchingHostKey(t *testing.T) {
	withTempKnownHosts(t)
	key, authorized := newTestKey(t)

	cb, err := HostKeyCallback(authorized)
	if err != nil {
		t.Fatalf("building callback: %s", err)
	}
	if err := cb("ssh.openport.io:22", nil, key); err != nil {
		t.Fatalf("expected the matching key to be accepted, got: %s", err)
	}
}

// The core of the fix: a different key on the wire must be refused.
func TestRejectsMismatchedHostKey(t *testing.T) {
	withTempKnownHosts(t)
	_, authorized := newTestKey(t)
	attackerKey, _ := newTestKey(t)

	cb, err := HostKeyCallback(authorized)
	if err != nil {
		t.Fatalf("building callback: %s", err)
	}
	err = cb("ssh.openport.io:22", nil, attackerKey)
	if err == nil {
		t.Fatal("a mismatched host key was accepted; this is the MITM the fix exists to prevent")
	}
	if !strings.Contains(err.Error(), "mismatch") {
		t.Errorf("expected a mismatch error, got: %s", err)
	}
}

// A malformed host_key must fail closed rather than silently degrading to the
// unverified path -- otherwise an attacker could force the fallback by
// corrupting the field.
func TestMalformedPublishedKeyFailsClosed(t *testing.T) {
	withTempKnownHosts(t)
	if _, err := HostKeyCallback("ssh-rsa this-is-not-base64!!"); err == nil {
		t.Fatal("expected a malformed published host key to be rejected")
	}
}

func TestVerifiedConnectionRecordsKnownHost(t *testing.T) {
	p := withTempKnownHosts(t)
	key, authorized := newTestKey(t)

	cb, _ := HostKeyCallback(authorized)
	if err := cb("ssh.openport.io:22", nil, key); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	contents, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("known_hosts was not written: %s", err)
	}
	if !strings.Contains(string(contents), "ssh.openport.io:22") {
		t.Errorf("expected the host to be recorded, got: %q", contents)
	}
}

func TestKnownHostsFileIsNotWorldReadable(t *testing.T) {
	p := withTempKnownHosts(t)
	key, authorized := newTestKey(t)

	cb, _ := HostKeyCallback(authorized)
	if err := cb("ssh.openport.io:22", nil, key); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	info, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %s", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("known_hosts should be 0600, got %04o", perm)
	}
}

// Trust-on-first-use: no published key, host not seen before -> accept and
// record.
func TestTrustOnFirstUseAcceptsUnknownHost(t *testing.T) {
	p := withTempKnownHosts(t)
	key, _ := newTestKey(t)

	cb, err := HostKeyCallback("")
	if err != nil {
		t.Fatalf("building callback: %s", err)
	}
	if err := cb("ssh.openport.io:22", nil, key); err != nil {
		t.Fatalf("first use should be accepted, got: %s", err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("first use should have been recorded: %s", err)
	}
}

// Trust-on-first-use: a host whose key changed must be refused. This is the
// tripwire that catches a compromise even when no key is published.
func TestTrustOnFirstUseRejectsChangedKey(t *testing.T) {
	withTempKnownHosts(t)
	first, _ := newTestKey(t)
	second, _ := newTestKey(t)

	cb, _ := HostKeyCallback("")
	if err := cb("ssh.openport.io:22", nil, first); err != nil {
		t.Fatalf("first use should be accepted, got: %s", err)
	}
	err := cb("ssh.openport.io:22", nil, second)
	if err == nil {
		t.Fatal("a changed host key was accepted under trust-on-first-use")
	}
	if !strings.Contains(err.Error(), "CHANGED") {
		t.Errorf("expected a changed-key error, got: %s", err)
	}
}

// Different hosts must not share an entry -- otherwise connecting to a second
// server would look like a key change on the first.
func TestDistinctHostsAreTrackedSeparately(t *testing.T) {
	withTempKnownHosts(t)
	keyA, _ := newTestKey(t)
	keyB, _ := newTestKey(t)

	cb, _ := HostKeyCallback("")
	if err := cb("eu.openport.io:22", nil, keyA); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}
	if err := cb("us.openport.io:22", nil, keyB); err != nil {
		t.Fatalf("a different host should not be treated as a key change: %s", err)
	}
	if err := cb("eu.openport.io:22", nil, keyA); err != nil {
		t.Fatalf("reconnecting to the first host should still verify: %s", err)
	}
}

// When the API vouches for a rotated key the connection proceeds, but the
// stored entry is updated so the next connection verifies against the new key.
func TestPublishedKeyRotationUpdatesKnownHosts(t *testing.T) {
	p := withTempKnownHosts(t)
	oldKey, oldAuthorized := newTestKey(t)
	newKey, newAuthorized := newTestKey(t)

	cbOld, _ := HostKeyCallback(oldAuthorized)
	if err := cbOld("ssh.openport.io:22", nil, oldKey); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	cbNew, _ := HostKeyCallback(newAuthorized)
	if err := cbNew("ssh.openport.io:22", nil, newKey); err != nil {
		t.Fatalf("a rotation vouched for by the server should be accepted, got: %s", err)
	}

	contents, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("reading known_hosts: %s", err)
	}
	if strings.Count(string(contents), "ssh.openport.io:22") != 1 {
		t.Errorf("expected exactly one entry after rotation, got: %q", contents)
	}
	if !strings.Contains(string(contents), strings.TrimSpace(strings.Fields(newAuthorized)[1])) {
		t.Errorf("known_hosts should hold the new key, got: %q", contents)
	}
}

// A stored key must still be enforced even if the file has comments, blank
// lines, and unrelated entries around it.
func TestKnownHostsParsingIgnoresNoise(t *testing.T) {
	p := withTempKnownHosts(t)
	key, _ := newTestKey(t)
	other, _ := newTestKey(t)

	entry := "ssh.openport.io:22 " + string(ssh.MarshalAuthorizedKey(key))
	contents := "# a comment\n\n   \nother.host:22 " +
		string(ssh.MarshalAuthorizedKey(other)) + entry
	if err := os.WriteFile(p, []byte(contents), 0600); err != nil {
		t.Fatalf("writing known_hosts: %s", err)
	}

	cb, _ := HostKeyCallback("")
	if err := cb("ssh.openport.io:22", nil, key); err != nil {
		t.Fatalf("the stored key should verify: %s", err)
	}
	if err := cb("ssh.openport.io:22", nil, other); err == nil {
		t.Fatal("a key belonging to a different host was accepted")
	}
}

func TestHostKeyAlgorithmsMatchThePublishedKeyType(t *testing.T) {
	_, authorized := newTestKey(t)
	got := HostKeyAlgorithms(authorized)
	want := []string{ssh.KeyAlgoED25519}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("HostKeyAlgorithms(ed25519 key) = %v, want %v", got, want)
	}
}

func TestHostKeyAlgorithmsForRSAOfferAllRSASignatureVariants(t *testing.T) {
	// An ssh-rsa key can be verified via any RSA signature algorithm; all of
	// them must be offered or a server preferring rsa-sha2 could not connect.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %s", err)
	}
	sshPub, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("converting key: %s", err)
	}
	got := HostKeyAlgorithms(string(ssh.MarshalAuthorizedKey(sshPub)))
	want := []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSA}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("HostKeyAlgorithms(rsa key) = %v, want %v", got, want)
	}
}

func TestHostKeyAlgorithmsFallBackToLibraryDefaults(t *testing.T) {
	// No published key (TOFU) and a malformed key both return nil: the first
	// has nothing to pin to, the second is rejected by HostKeyCallback anyway.
	if got := HostKeyAlgorithms(""); got != nil {
		t.Errorf("HostKeyAlgorithms(\"\") = %v, want nil", got)
	}
	if got := HostKeyAlgorithms("not a key"); got != nil {
		t.Errorf("HostKeyAlgorithms(malformed) = %v, want nil", got)
	}
}
