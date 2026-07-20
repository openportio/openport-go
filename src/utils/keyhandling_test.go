package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"os"
	"path"
	"testing"

	"golang.org/x/crypto/ssh"
)

// withTempOpenportHome points the key paths at a temp dir for one test.
func withTempOpenportHome(t *testing.T) string {
	t.Helper()
	origHome, origPriv, origPub := OPENPORT_HOME, OPENPORT_PRIVATE_KEY_PATH, OPENPORT_PUBLIC_KEY_PATH
	dir := t.TempDir()
	OPENPORT_HOME = path.Join(dir, ".openport")
	OPENPORT_PRIVATE_KEY_PATH = path.Join(OPENPORT_HOME, "id_rsa")
	OPENPORT_PUBLIC_KEY_PATH = path.Join(OPENPORT_HOME, "id_rsa.pub")
	t.Cleanup(func() {
		OPENPORT_HOME, OPENPORT_PRIVATE_KEY_PATH, OPENPORT_PUBLIC_KEY_PATH = origHome, origPriv, origPub
	})
	// CreateKeys assumes the directory already exists; EnsureHomeFolderExists
	// is what normally guarantees that.
	if err := os.MkdirAll(OPENPORT_HOME, 0700); err != nil {
		t.Fatalf("creating temp openport home: %s", err)
	}
	return OPENPORT_HOME
}

// The regression test for the actual finding: keys must not be 1024-bit.
func TestGeneratedKeyIsStrong(t *testing.T) {
	withTempOpenportHome(t)

	_, signer, err := CreateKeys()
	if err != nil {
		t.Fatalf("CreateKeys: %s", err)
	}

	cryptoKey, ok := signer.PublicKey().(ssh.CryptoPublicKey)
	if !ok {
		t.Fatal("public key does not expose the underlying crypto key")
	}
	rsaKey, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		t.Fatalf("expected an RSA key, got %T", cryptoKey.CryptoPublicKey())
	}
	if bits := rsaKey.N.BitLen(); bits != KeyBits {
		t.Errorf("expected a %d-bit key, got %d", KeyBits, bits)
	}
	if KeyBits < MinAcceptableKeyBits {
		t.Errorf("KeyBits (%d) is below MinAcceptableKeyBits (%d)", KeyBits, MinAcceptableKeyBits)
	}
}

// The private key must not be readable by anyone else. os.Create would have
// produced 0666 before umask.
func TestPrivateKeyIsNotReadableByOthers(t *testing.T) {
	withTempOpenportHome(t)

	if _, _, err := CreateKeys(); err != nil {
		t.Fatalf("CreateKeys: %s", err)
	}

	info, err := os.Stat(OPENPORT_PRIVATE_KEY_PATH)
	if err != nil {
		t.Fatalf("stat: %s", err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Errorf("private key should be 0600, got %04o", perm)
	}
	if perm&0o077 != 0 {
		t.Errorf("private key is accessible to group or other: %04o", perm)
	}
}

func TestPublicKeyPermissions(t *testing.T) {
	withTempOpenportHome(t)

	if _, _, err := CreateKeys(); err != nil {
		t.Fatalf("CreateKeys: %s", err)
	}

	info, err := os.Stat(OPENPORT_PUBLIC_KEY_PATH)
	if err != nil {
		t.Fatalf("stat: %s", err)
	}
	// 0644, not the old 0655 -- a data file should not carry execute bits.
	if perm := info.Mode().Perm(); perm != 0644 {
		t.Errorf("public key should be 0644, got %04o", perm)
	}
}

// EnsureKeysExist must never adopt the user's ~/.ssh/id_rsa as the openport
// identity. Beyond the hygiene problem, doing so would bypass the key-strength
// guarantee entirely.
func TestEnsureKeysExistDoesNotAdoptUserSshKey(t *testing.T) {
	home := withTempOpenportHome(t)

	// A weak key sitting where the old code would have found it.
	sshDir := path.Join(path.Dir(home), ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatalf("mkdir: %s", err)
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("generating weak key: %s", err)
	}
	weakPub, err := ssh.NewPublicKey(&weak.PublicKey)
	if err != nil {
		t.Fatalf("converting: %s", err)
	}

	_, signer, err := EnsureKeysExist()
	if err != nil {
		t.Fatalf("EnsureKeysExist: %s", err)
	}

	generated := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if string(generated) == string(ssh.MarshalAuthorizedKey(weakPub)) {
		t.Fatal("the user's own SSH key was adopted as the openport identity")
	}

	cryptoKey := signer.PublicKey().(ssh.CryptoPublicKey)
	if bits := cryptoKey.CryptoPublicKey().(*rsa.PublicKey).N.BitLen(); bits != KeyBits {
		t.Errorf("expected a freshly generated %d-bit key, got %d", KeyBits, bits)
	}
}

// An existing key is reused rather than regenerated: the public key is the
// account identity, so replacing it would detach the client from its account.
func TestEnsureKeysExistReusesExistingKey(t *testing.T) {
	withTempOpenportHome(t)

	_, first, err := EnsureKeysExist()
	if err != nil {
		t.Fatalf("first call: %s", err)
	}
	_, second, err := EnsureKeysExist()
	if err != nil {
		t.Fatalf("second call: %s", err)
	}

	if string(ssh.MarshalAuthorizedKey(first.PublicKey())) !=
		string(ssh.MarshalAuthorizedKey(second.PublicKey())) {
		t.Error("the existing key was replaced; this would orphan the user's account")
	}
}
