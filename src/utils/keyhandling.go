package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"os"
	"os/user"
	"path"
)

func GetHomeDir() string {
	if os.Getenv("HOME") != "" {
		return os.Getenv("HOME")
	}

	currentUser, err := user.Current()
	if err != nil {
		log.Warn(err)
		return "/root"
	} else {
		return currentUser.HomeDir
	}
}

var HOMEDIR = GetHomeDir()

var OPENPORT_HOME = path.Join(HOMEDIR, ".openport")
var OPENPORT_PRIVATE_KEY_PATH = path.Join(OPENPORT_HOME, "id_rsa")
var OPENPORT_PUBLIC_KEY_PATH = path.Join(OPENPORT_HOME, "id_rsa.pub")

// Note: the user's own ~/.ssh keys are deliberately not referenced any more.
// EnsureKeysExist used to adopt ~/.ssh/id_rsa as the openport identity; see the
// comment there for why that was removed.

// KeyBits is the size of newly generated RSA identity keys.
//
// This was 1024 until 2026-07, which has been below every published baseline
// since NIST disallowed it in 2013. These are long-lived keys registered to a
// user's account, so a weak one is not a transient exposure.
//
// Ed25519 would be the better choice -- shorter, faster, no parameter to get
// wrong -- but the server cannot accept it yet: the key validator, the key
// stripper and the Go SSH server all assume an "ssh-rsa " prefix. Once those
// are fixed and deployed, switch this over. See CRA-COMPLIANCE-PLAN.md item 10.
const KeyBits = 4096

// MinAcceptableKeyBits is the size below which an existing key is considered
// too weak to keep using. Existing keys are not rotated automatically -- see
// WarnIfKeyIsWeak.
const MinAcceptableKeyBits = 2048

func CreateKeys() ([]byte, ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, KeyBits)
	if err != nil {
		return nil, nil, err
	}

	// Write the private key 0600 explicitly. os.Create uses 0666 before umask,
	// so on a permissive umask the private key was world-readable. The
	// containing directory is 0700, which mitigated it but did not fix it.
	privateKeyFile, err := os.OpenFile(
		OPENPORT_PRIVATE_KEY_PATH,
		os.O_WRONLY|os.O_CREATE|os.O_TRUNC,
		0600,
	)
	if err != nil {
		return nil, nil, err
	}
	defer privateKeyFile.Close()
	// OpenFile's mode only applies when the file is being created. Rotating
	// over a key written by an older client reuses its inode, and those were
	// created 0644 -- so tighten the permissions explicitly every time.
	if err := privateKeyFile.Chmod(0600); err != nil {
		return nil, nil, err
	}
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return nil, nil, err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}
	// 0644, not 0655. The public key is not secret, but 0655 granted group and
	// other the execute bit on a data file, which was simply a typo.
	err = os.WriteFile(OPENPORT_PUBLIC_KEY_PATH, []byte(fmt.Sprintf("%s %s", ssh.MarshalAuthorizedKey(pub), hostname)), 0644)
	if err != nil {
		return nil, nil, err
	}
	return ReadKeys()
}

// WarnIfKeyIsWeak reports an existing identity key that is below
// MinAcceptableKeyBits.
//
// It deliberately does not rotate the key. The public key *is* the account
// identity -- the server looks up the user by it on every request -- so
// silently generating a new one would detach the client from its account and
// drop a paying user onto the free tier. Migrating existing keys needs a
// server-side way to relink a new key to an existing account; until that
// exists, the honest thing is to tell the user.
func WarnIfKeyIsWeak(key ssh.Signer) {
	weak, bits := KeyIsWeak(key)
	if !weak {
		return
	}
	log.Warnf(
		"Your openport key is only %d-bit RSA, which is no longer considered "+
			"secure. Run 'openport rotate-key <token>' to replace it with a "+
			"%d-bit key; your reserved ports are carried over. Get the token at "+
			"https://openport.io/user/keys .",
		bits, KeyBits,
	)
}

// KeyIsWeak reports whether an identity key is below MinAcceptableKeyBits,
// and its size. Non-RSA keys are never considered weak on size.
func KeyIsWeak(key ssh.Signer) (bool, int) {
	cryptoKey, ok := key.PublicKey().(ssh.CryptoPublicKey)
	if !ok {
		return false, 0
	}
	rsaKey, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
	if !ok {
		return false, 0
	}
	bits := rsaKey.N.BitLen()
	return bits < MinAcceptableKeyBits, bits
}

// RotateKeys replaces the stored identity key with a freshly generated one.
//
// It returns the previous public key, the new one, and a restore function.
//
// The old public key is what lets the server retire the key being replaced:
// it is sent as replaces_public_key when registering. Without it the old key
// stays active and remains a usable credential.
//
// The restore function puts the previous key back. Registering the new key can
// fail -- the network drops, the token is wrong, the account is at its key
// limit -- and a client left holding a key the server has never seen has lost
// access to its account with no way back. Callers must restore on any failure
// to register.
func RotateKeys() (oldPublicKey []byte, newPublicKey []byte, restore func(), err error) {
	EnsureHomeFolderExists()

	// Read the existing material before overwriting it, so it can be put back.
	previousPrivate, privateErr := os.ReadFile(OPENPORT_PRIVATE_KEY_PATH)
	previousPublic, publicErr := os.ReadFile(OPENPORT_PUBLIC_KEY_PATH)
	hadPreviousKey := privateErr == nil && publicErr == nil

	if hadPreviousKey {
		oldPublicKey = previousPublic
	} else {
		log.Debug("No existing key pair to rotate away from; creating a new one.")
	}

	restore = func() {
		if !hadPreviousKey {
			return
		}
		if err := os.WriteFile(OPENPORT_PRIVATE_KEY_PATH, previousPrivate, 0600); err != nil { // #nosec G703 -- path is OPENPORT_HOME/id_rsa, chosen by the local user, not remote input
			log.Errorf("Could not restore your previous private key: %s", err)
			return
		}
		if err := os.WriteFile(OPENPORT_PUBLIC_KEY_PATH, previousPublic, 0644); err != nil { // #nosec G703 G306 -- same local path; the public key is deliberately world-readable
			log.Errorf("Could not restore your previous public key: %s", err)
			return
		}
		log.Info("Your previous key has been restored; nothing was changed.")
	}

	newPublicKey, _, err = CreateKeys()
	if err != nil {
		restore()
		return nil, nil, restore, err
	}
	return oldPublicKey, newPublicKey, restore, nil
}

func ReadKeys() ([]byte, ssh.Signer, error) {
	publicKey, err := os.ReadFile(OPENPORT_PUBLIC_KEY_PATH)
	if err != nil {
		return nil, nil, err
	}

	buf, err := os.ReadFile(OPENPORT_PRIVATE_KEY_PATH)
	if err != nil {
		return nil, nil, err
	}

	key, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, nil, err
	}
	log.Debug(string(publicKey))
	return publicKey, key, nil
}

func EnsureHomeFolderExists() {
	err := os.Mkdir(OPENPORT_HOME, 0700)
	if err != nil {
		if !os.IsExist(err) {
			log.Fatal(err)
		}
	} else {
		log.Debugf("Created directory %s", OPENPORT_HOME)
	}
}

func EnsureKeysExist() ([]byte, ssh.Signer, error) {
	EnsureHomeFolderExists()

	if _, err := os.Stat(OPENPORT_PRIVATE_KEY_PATH); err == nil {
		publicKey, signer, err := ReadKeys()
		if err == nil {
			WarnIfKeyIsWeak(signer)
		}
		return publicKey, signer, err
	}

	// Always generate a dedicated key.
	//
	// This used to copy the user's general-purpose ~/.ssh/id_rsa into
	// ~/.openport/ and register that public key with openport.io. That was
	// poor hygiene and surprising: a user's primary SSH identity -- the one
	// that may authenticate them to their own servers, their forge, their
	// employer's infrastructure -- became a third-party service credential
	// without being asked.
	//
	// It also silently defeated the key-strength fix: on any machine with an
	// existing ~/.ssh/id_rsa, a fresh install would adopt that key, whatever
	// its size or age, instead of generating a strong one.
	//
	// This only affects new installations. Anyone who already has
	// ~/.openport/id_rsa keeps it, including keys that were copied in by the
	// old behaviour, so no existing account linkage is broken.
	return CreateKeys()
}
