package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
	"io/ioutil"
	"os"
	"os/user"
	"path"
)

func GetHomeDir() string {
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

var SSH_PRIVATE_KEY_PATH = path.Join(HOMEDIR, ".ssh", "id_rsa")
var SSH_PUBLIC_KEY_PATH = path.Join(HOMEDIR, ".ssh", "id_rsa.pub")

func CreateKeys() ([]byte, ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	// generate and write private key as PEM
	privateKeyFile, err := os.Create(OPENPORT_PRIVATE_KEY_PATH)
	if err != nil {
		return nil, nil, err
	}
	defer privateKeyFile.Close()
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return nil, nil, err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	err = ioutil.WriteFile(OPENPORT_PUBLIC_KEY_PATH, ssh.MarshalAuthorizedKey(pub), 0655)
	if err != nil {
		return nil, nil, err
	}
	return ReadKeys()
}

func ReadKeys() ([]byte, ssh.Signer, error) {
	publicKey, err := ioutil.ReadFile(OPENPORT_PUBLIC_KEY_PATH)
	if err != nil {
		return nil, nil, err
	}

	buf, err := ioutil.ReadFile(OPENPORT_PRIVATE_KEY_PATH)
	if err != nil {
		return nil, nil, err
	}

	key, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, nil, err
	}
	log.Debugf(string(publicKey))
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
		// File exists
		return ReadKeys()
	} else {
		_, err1 := os.Stat(SSH_PRIVATE_KEY_PATH)
		_, err2 := os.Stat(SSH_PUBLIC_KEY_PATH)
		if err1 == nil && err2 == nil {
			// ssh-key exists
			buf, err := ioutil.ReadFile(SSH_PRIVATE_KEY_PATH)
			if err != nil {
				log.Warn(err)
				return CreateKeys()
			}

			block, rest := pem.Decode(buf)
			if len(rest) > 0 {
				log.Debugf("Extra data included in key, creating new keys.")
				return CreateKeys()
			} else {
				if x509.IsEncryptedPEMBlock(block) {
					log.Debugf("Encrypted key, creating new keys.")
					return CreateKeys()
				} else {
					log.Debugf("Usable keys in %s, copying to %s", SSH_PUBLIC_KEY_PATH, OPENPORT_PUBLIC_KEY_PATH)
					err = ioutil.WriteFile(OPENPORT_PRIVATE_KEY_PATH, buf, 0600)
					if err != nil {
						log.Warn(err)
						return CreateKeys()
					}

					pubBuf, err := ioutil.ReadFile(SSH_PUBLIC_KEY_PATH)
					err = ioutil.WriteFile(OPENPORT_PUBLIC_KEY_PATH, pubBuf, 0600)
					if err != nil {
						log.Warn(err)
						return CreateKeys()
					}
					return ReadKeys()
				}
			}
		} else {
			return CreateKeys()
		}
	}
}
