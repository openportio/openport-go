package utils

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"path"
	"strings"
	"sync"

	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

// SSH host key verification.
//
// The client previously used ssh.InsecureIgnoreHostKey(), which accepts any
// host key presented on the SSH leg. Combined with the fallback address
// supplied by the API response, that allowed an attacker positioned on the
// network to transparently intercept every tunnel.
//
// Trust model
// -----------
// The expected host key is delivered in the /api/v1/request-port response,
// over a certificate-verified HTTPS connection. The client already trusts that
// response to tell it *where* to connect (server_ip, fallback_ssh_server_ip);
// this closes the gap where it trusted nothing to tell it *who* answers.
//
// The guarantee is therefore bounded by the Web PKI: an attacker who can forge
// a certificate for the API host controls both the address and the expected
// key. That is not a regression -- it is already true of everything else the
// client does -- but it is the honest limit of this mechanism.
//
// DNS (SSHFP) was considered and rejected: it is only meaningful under DNSSEC,
// Go's resolver does not validate DNSSEC, and an attacker able to intercept the
// SSH connection can generally spoof DNS as well.
//
// known_hosts caching layers a tripwire on top: a key seen before that changes
// is reported loudly even when the API says the new key is fine. That catches a
// one-off TLS compromise on the next connection instead of letting it pass
// silently.

var KnownHostsPath = path.Join(OPENPORT_HOME, "known_hosts")

// Serialises read-modify-write of the known_hosts file. A client can run
// several sessions in one process, each connecting concurrently.
var knownHostsMutex sync.Mutex

// warnOnce keeps the "no host key published" warning to one line per run
// rather than one per reconnect.
var warnOnce sync.Once

// HostKeyCallback builds the ssh.HostKeyCallback used for a session.
//
// expectedAuthorizedKey is the server's public host key in authorized_keys
// format ("ssh-rsa AAAA..."), as published by the API in the host_key field.
//
// When it is empty -- an older server, or one that has not been configured yet
// -- the client falls back to trust-on-first-use against known_hosts rather
// than failing. That fallback is deliberate and temporary: it exists so that
// upgrading clients do not break against servers that have not yet started
// publishing the key. Once servers reliably publish host_key, this should
// become a hard failure. See CRA-COMPLIANCE-PLAN.md Track C item 9.
func HostKeyCallback(expectedAuthorizedKey string) (ssh.HostKeyCallback, error) {
	expectedAuthorizedKey = strings.TrimSpace(expectedAuthorizedKey)

	if expectedAuthorizedKey == "" {
		warnOnce.Do(func() {
			log.Warn("The server did not publish its SSH host key; falling back to " +
				"trust-on-first-use. The first connection to a new server cannot be " +
				"verified. Upgrade the server to publish host_key.")
		})
		return trustOnFirstUseCallback, nil
	}

	expectedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(expectedAuthorizedKey))
	if err != nil {
		// Fail closed. A malformed key from the server is either a bug or an
		// attempt to push us onto the unverified path, and neither warrants
		// connecting anyway.
		return nil, fmt.Errorf("could not parse the host key published by the server: %w", err)
	}

	return func(hostname string, remote net.Addr, presented ssh.PublicKey) error {
		if !keysEqual(presented, expectedKey) {
			return fmt.Errorf(
				"SSH host key mismatch for %s.\n"+
					"  expected (from server): %s\n"+
					"  offered by host:        %s\n"+
					"This means the host answering is not the one openport.io identified. "+
					"Refusing to connect.",
				hostname, fingerprint(expectedKey), fingerprint(presented))
		}

		// The key matched what the API published. Still compare against
		// known_hosts: if we have seen a different key for this host before,
		// say so. That is not necessarily an attack -- the operator may have
		// rotated the key -- but it should never happen silently.
		if err := checkAndRecordKnownHost(hostname, presented); err != nil {
			log.Warnf("known_hosts: %s", err)
		}
		return nil
	}, nil
}

// trustOnFirstUseCallback verifies against known_hosts only. Unknown hosts are
// accepted and recorded; a host whose key has changed is rejected.
func trustOnFirstUseCallback(hostname string, remote net.Addr, presented ssh.PublicKey) error {
	knownHostsMutex.Lock()
	defer knownHostsMutex.Unlock()

	stored, found, err := lookupKnownHost(hostname)
	if err != nil {
		return fmt.Errorf("could not read %s: %w", KnownHostsPath, err)
	}

	if !found {
		log.Infof("Recording SSH host key for %s (%s) on first use.", hostname, fingerprint(presented))
		return appendKnownHost(hostname, presented)
	}

	if !keysEqual(presented, stored) {
		return fmt.Errorf(
			"SSH host key for %s has CHANGED.\n"+
				"  previously seen: %s\n"+
				"  now offered:     %s\n"+
				"Someone may be intercepting the connection. If the key was rotated "+
				"legitimately, remove the entry for %s from %s and reconnect.",
			hostname, fingerprint(stored), fingerprint(presented), hostname, KnownHostsPath)
	}
	return nil
}

// checkAndRecordKnownHost records the key for a host, or reports a change. It
// returns an error describing a change rather than rejecting: when the API has
// already vouched for the key, a rotation is expected and should not break the
// connection.
func checkAndRecordKnownHost(hostname string, presented ssh.PublicKey) error {
	knownHostsMutex.Lock()
	defer knownHostsMutex.Unlock()

	stored, found, err := lookupKnownHost(hostname)
	if err != nil {
		return err
	}
	if !found {
		return appendKnownHost(hostname, presented)
	}
	if !keysEqual(presented, stored) {
		if err := replaceKnownHost(hostname, presented); err != nil {
			return err
		}
		return fmt.Errorf(
			"host key for %s changed from %s to %s; the server vouched for the new key, "+
				"so this is most likely a legitimate key rotation. Updated %s",
			hostname, fingerprint(stored), fingerprint(presented), KnownHostsPath)
	}
	return nil
}

func keysEqual(a, b ssh.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	// Compare the wire encoding rather than the fingerprint: it is the actual
	// key material, and avoids depending on a hash for a security decision.
	x, y := a.Marshal(), b.Marshal()
	if len(x) != len(y) {
		return false
	}
	var diff byte
	for i := range x {
		diff |= x[i] ^ y[i]
	}
	return diff == 0
}

func fingerprint(key ssh.PublicKey) string {
	if key == nil {
		return "<none>"
	}
	return ssh.FingerprintSHA256(key)
}

// known_hosts here is a simplified version of the OpenSSH format:
//
//	<host> <keytype> <base64>
//
// Hashed hostnames, wildcards, markers (@revoked) and multiple keys per host
// are not supported -- this file is written and read only by openport, and
// keeping the parser small keeps it auditable.
func lookupKnownHost(hostname string) (ssh.PublicKey, bool, error) {
	f, err := os.Open(KnownHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[0] != hostname {
			continue
		}
		blob, err := base64.StdEncoding.DecodeString(fields[2])
		if err != nil {
			log.Warnf("Ignoring malformed entry for %s in %s", hostname, KnownHostsPath)
			continue
		}
		key, err := ssh.ParsePublicKey(blob)
		if err != nil {
			log.Warnf("Ignoring unparseable key for %s in %s", hostname, KnownHostsPath)
			continue
		}
		return key, true, nil
	}
	return nil, false, scanner.Err()
}

func appendKnownHost(hostname string, key ssh.PublicKey) error {
	if err := os.MkdirAll(path.Dir(KnownHostsPath), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(KnownHostsPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s %s", hostname, ssh.MarshalAuthorizedKey(key))
	return err
}

func replaceKnownHost(hostname string, key ssh.PublicKey) error {
	f, err := os.Open(KnownHostsPath)
	if err != nil {
		if os.IsNotExist(err) {
			return appendKnownHost(hostname, key)
		}
		return err
	}
	var kept []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) >= 1 && fields[0] == hostname {
			continue
		}
		kept = append(kept, line)
	}
	scanErr := scanner.Err()
	f.Close()
	if scanErr != nil {
		return scanErr
	}

	kept = append(kept, strings.TrimRight(
		fmt.Sprintf("%s %s", hostname, ssh.MarshalAuthorizedKey(key)), "\n"))

	// Write via a temp file and rename so an interrupted write cannot leave a
	// truncated known_hosts behind.
	tmp := KnownHostsPath + ".tmp"
	if err := os.WriteFile(tmp, []byte(strings.Join(kept, "\n")+"\n"), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, KnownHostsPath)
}
