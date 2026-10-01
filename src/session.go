package openport

import (
	"fmt"

	db "github.com/openportio/openport-go/database"
	log "github.com/sirupsen/logrus"
)

// tunnelDialAddress is the local address incoming tunnel connections are
// proxied to: the in-process TLS terminator when passthrough is active, the
// forwarded service itself otherwise. It reads TlsProxyPort, which is runtime
// state (not persisted), so it lives with the tunnel logic rather than in the
// database package.
func tunnelDialAddress(s db.Session) string {
	if s.TlsProxyPort != 0 {
		return fmt.Sprintf("127.0.0.1:%d", s.TlsProxyPort)
	}
	return fmt.Sprintf("localhost:%d", s.LocalPort)
}

// printSessionMessage logs the user-facing "Now forwarding ..." line for a
// session (how the forward is presented to the user), then the server's
// message. This is presentation, so it belongs with the client rather than in
// the database package.
func printSessionMessage(s db.Session, message string, udpActive bool) {
	if s.TlsPassthrough {
		address := s.HttpForwardAddress
		if s.CustomDomain != "" {
			address = s.CustomDomain
		}
		if s.LocalTLS {
			log.Infof("Now forwarding https://%s to localhost:%d (end-to-end TLS; your local service holds the certificate)", address, s.LocalPort)
		} else {
			log.Infof("Now forwarding https://%s to localhost:%d (TLS terminates on this machine)", address, s.LocalPort)
		}
	} else if s.HttpForward {
		log.Infof("Now forwarding remote address %s to localhost", s.HttpForwardAddress)
	} else {
		suffix := ""
		if udpActive {
			suffix = " (tcp & udp)"
		}
		log.Infof("Now forwarding remote port %s:%d to localhost:%d%s", s.SshServer, s.RemotePort, s.LocalPort, suffix)
	}
	log.Info(message)
}
