package openport

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	db "github.com/openportio/openport-go/database"
	"github.com/openportio/openport-go/utils"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// Extra root CA for the ACME directory endpoint, so the tests can run
// against pebble. Testing only.
const ACME_CA_FILE_ENV = "OPENPORT_ACME_CA_FILE"

// StartTLSTerminator serves the session's certificate on a loopback
// listener and raw-copies the decrypted bytes to the forwarded service.
// While TLS passthrough is active the tunnel dials this listener instead
// of the service (see Session.TunnelDialAddress).
//
// With --tls-cert/--tls-key the given certificate is served. Without them
// certificates come from Let's Encrypt: the TLS-ALPN-01 challenge arrives
// through the tunnel like any other TLS connection, so no port forwarding
// or DNS credentials are needed here either.
func (app *App) StartTLSTerminator(session *db.Session) error {
	config, err := terminatorTLSConfig(session)
	if err != nil {
		return err
	}
	// A plain listener, not tls.Listen: the tunnel prepends a PROXY protocol
	// header (nginx proxy_protocol) that must be stripped before the TLS
	// handshake.
	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	session.TlsProxyPort = rawListener.Addr().(*net.TCPAddr).Port
	log.Debugf("TLS terminator listening on 127.0.0.1:%d", session.TlsProxyPort)

	app.StopHooks.PushBack(func() { rawListener.Close() })

	localAddress := fmt.Sprintf("localhost:%d", session.LocalPort)
	go func() {
		for {
			raw, err := rawListener.Accept()
			if err != nil {
				log.Debugf("TLS terminator closed: %s", err)
				return
			}
			go terminate(raw, config, localAddress)
		}
	}()
	return nil
}

func terminate(raw net.Conn, config *tls.Config, localAddress string) {
	log.Debugf("TLS terminator: accepted a connection from the tunnel")
	raw.SetDeadline(time.Now().Add(30 * time.Second))
	conn, clientIP, err := stripProxyProtocol(raw)
	if err != nil {
		log.Debugf("could not read PROXY header: %s", err)
		raw.Close()
		return
	}
	if clientIP != "" {
		log.Debugf("TLS terminator: connection from %s", clientIP)
	}

	tlsConn := tls.Server(conn, config)
	// The handshake normally happens lazily on first read, but the ACME
	// challenge has to be detected before any bytes are proxied.
	if err := tlsConn.Handshake(); err != nil {
		log.Debugf("TLS handshake failed: %s", err)
		tlsConn.Close()
		return
	}
	log.Debugf("TLS terminator: handshake ok, proxying to %s", localAddress)
	tlsConn.SetDeadline(time.Time{})
	if tlsConn.ConnectionState().NegotiatedProtocol == acme.ALPNProto {
		// A validation probe from the certificate authority; the handshake
		// itself was the answer.
		log.Debug("Answered an ACME tls-alpn-01 validation request.")
		tlsConn.Close()
		return
	}

	target, err := net.Dial("tcp", localAddress)
	if err != nil {
		log.Warn(err)
		tlsConn.Close()
		return
	}
	// Both goroutines close both ends: whichever side disconnects first,
	// the copy in the other direction gets unblocked instead of sitting on
	// a keep-alive socket forever (one fd + goroutine per client visit).
	go func() {
		defer tlsConn.Close()
		defer target.Close()
		io.Copy(tlsConn, target)
	}()
	go func() {
		defer tlsConn.Close()
		defer target.Close()
		io.Copy(target, tlsConn)
	}()
}

// bufferedConn replays bytes already read into a bufio.Reader (past the PROXY
// header) before continuing to read from the underlying connection.
type bufferedConn struct {
	r *bufio.Reader
	net.Conn
}

func (c bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// stripProxyProtocol consumes an optional PROXY protocol v1 header from the
// tunnel (nginx sends v1, a single "PROXY ...\r\n" line) and returns the
// connection positioned at the first TLS byte, plus the real client IP when
// the header was present. A connection without the header is passed through
// unchanged, so a direct connection still works.
func stripProxyProtocol(conn net.Conn) (net.Conn, string, error) {
	r := bufio.NewReader(conn)
	prefix, err := r.Peek(6)
	if err != nil {
		return nil, "", err
	}
	if string(prefix) != "PROXY " {
		return bufferedConn{r: r, Conn: conn}, "", nil
	}
	line, err := r.ReadString('\n')
	if err != nil {
		return nil, "", err
	}
	// "PROXY TCP4 <src> <dst> <sport> <dport>\r\n"
	fields := strings.Fields(strings.TrimSpace(line))
	clientIP := ""
	if len(fields) >= 3 {
		clientIP = fields[2]
	}
	return bufferedConn{r: r, Conn: conn}, clientIP, nil
}

func terminatorTLSConfig(session *db.Session) (*tls.Config, error) {
	if session.TlsCertPath != "" {
		cert, err := tls.LoadX509KeyPair(session.TlsCertPath, session.TlsKeyPath)
		if err != nil {
			return nil, fmt.Errorf("could not load --tls-cert/--tls-key: %w", err)
		}
		return &tls.Config{
			Certificates: []tls.Certificate{cert},
			// The decrypted bytes are copied to the service as-is, so only
			// HTTP/1.1 may be negotiated: h2 frames would be garbage to it.
			NextProtos: []string{"http/1.1"},
			MinVersion: legacyMinTLSVersion, // #nosec G402 -- see legacyMinTLSVersion
		}, nil
	}

	manager := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
		Cache:  autocert.DirCache(path.Join(utils.OPENPORT_HOME, "certs")),
		// The forwarding address is only known once the first port request
		// has been answered, which is always before the first TLS
		// connection can arrive through the tunnel.
		HostPolicy: func(_ context.Context, host string) error {
			return checkTerminatorHost(session, host)
		},
	}
	if session.AcmeDirectory != "" {
		client, err := acmeClientForDirectory(session.AcmeDirectory)
		if err != nil {
			return nil, err
		}
		manager.Client = client
	}
	log.Info("Certificates are obtained from Let's Encrypt (terms: https://letsencrypt.org/repository/). Use --tls-cert/--tls-key to bring your own.")
	return &tls.Config{
		GetCertificate: manager.GetCertificate,
		NextProtos:     []string{"http/1.1", acme.ALPNProto},
		MinVersion:     legacyMinTLSVersion, // #nosec G402 -- see legacyMinTLSVersion
	}, nil
}

// The server-terminated forwards accept TLSv1 with CBC suites because
// deployed embedded devices still speak nothing newer; passthrough moves the
// termination here, so it must not silently cut those devices off.
const legacyMinTLSVersion = tls.VersionTLS10 // #nosec G402 -- deliberate parity with the server-side forwards

// checkTerminatorHost restricts autocert issuance to the user's own domain.
// The <xxxxx>.u.openport.io forwarding address (and its .xyz sibling) also
// routes to this terminator while the domain is latched, but issuing for it
// would draw from the openport.io per-domain Let's Encrypt rate limit that
// the servers' wildcard renewals depend on -- the very reason main.go
// refuses --tls-passthrough without --domain. A visitor using the
// forwarding address gets a failed handshake instead of a certificate.
func checkTerminatorHost(session *db.Session, host string) error {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if session.CustomDomain != "" && host == strings.ToLower(session.CustomDomain) {
		return nil
	}
	return fmt.Errorf("host %q is not this session's custom domain", host)
}

func acmeClientForDirectory(directory string) (*acme.Client, error) {
	client := &acme.Client{DirectoryURL: directory}
	if caFile := os.Getenv(ACME_CA_FILE_ENV); caFile != "" {
		pem, err := os.ReadFile(caFile) // #nosec G703 -- operator-set env var naming a local file, read as the same user; testing hook, not remote input
		if err != nil {
			return nil, fmt.Errorf("could not read %s: %w", ACME_CA_FILE_ENV, err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", caFile)
		}
		client.HTTPClient = &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		}
	}
	return client, nil
}
