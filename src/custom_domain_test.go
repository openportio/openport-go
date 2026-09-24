package openport

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

// A name under the reserved .invalid TLD can never resolve, which is
// exactly the "user has not created the CNAME yet" state.
const unroutableDomain = "cname-not-created-yet.invalid"

const forwardAddress = "test123.u.openport.io"

func passthroughApp(wantDomain string) *App {
	app := CreateApp()
	app.passthrough.wantPassthrough = true
	app.passthrough.wantDomain = wantDomain
	app.Session.HttpForwardAddress = forwardAddress
	return app
}

func TestWaitingCustomDomainFallsBackToHttpForward(t *testing.T) {
	app := passthroughApp(unroutableDomain)
	defer app.Stop(0)
	app.Session.LocalTLS = false

	app.applyCustomDomainMode()

	// Terminator mode cannot get a certificate before the CNAME routes
	// here, so the session must come up as a plain http-forward.
	assert.False(t, app.Session.TlsPassthrough)
	assert.Equal(t, "", app.Session.CustomDomain)
	assert.Equal(t, 0, app.Session.TlsProxyPort)
}

func TestWaitingCustomDomainWithLocalTLSKeepsPassthroughUp(t *testing.T) {
	app := passthroughApp(unroutableDomain)
	defer app.Stop(0)
	app.Session.LocalTLS = true

	app.applyCustomDomainMode()

	// Still waiting for the CNAME, but the session must stay in
	// passthrough: the plain http-forward fallback would feed plaintext to
	// the HTTPS-only local service.
	assert.True(t, app.Session.TlsPassthrough)
	assert.Equal(t, "", app.Session.CustomDomain, "the domain must not be claimed before it routes")
	if assert.NotZero(t, app.Session.TlsProxyPort, "the TLS relay should be listening") {
		conn, err := net.DialTimeout("tcp",
			fmt.Sprintf("127.0.0.1:%d", app.Session.TlsProxyPort), time.Second)
		if assert.NoError(t, err, "the relay port should accept connections") {
			conn.Close()
		}
	}

	// The poller must keep watching so the session still upgrades to the
	// custom domain once the CNAME appears.
	app.passthrough.mu.Lock()
	pollerRunning := app.passthrough.pollerRunning
	app.passthrough.mu.Unlock()
	assert.True(t, pollerRunning, "the DNS poller should be running while waiting")

	// A reconnect re-applies the mode; the relay must be reused, not doubled.
	firstPort := app.Session.TlsProxyPort
	app.applyCustomDomainMode()
	assert.Equal(t, firstPort, app.Session.TlsProxyPort)
}

func TestLatchedCustomDomainServesTheDomain(t *testing.T) {
	app := passthroughApp(unroutableDomain)
	defer app.Stop(0)
	app.Session.LocalTLS = true
	app.passthrough.latched = true

	app.applyCustomDomainMode()

	// Once latched (the CNAME was seen routable), the domain is claimed on
	// the session without re-checking DNS, so a transient blip cannot flap
	// the session back to the waiting mode.
	assert.True(t, app.Session.TlsPassthrough)
	assert.Equal(t, unroutableDomain, app.Session.CustomDomain)
	assert.NotZero(t, app.Session.TlsProxyPort)
}
