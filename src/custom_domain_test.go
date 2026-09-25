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

func TestFreshSessionGuidanceUsesTheAddressFromTheFirstResponse(t *testing.T) {
	app := passthroughApp(unroutableDomain)
	defer app.Stop(0)
	// A fresh session has no forwarding address before the first port
	// response, and applyCustomDomainMode runs before the request.
	app.Session.HttpForwardAddress = ""
	app.applyCustomDomainMode()

	h := &app.passthrough
	app.maybePrintDomainGuidance()
	h.mu.Lock()
	printedBeforeAddress := h.guidancePrinted
	h.mu.Unlock()
	assert.False(t, printedBeforeAddress, "no guidance can be printed before the address is known")

	// The port response arrives while the connection stays up, so the
	// poller (not a later applyCustomDomainMode) must see the address.
	h.noteForwardAddress(forwardAddress)
	app.maybePrintDomainGuidance()
	h.mu.Lock()
	printed := h.guidancePrinted
	seenAddress := h.forwardAddress
	h.mu.Unlock()
	assert.True(t, printed, "the CNAME guidance must be printed once the first response names the address")
	assert.Equal(t, forwardAddress, seenAddress, "the poller's routability check needs the address")
}

func TestDnsProbeOverrideParsing(t *testing.T) {
	assert.Len(t, probeResolverList(), len(probeResolvers))

	t.Setenv(DNS_PROBE_ENV, "127.0.0.1:5301, 127.0.0.1:5302")
	assert.Len(t, probeResolverList(), 2)

	// Junk falls back to the real list rather than leaving no resolvers.
	t.Setenv(DNS_PROBE_ENV, " , ")
	assert.Len(t, probeResolverList(), len(probeResolvers))
}

func TestDnsProbeOverrideReroutesTheReadinessPoll(t *testing.T) {
	// A fake resolver that answers every A query with the same address
	// makes any domain "routable" to any forward address; the public
	// resolvers would answer NXDOMAIN for both .invalid names.
	t.Setenv(DNS_PROBE_ENV, startFakeDNSServer(t, net.IPv4(198, 51, 100, 7)))
	assert.True(t, domainRoutable(unroutableDomain, "forward.address.invalid"))
}

// startFakeDNSServer runs a minimal UDP DNS responder for the duration of
// the test: every A question gets one answer with the given address, every
// other question an empty NOERROR. Returns its listen address.
func startFakeDNSServer(t *testing.T, answer net.IP) string {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 512)
		for {
			n, client, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			query := buf[:n]
			if n < 12 {
				continue
			}
			// Find the end of the question name to read the qtype.
			i := 12
			for i < n && query[i] != 0 {
				i += int(query[i]) + 1
			}
			if i+5 > n {
				continue
			}
			qtype := uint16(query[i+1])<<8 | uint16(query[i+2])
			question := query[12 : i+5]

			response := []byte{query[0], query[1], 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0}
			response = append(response, question...)
			if qtype == 1 { // A
				response[7] = 1 // ANCOUNT
				response = append(response,
					0xC0, 0x0C, // name: pointer to the question
					0, 1, 0, 1, // type A, class IN
					0, 0, 0, 60, // TTL
					0, 4) // RDLENGTH
				response = append(response, answer.To4()...)
			}
			_, _ = conn.WriteToUDP(response, client)
		}
	}()
	return conn.LocalAddr().String()
}
