package openport

import (
	"context"
	"net"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// Custom-domain TLS passthrough, with a hands-off setup.
//
// Terminating TLS on this machine means the public certificate is for the
// user's own domain, which must be CNAME'd to our forwarding address. That
// address is only known once we connect, so instead of failing when the
// CNAME is not there yet, we serve a normal http-forward, print the record
// to create, and watch DNS. The moment the domain resolves to us we end the
// current connection so the reconnect comes up in passthrough mode. A latch
// keeps us in passthrough across later reconnects so a transient DNS blip
// cannot flap us back.
//
// This lives in the client (not any one integration) so every user gets the
// same behaviour.

const domainPollInterval = 20 * time.Second

// tlsPassthroughHandler owns all the passthrough orchestration state: what
// the user asked for (want*), the per-process upgrade latch, the running
// terminator, and the hook the DNS poller uses to end the current
// connection. The zero value is a no-op for sessions without passthrough.
type tlsPassthroughHandler struct {
	wantPassthrough bool
	wantDomain      string

	// once true, stay in passthrough across reconnects. Deliberately not
	// persisted: a fresh process re-verifies DNS once, so a removed CNAME
	// degrades to the waiting mode instead of a fatal loop.
	latched bool

	// local port of the running TLS terminator, so mode toggles between
	// connections do not start a second listener (Session.TlsProxyPort is
	// the per-connection dial target, 0 while serving plain http-forward).
	terminatorPort int

	pollerStarted bool

	// mu guards the two fields shared with the poller goroutine.
	mu               sync.Mutex
	interruptCurrent func() // ends the current tunnel so the loop reconnects
	guidancePrinted  bool
}

func (h *tlsPassthroughHandler) setInterrupt(fn func()) {
	h.mu.Lock()
	h.interruptCurrent = fn
	h.mu.Unlock()
}

func (h *tlsPassthroughHandler) clearInterrupt() {
	h.mu.Lock()
	h.interruptCurrent = nil
	h.mu.Unlock()
}

func (h *tlsPassthroughHandler) callInterrupt() {
	h.mu.Lock()
	fn := h.interruptCurrent
	h.mu.Unlock()
	if fn != nil {
		fn()
	}
}

// applyCustomDomainMode sets the effective per-connection passthrough fields
// on app.Session before a port request. Call it at the top of each loop
// iteration.
func (app *App) applyCustomDomainMode() {
	h := &app.passthrough
	if !h.wantPassthrough {
		return
	}

	effective := false
	switch {
	case h.wantDomain == "":
		// Passthrough without a custom domain (--tls-cert on the openport
		// address); nothing to wait for.
		effective = true
	case h.latched:
		effective = true
	default:
		addr := app.Session.HttpForwardAddress
		if addr != "" && domainRoutable(h.wantDomain, addr) {
			effective = true
			h.latched = true
			log.Infof("Custom domain %s points at %s; enabling end-to-end encryption.", h.wantDomain, addr)
		}
	}

	if effective {
		app.Session.TlsPassthrough = true
		app.Session.CustomDomain = h.wantDomain
		if h.terminatorPort == 0 {
			if err := app.StartTLSTerminator(&app.Session); err != nil {
				log.Fatalf("%s", err)
			}
			h.terminatorPort = app.Session.TlsProxyPort
		}
		app.Session.TlsProxyPort = h.terminatorPort
		return
	}

	// Not routable yet: serve a normal http-forward and guide the user.
	app.Session.TlsPassthrough = false
	app.Session.CustomDomain = ""
	app.Session.TlsProxyPort = 0
	app.maybePrintDomainGuidance()
	app.ensureDomainPoller()
}

func (app *App) maybePrintDomainGuidance() {
	h := &app.passthrough
	addr := app.Session.HttpForwardAddress
	if addr == "" {
		return
	}
	h.mu.Lock()
	if h.guidancePrinted {
		h.mu.Unlock()
		return
	}
	h.guidancePrinted = true
	h.mu.Unlock()
	log.Infof("-----------------------------------------------------------------")
	log.Infof("To serve https://%s with end-to-end encryption, create a CNAME", h.wantDomain)
	log.Infof("record at your DNS provider. In most provider dashboards:")
	log.Infof("    Type:          CNAME")
	log.Infof("    Name/Host:     the subdomain part of %s", h.wantDomain)
	log.Infof("                   (some providers want the full name; no trailing dot)")
	log.Infof("    Value/Target:  %s", addr)
	log.Infof("    TTL:           any (300 is fine)")
	log.Infof("Or, as a raw zone file entry:")
	log.Infof("    %s.   CNAME   %s.", h.wantDomain, addr)
	log.Infof("No restart needed: this switches over automatically within a")
	log.Infof("minute of the record propagating. Until then, your service stays")
	log.Infof("reachable on https://%s .", addr)
	log.Infof("-----------------------------------------------------------------")
}

// ensureDomainPoller starts (once) a goroutine that ends the current
// connection when the custom domain becomes routable, so the loop upgrades.
func (app *App) ensureDomainPoller() {
	h := &app.passthrough
	if h.pollerStarted || h.wantDomain == "" {
		return
	}
	h.pollerStarted = true
	go func() {
		for {
			// Print the CNAME instructions as soon as the address is known
			// (the main loop is blocked in the connected tunnel, so it
			// cannot do it while we wait here).
			app.maybePrintDomainGuidance()
			time.Sleep(domainPollInterval)
			if app.Stopped || h.latched {
				return
			}
			addr := app.Session.HttpForwardAddress
			if addr != "" && domainRoutable(h.wantDomain, addr) {
				log.Infof("Detected %s -> %s. Reconnecting to enable end-to-end encryption...", h.wantDomain, addr)
				h.callInterrupt()
				return
			}
		}
	}()
}

// domainRoutable reports whether domain currently resolves to the same host
// as address (i.e. the user's CNAME is in place). Comparing resolved IPs
// rather than the CNAME target means the .io/.xyz spellings of the
// forwarding address, which share an IP, both count.
func domainRoutable(domain, address string) bool {
	domainIPs := lookupIPSet(domain)
	if len(domainIPs) == 0 {
		return false
	}
	for ip := range lookupIPSet(address) {
		if domainIPs[ip] {
			return true
		}
	}
	return false
}

// probeResolver queries a public resolver directly instead of the local one.
// The readiness poll runs before the user has created their CNAME, and a
// local resolver (e.g. systemd-resolved) would cache that NXDOMAIN for the
// zone's SOA minimum -- often hours -- so the poll would keep seeing the
// stale negative long after the record exists. Public resolvers cap negative
// caching to minutes, so the switch happens promptly once the CNAME is up.
var probeResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		d := net.Dialer{Timeout: 5 * time.Second}
		if c, err := d.DialContext(ctx, network, "1.1.1.1:53"); err == nil {
			return c, nil
		}
		return d.DialContext(ctx, network, "8.8.8.8:53")
	},
}

func lookupIPSet(host string) map[string]bool {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	ips, err := probeResolver.LookupHost(ctx, host)
	if err != nil {
		// A network that blocks outbound DNS to public resolvers still has
		// the local one; fall back so the check works there too.
		ips, err = net.LookupHost(host)
		if err != nil {
			return nil
		}
	}
	set := make(map[string]bool, len(ips))
	for _, ip := range ips {
		set[ip] = true
	}
	return set
}
