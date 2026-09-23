package openport

import (
	"context"
	"errors"
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
	// Written once before the connection loop starts, read-only after.
	wantPassthrough bool
	wantDomain      string

	// local port of the running TLS terminator, so mode toggles between
	// connections do not start a second listener (Session.TlsProxyPort is
	// the per-connection dial target, 0 while serving plain http-forward).
	// Main loop only.
	terminatorPort int

	// mu guards every field below: they are shared with the poller goroutine.
	mu sync.Mutex

	// once true, stay in passthrough across reconnects. Deliberately not
	// persisted: a fresh process re-verifies DNS once, so a removed CNAME
	// degrades to the waiting mode instead of a fatal loop.
	latched bool

	// snapshot of Session.HttpForwardAddress for the poller; the Session
	// itself belongs to the main loop.
	forwardAddress string

	pollerRunning    bool
	interruptCurrent func()        // ends the current tunnel so the loop reconnects
	done             chan struct{} // closed when the app stops
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

	h.mu.Lock()
	h.forwardAddress = app.Session.HttpForwardAddress
	latched := h.latched
	h.mu.Unlock()

	useDomain := false
	switch {
	case h.wantDomain == "":
		// Passthrough without a custom domain (--tls-cert or --local-tls on
		// the openport address); nothing to wait for.
	case latched:
		useDomain = true
	default:
		addr := app.Session.HttpForwardAddress
		if addr != "" && domainRoutable(h.wantDomain, addr) {
			useDomain = true
			h.mu.Lock()
			h.latched = true
			h.mu.Unlock()
			log.Infof("Custom domain %s points at %s; enabling end-to-end encryption.", h.wantDomain, addr)
		}
	}

	waiting := h.wantDomain != "" && !useDomain
	if waiting && !app.Session.LocalTLS {
		// Terminator mode cannot get a certificate before the domain routes
		// here, so serve a normal http-forward while we wait.
		app.Session.TlsPassthrough = false
		app.Session.CustomDomain = ""
		app.Session.TlsProxyPort = 0
		app.maybePrintDomainGuidance()
		app.ensureDomainPoller()
		return
	}
	// Local-TLS mode keeps passthrough up even while waiting: the local
	// service owns the certificate, and the plain http-forward fallback
	// would feed it plaintext. Until the CNAME routes, the forward works on
	// the standard address (with the local certificate's name mismatch).

	app.Session.TlsPassthrough = true
	app.Session.CustomDomain = ""
	if useDomain {
		app.Session.CustomDomain = h.wantDomain
	}
	if h.terminatorPort == 0 {
		var err error
		if app.Session.LocalTLS {
			err = app.StartTLSRelay(&app.Session)
		} else {
			err = app.StartTLSTerminator(&app.Session)
		}
		if err != nil {
			log.Fatalf("%s", err)
		}
		h.terminatorPort = app.Session.TlsProxyPort
	}
	app.Session.TlsProxyPort = h.terminatorPort
	if waiting {
		app.maybePrintDomainGuidance()
		app.ensureDomainPoller()
	}
}

func (app *App) maybePrintDomainGuidance() {
	h := &app.passthrough
	h.mu.Lock()
	addr := h.forwardAddress
	if addr == "" || h.guidancePrinted {
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

// ensureDomainPoller starts a goroutine that ends the current connection
// when the custom domain becomes routable, so the loop upgrades. The poller
// exits after firing (or on latch/stop); it is restarted here if a later
// loop iteration is back in waiting mode -- e.g. the interrupt fired between
// connections, or a reconnect's DNS check transiently failed -- so a session
// that can stay up for weeks is never stranded in server-terminated mode.
func (app *App) ensureDomainPoller() {
	h := &app.passthrough
	if h.wantDomain == "" {
		return
	}
	h.mu.Lock()
	if h.pollerRunning {
		h.mu.Unlock()
		return
	}
	h.pollerRunning = true
	if h.done == nil {
		h.done = make(chan struct{})
		app.StopHooks.PushBack(func() { close(h.done) })
	}
	h.mu.Unlock()
	go func() {
		defer func() {
			h.mu.Lock()
			h.pollerRunning = false
			h.mu.Unlock()
		}()
		for {
			// Print the CNAME instructions as soon as the address is known
			// (the main loop is blocked in the connected tunnel, so it
			// cannot do it while we wait here).
			app.maybePrintDomainGuidance()
			select {
			case <-h.done:
				return
			case <-time.After(domainPollInterval):
			}
			h.mu.Lock()
			latched := h.latched
			addr := h.forwardAddress
			h.mu.Unlock()
			if latched {
				return
			}
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

// The probe resolvers query public resolvers directly instead of the local
// one. The readiness poll runs before the user has created their CNAME, and
// a local resolver (e.g. systemd-resolved) would cache that NXDOMAIN for the
// zone's SOA minimum -- often hours -- so the poll would keep seeing the
// stale negative long after the record exists. Public resolvers cap negative
// caching to minutes, so the switch happens promptly once the CNAME is up.
//
// They are tried in order, each with its own timeout: a UDP dial "succeeds"
// even on a network that blackholes the resolver, so a dial-level fallback
// would never fire. The local resolver comes last, for networks that block
// outbound DNS to public resolvers entirely.
var probeResolvers = []*net.Resolver{
	publicResolver("1.1.1.1:53"),
	publicResolver("8.8.8.8:53"),
	net.DefaultResolver,
}

func publicResolver(address string) *net.Resolver {
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, address)
		},
	}
}

func lookupIPSet(host string) map[string]bool {
	for _, resolver := range probeResolvers {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		ips, err := resolver.LookupHost(ctx, host)
		cancel()
		if err == nil {
			set := make(map[string]bool, len(ips))
			for _, ip := range ips {
				set[ip] = true
			}
			return set
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// An authoritative "no such name": the CNAME is simply not
			// there yet. Asking the next resolver would only slow the poll.
			return nil
		}
	}
	return nil
}
