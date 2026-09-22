package openport

import (
	"context"
	"net"
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

// applyCustomDomainMode sets the effective per-connection passthrough fields
// on app.Session before a port request. Call it at the top of each loop
// iteration.
func (app *App) applyCustomDomainMode() {
	if !app.wantPassthrough {
		return
	}

	effective := false
	switch {
	case app.wantDomain == "":
		// Passthrough without a custom domain (e.g. --tls-cert on the
		// openport address); nothing to wait for.
		effective = true
	case app.passthroughLatched:
		effective = true
	default:
		addr := app.Session.HttpForwardAddress
		if addr != "" && domainRoutable(app.wantDomain, addr) {
			effective = true
			app.passthroughLatched = true
			log.Infof("Custom domain %s points at %s; enabling end-to-end encryption.", app.wantDomain, addr)
		}
	}

	if effective {
		app.Session.TlsPassthrough = true
		app.Session.CustomDomain = app.wantDomain
		if app.tlsProxyPort == 0 {
			if err := app.StartTLSTerminator(&app.Session); err != nil {
				log.Fatalf("%s", err)
			}
			app.tlsProxyPort = app.Session.TlsProxyPort
		}
		app.Session.TlsProxyPort = app.tlsProxyPort
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
	addr := app.Session.HttpForwardAddress
	if addr == "" {
		return
	}
	app.mu.Lock()
	if app.domainGuidancePrinted {
		app.mu.Unlock()
		return
	}
	app.domainGuidancePrinted = true
	app.mu.Unlock()
	log.Infof("-----------------------------------------------------------------")
	log.Infof("To serve https://%s with end-to-end encryption, create this DNS record:", app.wantDomain)
	log.Infof("    %s.   CNAME   %s.", app.wantDomain, addr)
	log.Infof("No restart needed: this will switch over automatically within a")
	log.Infof("minute of the record propagating. Until then %s stays reachable", app.wantDomain)
	log.Infof("on https://%s .", addr)
	log.Infof("-----------------------------------------------------------------")
}

// ensureDomainPoller starts (once) a goroutine that ends the current
// connection when the custom domain becomes routable, so the loop upgrades.
func (app *App) ensureDomainPoller() {
	if app.domainPollerStarted || app.wantDomain == "" {
		return
	}
	app.domainPollerStarted = true
	go func() {
		for {
			// Print the CNAME instructions as soon as the address is known
			// (the main loop is blocked in the connected tunnel, so it
			// cannot do it while we wait here).
			app.maybePrintDomainGuidance()
			time.Sleep(domainPollInterval)
			if app.Stopped || app.passthroughLatched {
				return
			}
			addr := app.Session.HttpForwardAddress
			if addr != "" && domainRoutable(app.wantDomain, addr) {
				log.Infof("Detected %s -> %s. Reconnecting to enable end-to-end encryption...", app.wantDomain, addr)
				app.callInterrupt()
				return
			}
		}
	}()
}

func (app *App) setInterrupt(fn func()) {
	app.mu.Lock()
	app.interruptCurrent = fn
	app.mu.Unlock()
}

func (app *App) clearInterrupt() {
	app.mu.Lock()
	app.interruptCurrent = nil
	app.mu.Unlock()
}

func (app *App) callInterrupt() {
	app.mu.Lock()
	fn := app.interruptCurrent
	app.mu.Unlock()
	if fn != nil {
		fn()
	}
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
