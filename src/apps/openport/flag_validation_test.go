package main

import (
	"path/filepath"
	"testing"

	"github.com/openportio/openport-go"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// log.Fatal normally os.Exits the process; the tests swap the exit for a
// panic so run() unwinds back here and the message can be asserted on.
type fatalExit struct{}

// captureHook records the fatal entry (the vendor tree does not carry
// logrus/hooks/test, and this is all we need from it).
type captureHook struct {
	lastFatal string
}

func (h *captureHook) Levels() []log.Level { return []log.Level{log.FatalLevel} }

func (h *captureHook) Fire(entry *log.Entry) error {
	h.lastFatal = entry.Message
	return nil
}

func runExpectingFatal(t *testing.T, args ...string) string {
	t.Helper()
	logger := log.StandardLogger()
	hook := &captureHook{}
	logger.AddHook(hook)
	oldExit := logger.ExitFunc
	logger.ExitFunc = func(int) { panic(fatalExit{}) }
	defer func() { logger.ExitFunc = oldExit }()

	app := openport.CreateApp()
	defer app.Stop(0)

	sawFatal := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(fatalExit); !ok {
					panic(r)
				}
				sawFatal = true
			}
		}()
		run(app, append([]string{OPENPORT_EXE}, args...))
	}()
	if !sawFatal {
		t.Fatalf("expected a fatal flag-validation error for %v", args)
	}
	if hook.lastFatal == "" {
		t.Fatal("log.Fatal fired but no entry was captured")
	}
	return hook.lastFatal
}

func testDb(t *testing.T) string {
	return filepath.Join(t.TempDir(), "flags.db")
}

func TestLocalTLSRequiresTlsPassthrough(t *testing.T) {
	msg := runExpectingFatal(t, "8080",
		"--local-tls",
		"--database", testDb(t),
	)
	assert.Contains(t, msg, "--local-tls requires --tls-passthrough")
}

func TestLocalTLSRefusesTlsCertAndKey(t *testing.T) {
	msg := runExpectingFatal(t, "8080",
		"--tls-passthrough", "--local-tls",
		"--tls-cert", "cert.pem", "--tls-key", "key.pem",
		"--database", testDb(t),
	)
	assert.Contains(t, msg, "drop --tls-cert/--tls-key")
}

func TestLocalProxyProtocolRequiresLocalTLS(t *testing.T) {
	msg := runExpectingFatal(t, "8080",
		"--local-proxy-protocol",
		"--database", testDb(t),
	)
	assert.Contains(t, msg, "--local-proxy-protocol requires --local-tls")
}

func TestBareTlsPassthroughStillRefused(t *testing.T) {
	// Guards the Let's Encrypt rate-limit reasoning: relaxing the check to
	// admit --local-tls must not have opened the bare autocert case.
	msg := runExpectingFatal(t, "8080",
		"--tls-passthrough",
		"--database", testDb(t),
	)
	assert.Contains(t, msg, "--tls-passthrough needs one of --domain, --tls-cert or --local-tls")
}
