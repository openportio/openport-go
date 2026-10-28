//go:build !windows

package openport

import (
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func sendSignalToSelf(t *testing.T, sig syscall.Signal) {
	t.Helper()
	assert.NoError(t, syscall.Kill(os.Getpid(), sig))
}

// While the tunnel is still connecting (device offline, server unreachable)
// no command runs yet, so ctrl-c must abort the session like it does
// without exec.
func TestExecSignals_interruptBeforeCommandStarts(t *testing.T) {
	defer signal.Reset(syscall.SIGINT, syscall.SIGTERM)

	app := createExecApp("true")
	handleExecSignals(app)
	sendSignalToSelf(t, syscall.SIGINT)
	assert.Equal(t, EXIT_CODE_INTERRUPTED, waitForExitCode(t, app))
}

// Once the command runs, ctrl-c belongs to it: the session ends when the
// command decides to exit, with the command's exit code.
func TestExecSignals_interruptIgnoredWhileCommandRuns(t *testing.T) {
	defer signal.Reset(syscall.SIGINT, syscall.SIGTERM)
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	stop := filepath.Join(dir, "stop")

	app := createExecApp("touch " + started + "; while [ ! -e " + stop + " ]; do sleep 0.05; done; exit 3")
	handleExecSignals(app)
	app.StartExecOnce()
	waitForFile(t, started)
	// The real child is in the foreground process group and gets its own
	// SIGINT from the terminal; here only the app is signalled.
	sendSignalToSelf(t, syscall.SIGINT)
	select {
	case exitCode := <-app.ExitCode:
		t.Fatalf("SIGINT stopped the app (exit code %d) while the command was running", exitCode)
	case <-time.After(300 * time.Millisecond):
	}
	assert.NoError(t, os.WriteFile(stop, nil, 0600))
	assert.Equal(t, 3, waitForExitCode(t, app))
}

// SIGTERM tears the session down and kills the command with it.
func TestExecSignals_terminateKillsCommand(t *testing.T) {
	defer signal.Reset(syscall.SIGINT, syscall.SIGTERM)
	started := filepath.Join(t.TempDir(), "started")

	app := createExecApp("touch " + started + "; exec sleep 30")
	handleExecSignals(app)
	app.StartExecOnce()
	waitForFile(t, started)
	time.Sleep(100 * time.Millisecond) // let the shell exec into sleep
	app.Exec.mu.Lock()
	cmd := app.Exec.cmd
	app.Exec.mu.Unlock()

	sendSignalToSelf(t, syscall.SIGTERM)
	assert.Equal(t, EXIT_CODE_INTERRUPTED, waitForExitCode(t, app))
	assert.Eventually(t, func() bool {
		// Fails once the killed command has been reaped.
		return cmd.Process.Signal(syscall.Signal(0)) != nil
	}, 5*time.Second, 50*time.Millisecond, "the command was not killed")
}
