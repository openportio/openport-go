package openport

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	db "github.com/openportio/openport-go/database"
	"github.com/stretchr/testify/assert"
)

func TestSubstitutePort(t *testing.T) {
	assert.Equal(t, "ssh root@localhost -p 1234", substitutePort("ssh root@localhost -p $port", 1234))
	assert.Equal(t, "curl http://localhost:1234/x", substitutePort("curl http://localhost:${port}/x", 1234))
	assert.Equal(t, "1234 1234", substitutePort("${port} $port", 1234))
	assert.Equal(t, "no placeholders", substitutePort("no placeholders", 1234))
}

func createExecApp(command ...string) *App {
	app := CreateApp()
	app.DbHandler = &db.DummyDBHandler{}
	app.Session = db.Session{LocalPort: 4321}
	app.SetExecCommand(command)
	return app
}

func waitForExitCode(t *testing.T, app *App) int {
	t.Helper()
	select {
	case exitCode := <-app.ExitCode:
		return exitCode
	case <-time.After(10 * time.Second):
		t.Fatal("the app did not stop")
		return -1
	}
}

func skipOnWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/sh")
	}
}

// The command's exit code becomes the app's exit code, and "$port" reaches
// the command as the tunnel's local port, both through a shell command line
// and as separate arguments.
func TestExec_exitCodeAndPortSubstitution(t *testing.T) {
	skipOnWindows(t)
	out := filepath.Join(t.TempDir(), "port")

	app := createExecApp("echo $port > " + out + "; exit 5")
	app.StartExecOnce()
	assert.Equal(t, 5, waitForExitCode(t, app))
	content, err := os.ReadFile(out)
	assert.NoError(t, err)
	assert.Equal(t, "4321\n", string(content))

	app = createExecApp("/bin/sh", "-c", "test \"$1\" = 4321", "sh", "${port}")
	app.StartExecOnce()
	assert.Equal(t, 0, waitForExitCode(t, app))
}

// A reconnecting tunnel calls StartExecOnce again; the command must only
// ever run once.
func TestExec_startsOnlyOnce(t *testing.T) {
	skipOnWindows(t)
	counter := filepath.Join(t.TempDir(), "counter")
	stop := filepath.Join(t.TempDir(), "stop")

	app := createExecApp("echo x >> " + counter + "; while [ ! -e " + stop + " ]; do sleep 0.05; done")
	for i := 0; i < 3; i++ {
		app.StartExecOnce()
	}
	time.Sleep(300 * time.Millisecond)
	app.StartExecOnce()
	assert.NoError(t, os.WriteFile(stop, nil, 0600))
	assert.Equal(t, 0, waitForExitCode(t, app))

	content, err := os.ReadFile(counter)
	assert.NoError(t, err)
	assert.Equal(t, "x\n", string(content))
}

func TestExec_commandThatCannotStart(t *testing.T) {
	app := createExecApp("/does/not/exist")
	app.StartExecOnce()
	assert.Equal(t, EXIT_CODE_INVALID_ARGUMENT, waitForExitCode(t, app))
}

func TestExec_noCommandIsANoop(t *testing.T) {
	app := CreateApp()
	app.StartExecOnce() // no exec handler at all
	app.SetExecCommand(nil)
	app.StartExecOnce()
	select {
	case exitCode := <-app.ExitCode:
		t.Fatalf("unexpected stop with exit code %d", exitCode)
	case <-time.After(200 * time.Millisecond):
	}
}

func waitForFile(t *testing.T, path string) {
	t.Helper()
	assert.Eventually(t, func() bool {
		_, err := os.Stat(path)
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "%s never appeared", path)
}
