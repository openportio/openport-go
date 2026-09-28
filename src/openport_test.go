package openport

import (
	db "github.com/openportio/openport-go/database"
	"github.com/openportio/openport-go/utils"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
	"time"
)

func TestApp_getRestartCommand(t *testing.T) {
	app := CreateApp()
	dbFile := "test-files/tmp/openport-1.3.0.db"
	_ = os.Remove(dbFile)
	utils.FailOnError(CopyFile("test-files/openport-1.3.0.db", dbFile), "Could not copy file")
	app.DbHandler.SetPath(dbFile)
	session, err := app.DbHandler.GetSessionsToRestart()
	utils.FailOnError(err, "Could not get sessions to restart")
	restartCommand := app.getRestartCommand(session[0], DEFAULT_SERVER)
	assert.Equal(t, strings.Split("44 --database test-files/tmp/openport-1.3.0.db --automatic-restart", " "), restartCommand)
}

// The pickled restart commands come from a local DB written by the old Python
// client. A corrupt or hand-tampered entry must degrade to the session-content
// fallback instead of panicking the client.
func TestApp_getRestartCommand_badPickles(t *testing.T) {
	app := CreateApp()
	app.DbHandler.SetPath("test-files/tmp/does-not-matter.db")
	fallback := []string{"44", "--database", "test-files/tmp/does-not-matter.db", "--automatic-restart"}

	testCases := []struct {
		name           string
		restartCommand string
		expected       []string
	}{
		{"corrupt pickle", "\x80\x02garbage", fallback},
		{"pickled int", "\x80\x02K\x01.", fallback},
		{"pickled list of ints", "\x80\x02]K\x01a.", fallback},
		{"pickled empty list", "\x80\x02].", fallback},
		{"pickled command list", "\x80\x02]U\x08openportaU\x0244a.", fallback},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			session := db.Session{LocalPort: 44, RestartCommand: testCase.restartCommand}
			assert.Equal(t, testCase.expected, app.getRestartCommand(session, DEFAULT_SERVER))
		})
	}
}

func waitForConnectedState(t *testing.T, app *App, connected bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for app.ConnectedState.IsConnected() != connected {
		if time.Now().After(deadline) {
			t.Fatalf("state machine did not reach connected=%t", connected)
		}
		time.Sleep(time.Millisecond)
	}
}

// A reconnect that dies right away can leave its MarkConnected event still
// queued in the buffered Connected channel when MarkDisconnected runs. The
// stale event must not flip the state machine back to connected, or
// --exit-on-failure-timeout never fires and the client hangs instead of
// exiting (AppTestWS.test_exits_on_disconnect_if_connection_timeout_set,
// main pipeline 1192).
func TestExitOnFailureTimeout_reconnectDropRace(t *testing.T) {
	app := CreateApp()
	app.ExitOnFailureTimeout = 1
	go app.ConnectedState.DoState()

	app.MarkConnected()
	waitForConnectedState(t, app, true)

	app.MarkDisconnected()
	waitForConnectedState(t, app, false)

	// Reconnect and immediate drop, before the state machine consumes the
	// connected event.
	app.MarkConnected()
	app.MarkDisconnected()

	select {
	case code := <-app.ExitCode:
		assert.Equal(t, EXIT_CODE_NO_CONNECTION, code)
	case <-time.After(5 * time.Second):
		t.Fatal("app did not exit while the connection stayed down")
	}
}
