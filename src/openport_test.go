package openport

import (
	db "github.com/openportio/openport-go/database"
	"github.com/openportio/openport-go/utils"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
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
