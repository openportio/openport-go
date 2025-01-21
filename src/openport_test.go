package openport

import (
	"github.com/openportio/openport-go/utils"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
)

func TestApp_getRestartCommand(t *testing.T) {
	app := CreateApp()
	dbFile := "test-files/tmp/openport-1.3.0.db"
	os.Remove(dbFile)
	utils.FailOnError(CopyFile("test-files/openport-1.3.0.db", dbFile), "Could not copy file")
	app.DbHandler.SetPath(dbFile)
	session, err := app.DbHandler.GetSessionsToRestart()
	utils.FailOnError(err, "Could not get sessions to restart")
	restartCommand := app.getRestartCommand(session[0], DEFAULT_SERVER)
	assert.Equal(t, strings.Split("44 --database test-files/tmp/openport-1.3.0.db --automatic-restart", " "), restartCommand)
}
