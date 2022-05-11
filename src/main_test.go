package main

import (
	log "github.com/sirupsen/logrus"
	"os"
	"strconv"
	"testing"
	"time"
)

const TEST_SERVER = "https://test2.openport.io"
const OPENPORT_EXE = "/Users/jan/swprojects/openport-go-client/src/openport"

func TestReverseTunnel(t *testing.T) {
	dbFile := "tmp/TestReverseTunnel.db"
	port := getFreePort(t)
	app := createApp()
	defer app.Stop()

	go app.run([]string{OPENPORT_EXE, "--local-port", strconv.Itoa(port), "--server", TEST_SERVER, "--verbose", "--database", dbFile})
	waitForApp(t, &app)
	ClickLink(t, app.Session.OpenPortForIpLink)
	CheckTcpForward(t, port, app.Session.SshServer, app.Session.RemotePort)
}

func TestSaveForwardTunnel(t *testing.T) {
	dbFile := "tmp/TestSaveForwardTunnel.db"
	err := os.Remove(dbFile)
	if err != nil {
		log.Warn(err)
	}

	killAllApp := createApp()
	defer killAllApp.run([]string{OPENPORT_EXE, "kill-all", "--database", dbFile})

	port := getFreePort(t)

	reserveApp := createApp()
	defer reserveApp.Stop()

	go reserveApp.run([]string{
		OPENPORT_EXE,
		"--local-port",
		strconv.Itoa(port),
		"--server", TEST_SERVER,
		"--verbose",
		"--database", dbFile,
		"--restart-on-reboot",
	})
	waitForApp(t, &reserveApp)
	ClickLink(t, reserveApp.Session.OpenPortForIpLink)
	CheckTcpForward(t, port, reserveApp.Session.SshServer, reserveApp.Session.RemotePort)

	forwardPort := getFreePort(t)

	forwardApp := createApp()
	defer forwardApp.Stop()
	go forwardApp.run([]string{
		OPENPORT_EXE,
		"forward",
		"--server", TEST_SERVER,
		"--database", dbFile,
		"--local-port", strconv.Itoa(forwardPort),
		"--verbose",
		"--remote-port", strconv.Itoa(reserveApp.Session.RemotePort),
		"--restart-on-reboot",
	})

	waitForApp(t, &forwardApp)
	time.Sleep(1 * time.Second)

	CheckTcpForward(t, port, "127.0.0.1", forwardPort)
	activeSessions, err := forwardApp.dbHandler.GetAllActive()
	failIfError(t, err)
	assertEqual(t, 2, len(activeSessions))

	forwardApp.Stop()

	CheckTcpForwardFails(t, port, "127.0.0.1", forwardPort)
	activeSessions, err = forwardApp.dbHandler.GetAllActive()
	failIfError(t, err)
	assertEqual(t, 1, len(activeSessions))

	sessionsToRestart, err := forwardApp.dbHandler.GetSessionsToRestart()
	failIfError(t, err)
	assertEqual(t, 2, len(sessionsToRestart))

	// Restarting app
	restartShares := func() {
		restartApp := createApp()
		restartApp.run([]string{
			OPENPORT_EXE,
			"restart-sessions",
			"--database", dbFile,
		})
	}
	timeoutFunction(t, restartShares, 2*time.Second)

	time.Sleep(1 * time.Second)
	activeSessions, err = forwardApp.dbHandler.GetAllActive()
	failIfError(t, err)
	assertEqual(t, 2, len(activeSessions))

	CheckTcpForward(t, port, "127.0.0.1", forwardPort)
}
