package main

import (
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"os"
	"strconv"
	"testing"
	"time"
)

const TEST_SERVER = "https://test2.openport.io"

var OPENPORT_EXE = defaultEnv("OPENPORT_EXE", "/Users/jan/swprojects/openport-go-client/src/openport")

func TestReverseTunnel(t *testing.T) {
	dbFile := "tmp/TestReverseTunnel.db"
	port := getFreePort(t)
	app := createApp()
	defer app.Stop(0)

	go app.run([]string{
		OPENPORT_EXE,
		strconv.Itoa(port),
		"--server", TEST_SERVER,
		"--verbose",
		"--database", dbFile,
		"--exit-on-failure-timeout", "10",
	})
	waitForApp(t, app)
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
	defer reserveApp.Stop(0)

	go reserveApp.run([]string{
		OPENPORT_EXE,
		strconv.Itoa(port),
		"--server", TEST_SERVER,
		"--verbose",
		"--database", dbFile,
		"--restart-on-reboot",
	})
	waitForApp(t, reserveApp)
	ClickLink(t, reserveApp.Session.OpenPortForIpLink)
	CheckTcpForward(t, port, reserveApp.Session.SshServer, reserveApp.Session.RemotePort)

	forwardPort := getFreePort(t)

	forwardApp := createApp()
	defer forwardApp.Stop(0)
	go forwardApp.run([]string{
		OPENPORT_EXE,
		"forward",
		"--server", TEST_SERVER,
		"--database", dbFile,
		"--local-port", strconv.Itoa(forwardPort),
		"--exit-on-failure-timeout", "10",
		"--verbose",
		"--remote-port", strconv.Itoa(reserveApp.Session.RemotePort),
		"--restart-on-reboot",
	})

	waitForApp(t, forwardApp)
	time.Sleep(1 * time.Second)

	CheckTcpForward(t, port, "127.0.0.1", forwardPort)
	activeSessions, err := forwardApp.dbHandler.GetAllActive()
	failIfError(t, err)
	assertEqual(t, 2, len(activeSessions))

	forwardApp.Stop(0)
	getExitCode := func() string {
		return strconv.Itoa(<-forwardApp.exitCode)
	}
	assert.Equal(t, "0", timeoutFunction(t, getExitCode, 3*time.Second))
	time.Sleep(500 * time.Millisecond)

	CheckTcpForwardFails(t, port, "127.0.0.1", forwardPort)
	activeSessions, err = forwardApp.dbHandler.GetAllActive()
	failIfError(t, err)
	assertEqual(t, 1, len(activeSessions))

	sessionsToRestart, err := forwardApp.dbHandler.GetSessionsToRestart()
	failIfError(t, err)
	assertEqual(t, 2, len(sessionsToRestart))

	// Restarting app
	restartShares := func() string {
		restartApp := createApp()
		restartApp.run([]string{
			OPENPORT_EXE,
			"restart-sessions",
			"--database", dbFile,
		})
		return "ok"
	}
	timeoutFunction(t, restartShares, 2*time.Second)

	time.Sleep(1 * time.Second)
	activeSessions, err = forwardApp.dbHandler.GetAllActive()
	failIfError(t, err)
	assertEqual(t, 2, len(activeSessions))

	CheckTcpForward(t, port, "127.0.0.1", forwardPort)
}

func TestConnectionTimeout(t *testing.T) {
	dbFile := "tmp/TestConnectionTimeout.db"
	err := os.Remove(dbFile)
	if err != nil {
		log.Warn(err)
	}

	killAllApp := createApp()
	defer killAllApp.run([]string{OPENPORT_EXE, "kill-all", "--database", dbFile})

	port := getFreePort(t)

	reserveApp := createApp()
	defer reserveApp.Stop(0)

	start := time.Now()
	go reserveApp.run([]string{
		OPENPORT_EXE,
		"--exit-on-failure-timeout", "1",
		strconv.Itoa(port),
		"--server", "https://non-existant.example.com",
		"--verbose",
		"--database", dbFile,
	})

	waitForExitCode := func() string {
		return strconv.Itoa(<-reserveApp.exitCode)
	}
	assertEqual(t, strconv.Itoa(EXIT_CODE_NO_CONNECTION), timeoutFunction(t, waitForExitCode, 2*time.Second))

	assert.True(t, time.Now().After(start.Add(500*time.Millisecond)), "App exited to quickly")
	// TODO: does this still work after a restart

	//// Restarting app
	//restartShares := func() string {
	//	restartApp := createApp()
	//	restartApp.run([]string{
	//		OPENPORT_EXE,
	//		"restart-sessions",
	//		"--database", dbFile,
	//	})
	//	return "ok"
	//}
	//timeoutFunction(t, restartShares, 2*time.Second)
	//
	//time.Sleep(500 * time.Millisecond)
	//waitForApp(t, &reserveApp)
}

func TestConnectionTimeoutWithSuccessfulConnection(t *testing.T) {
	dbFile := "tmp/TestConnectionTimeoutWithSuccessfulConnection.db"
	err := os.Remove(dbFile)
	if err != nil {
		log.Warn(err)
	}

	killAllApp := createApp()
	defer killAllApp.run([]string{OPENPORT_EXE, "kill-all", "--database", dbFile})

	port := getFreePort(t)

	reserveApp := createApp()
	defer reserveApp.Stop(0)

	go reserveApp.run([]string{
		OPENPORT_EXE,
		"--exit-on-failure-timeout", "5",
		strconv.Itoa(port),
		"--server", TEST_SERVER,
		"--verbose",
		"--database", dbFile,
	})

	select {
	case <-reserveApp.exitCode:
		assert.FailNow(t, "App exited to quickly")
	case <-time.After(6 * time.Second):
		// ok, this is fine.
	}
	reserveApp.Stop(0)
}
