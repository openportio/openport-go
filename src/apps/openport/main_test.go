package main

import (
	"github.com/openportio/openport-go"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"os"
	"strconv"
	"testing"
	"time"
)

const TEST_SERVER = "https://test2.openport.io"

var OPENPORT_EXE = openport.DefaultEnv("OPENPORT_EXE", "/home/jan/workspace/openport-go-client/openport-amd64")

func TestReverseTunnel(t *testing.T) {
	dbFile := "tmp/TestReverseTunnel.db"
	port := openport.GetFreePort(t)
	app := openport.CreateApp()
	defer app.Stop(0)

	go run(app, []string{
		OPENPORT_EXE,
		strconv.Itoa(port),
		"--server", TEST_SERVER,
		"--verbose",
		"--database", dbFile,
		"--exit-on-failure-timeout", "10",
	})
	openport.WaitForApp(t, app)
	openport.ClickLink(t, app.Session.OpenPortForIpLink)
	openport.CheckTcpForward(t, port, app.Session.SshServer, app.Session.RemotePort)
}

func TestReverseTunnelWithWS(t *testing.T) {
	dbFile := "tmp/TestReverseTunnel.db"
	port := openport.GetFreePort(t)
	app := openport.CreateApp()
	defer app.Stop(0)

	go run(app, []string{
		OPENPORT_EXE,
		strconv.Itoa(port),
		"--server", TEST_SERVER,
		"--verbose",
		"--database", dbFile,
		"--ws",
		"--exit-on-failure-timeout", "10",
	})
	openport.WaitForApp(t, app)
	openport.ClickLink(t, app.Session.OpenPortForIpLink)
	openport.CheckTcpForward(t, port, app.Session.SshServer, app.Session.RemotePort)
}
func TestReverseTunnelWithWSNoSSL(t *testing.T) {
	dbFile := "tmp/TestReverseTunnel.db"
	port := openport.GetFreePort(t)
	app := openport.CreateApp()
	defer app.Stop(0)

	go run(app, []string{
		OPENPORT_EXE,
		strconv.Itoa(port),
		"--server", TEST_SERVER,
		"--verbose",
		"--database", dbFile,
		"--ws",
		"--no-ssl",
		"--exit-on-failure-timeout", "10",
	})
	openport.WaitForApp(t, app)
	openport.ClickLink(t, app.Session.OpenPortForIpLink)
	openport.CheckTcpForward(t, port, app.Session.SshServer, app.Session.RemotePort)
}

func TestSaveForwardTunnel(t *testing.T) {
	dbFile := "tmp/TestSaveForwardTunnel.db"
	err := os.Remove(dbFile)
	if err != nil {
		log.Warn(err)
	}

	killAllApp := openport.CreateApp()
	defer run(killAllApp, []string{OPENPORT_EXE, "kill-all", "--database", dbFile})

	port := openport.GetFreePort(t)

	reserveApp := openport.CreateApp()
	defer reserveApp.Stop(0)

	go run(reserveApp, []string{
		OPENPORT_EXE,
		strconv.Itoa(port),
		"--server", TEST_SERVER,
		"--verbose",
		"--database", dbFile,
		"--restart-on-reboot",
	})
	openport.WaitForApp(t, reserveApp)
	openport.ClickLink(t, reserveApp.Session.OpenPortForIpLink)
	openport.CheckTcpForward(t, port, reserveApp.Session.SshServer, reserveApp.Session.RemotePort)

	forwardPort := openport.GetFreePort(t)

	forwardApp := openport.CreateApp()
	defer forwardApp.Stop(0)
	go run(forwardApp, []string{
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

	openport.WaitForApp(t, forwardApp)
	time.Sleep(1 * time.Second)

	openport.CheckTcpForward(t, port, "127.0.0.1", forwardPort)
	activeSessions, err := forwardApp.DbHandler.GetAllActive()
	openport.FailIfError(t, err)
	openport.AssertEqual(t, 2, len(activeSessions))

	forwardApp.Stop(0)
	getExitCode := func() string {
		return strconv.Itoa(<-forwardApp.ExitCode)
	}
	assert.Equal(t, "0", openport.TimeoutFunction(t, getExitCode, 3*time.Second))
	time.Sleep(500 * time.Millisecond)

	openport.CheckTcpForwardFails(t, port, "127.0.0.1", forwardPort)
	activeSessions, err = forwardApp.DbHandler.GetAllActive()
	openport.FailIfError(t, err)
	openport.AssertEqual(t, 1, len(activeSessions))

	sessionsToRestart, err := forwardApp.DbHandler.GetSessionsToRestart()
	openport.FailIfError(t, err)
	openport.AssertEqual(t, 2, len(sessionsToRestart))

	// Restarting app
	restartShares := func() string {
		restartApp := openport.CreateApp()
		run(restartApp, []string{
			OPENPORT_EXE,
			"restart-sessions",
			"--database", dbFile,
		})
		return "ok"
	}
	openport.TimeoutFunction(t, restartShares, 2*time.Second)

	time.Sleep(1 * time.Second)
	activeSessions, err = forwardApp.DbHandler.GetAllActive()
	openport.FailIfError(t, err)
	openport.AssertEqual(t, 2, len(activeSessions))

	openport.CheckTcpForward(t, port, "127.0.0.1", forwardPort)
}

func TestConnectionTimeout(t *testing.T) {
	dbFile := "tmp/TestConnectionTimeout.db"
	err := os.Remove(dbFile)
	if err != nil {
		log.Warn(err)
	}

	killAllApp := openport.CreateApp()
	defer run(killAllApp, []string{OPENPORT_EXE, "kill-all", "--database", dbFile})

	port := openport.GetFreePort(t)

	reserveApp := openport.CreateApp()
	defer reserveApp.Stop(0)

	start := time.Now()
	go run(reserveApp, []string{
		OPENPORT_EXE,
		"--exit-on-failure-timeout", "1",
		strconv.Itoa(port),
		"--server", "https://non-existant.example.com",
		"--verbose",
		"--database", dbFile,
	})

	waitForExitCode := func() string {
		return strconv.Itoa(<-reserveApp.ExitCode)
	}
	openport.AssertEqual(t, strconv.Itoa(openport.EXIT_CODE_NO_CONNECTION), openport.TimeoutFunction(t, waitForExitCode, 2*time.Second))

	assert.True(t, time.Now().After(start.Add(500*time.Millisecond)), "App exited to quickly")
	// TODO: does this still work after a restart

	//// Restarting app
	//restartShares := func() string {
	//	restartApp := CreateApp()
	//	run(restartApp, []string{
	//		OPENPORT_EXE,
	//		"restart-sessions",
	//		"--database", dbFile,
	//	})
	//	return "ok"
	//}
	//TimeoutFunction(t, restartShares, 2*time.Second)
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

	killAllApp := openport.CreateApp()
	defer run(killAllApp, []string{OPENPORT_EXE, "kill-all", "--database", dbFile})

	port := openport.GetFreePort(t)

	reserveApp := openport.CreateApp()
	defer reserveApp.Stop(0)

	go run(reserveApp, []string{
		OPENPORT_EXE,
		"--exit-on-failure-timeout", "5",
		strconv.Itoa(port),
		"--server", TEST_SERVER,
		"--verbose",
		"--database", dbFile,
	})

	select {
	case <-reserveApp.ExitCode:
		assert.FailNow(t, "App exited to quickly")
	case <-time.After(6 * time.Second):
		// ok, this is fine.
	}
	reserveApp.Stop(0)
}
