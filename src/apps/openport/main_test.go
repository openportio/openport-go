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

const TEST_SERVER = "https://test.openport.io"

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

	reverseApp := openport.CreateApp()
	defer reverseApp.Stop(0)

	go run(reverseApp, []string{
		OPENPORT_EXE,
		strconv.Itoa(port),
		"--server", TEST_SERVER,
		"--verbose",
		"--database", dbFile,
		"--restart-on-reboot",
	})
	openport.WaitForApp(t, reverseApp)
	openport.ClickLink(t, reverseApp.Session.OpenPortForIpLink)
	openport.CheckTcpForward(t, port, reverseApp.Session.SshServer, reverseApp.Session.RemotePort)
	openport.AssertEqual(t, true, reverseApp.Session.Connected)

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
		"--remote-port", strconv.Itoa(reverseApp.Session.RemotePort),
		"--restart-on-reboot",
	})

	openport.WaitForApp(t, forwardApp)

	openport.CheckTcpForward(t, port, "127.0.0.1", forwardPort)
	openport.AssertEqual(t, true, forwardApp.Session.Connected)

	activeSessions, err := forwardApp.DbHandler.GetAllActive()
	openport.FailIfError(t, err)
	openport.AssertEqual(t, 2, len(activeSessions))
	allConnected := true
	for _, session := range activeSessions {
		allConnected = allConnected && session.Connected
	}
	openport.AssertEqual(t, true, allConnected)

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

	waitForActiveSessions := func() string {
		endTicker := time.NewTicker(20 * time.Second)
		for {
			activeSessions, err := forwardApp.DbHandler.GetAllActive()
			openport.FailIfError(t, err)
			if len(activeSessions) == 2 {
				allConnected := true
				for _, session := range activeSessions {
					allConnected = allConnected && session.Connected
				}
				if allConnected {
					return "ok"
				}
			}
			select {
			case <-endTicker.C:
				return "not ok"
			default:
				time.Sleep(50 * time.Millisecond)
				println("waiting for active sessions")
			}
		}
	}
	openport.AssertEqual(t, "ok", openport.TimeoutFunction(t, waitForActiveSessions, 20*time.Second))
	time.Sleep(500 * time.Millisecond)

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

func TestStripAutomaticRestart(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"long flag", []string{"8080", "--restart-on-reboot", "--automatic-restart"}, []string{"8080", "--restart-on-reboot"}},
		{"long flag with value", []string{"8080", "--automatic-restart=true"}, []string{"8080"}},
		{"short flag", []string{"8080", "-a"}, []string{"8080"}},
		{"short flag with value", []string{"8080", "-a=true"}, []string{"8080"}},
		{"combined shorthand", []string{"8080", "-va"}, []string{"8080", "-v"}},
		{"combined shorthand with value for it", []string{"8080", "-va=true"}, []string{"8080", "-v"}},
		{"combined shorthand with value for another flag", []string{"8080", "-ad=x"}, []string{"8080", "-d=x"}},
		{"kept after terminator", []string{"8080", "--", "-a"}, []string{"8080", "--", "-a"}},
		{"unrelated flags untouched", []string{"8080", "-v", "--server", "https://x"}, []string{"8080", "-v", "--server", "https://x"}},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, stripAutomaticRestart(c.in), c.name)
	}
}

func TestRewriteFlagValue(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"separate value", []string{"8080", "--tls-cert", "cert.pem"}, []string{"8080", "--tls-cert", "/abs/cert.pem"}},
		{"equals value", []string{"8080", "--tls-cert=cert.pem"}, []string{"8080", "--tls-cert=/abs/cert.pem"}},
		{"flag absent", []string{"8080", "-v"}, []string{"8080", "-v"}},
		{"kept after terminator", []string{"8080", "--", "--tls-cert", "cert.pem"}, []string{"8080", "--", "--tls-cert", "cert.pem"}},
		{"prefix of another flag untouched", []string{"8080", "--tls-cert-x", "y"}, []string{"8080", "--tls-cert-x", "y"}},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, rewriteFlagValue(c.in, "--tls-cert", "/abs/cert.pem"), c.name)
	}
}
