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

	go reserveApp.run([]string{OPENPORT_EXE, "--local-port", strconv.Itoa(port), "--server", TEST_SERVER, "--verbose", "--database", dbFile})
	waitForApp(t, &reserveApp)
	ClickLink(t, reserveApp.Session.OpenPortForIpLink)
	CheckTcpForward(t, port, reserveApp.Session.SshServer, reserveApp.Session.RemotePort)

	forwardPort := getFreePort(t)

	forwardApp := createApp()
	defer forwardApp.Stop()
	go forwardApp.run([]string{OPENPORT_EXE, "forward",
		"--server", TEST_SERVER, "--database", dbFile,
		"--local-port", strconv.Itoa(forwardPort),
		"--verbose",
		"--remote-port", strconv.Itoa(reserveApp.Session.RemotePort),
		"--restart-on-reboot"})

	waitForApp(t, &forwardApp)
	time.Sleep(1 * time.Second)

	CheckTcpForward(t, port, "127.0.0.1", forwardPort)
	activeSessions, err := forwardApp.dbHandler.GetAllActive()
	failIfError(t, err)
	assertEqual(t, 2, len(activeSessions))

	forwardApp.Stop()

	// Restarting app
	CheckTcpForwardFails(t, port, "127.0.0.1", forwardPort)
	activeSessions, err = forwardApp.dbHandler.GetAllActive()
	failIfError(t, err)
	assertEqual(t, 1, len(activeSessions))

	restartApp := createApp()
	// todo: won't work because the first arg is wrong...
	restartShares := func() {
		restartApp.run([]string{OPENPORT_EXE, "restart-sessions", "--database", dbFile})
	}
	timeoutFunction(t, restartShares, 2*time.Second)

	time.Sleep(3 * time.Second)

	CheckTcpForward(t, port, "127.0.0.1", forwardPort)
	activeSessions, err = forwardApp.dbHandler.GetAllActive()
	failIfError(t, err)
	assertEqual(t, 2, len(activeSessions))

	/*
		   #
		   def foo():
			   in_session2 = self.db_handler.get_share_by_local_port(forwarding_port, filter_active=False)
			   if in_session2 is None:
				   print('forwarding session not found')
				   return False

			   print('forwarding session found')
			   in_app_management_port2 = in_session2.app_management_port
			   # wait for the session to be renewed
			   if forward_app_management_port == in_app_management_port2:
				   print('still same session')
				   return False
			   if not in_session2.active:
				   print('session not active')
				   return False

			   return run_method_with_timeout(is_running, args=[in_session2], timeout_s=5)

		   wait_for_response(foo, timeout=10)
		   logger.debug('sleeping now')
		   logger.debug('wait_for_response done')
		   check_tcp_port_forward(self, remote_host='127.0.0.1', local_port=serving_port, remote_port=forwarding_port)

	*/

}
