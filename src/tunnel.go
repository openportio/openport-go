package openport

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	db "github.com/openportio/openport-go/database"
	"github.com/openportio/openport-go/utils"
	"github.com/openportio/openport-go/ws_channel"
	"github.com/phayes/freeport"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/ssh"
)

func (app *App) CreateTunnel() {
	if app.Session.RestartCommand != "" {
		CheckUsernameInConfigFile()
	}
	HandleSignals(app)
	publicKey, key, err := utils.EnsureKeysExist()
	if err != nil {
		log.Fatalf("Error during fetching/creating key: %s", err)
	}
	app.DbHandler.InitDB()
	dbSession := app.DbHandler.EnrichSessionWithHistory(&app.Session)
	oldSession, err := app.DbHandler.GetSession(app.Session.LocalPort)
	if err != nil {
		log.Fatalf("error fetching session: %s", err)
	}
	if oldSession.ID > 0 && SessionIsLive(oldSession) {
		log.Fatalf("Port forward already running for port %d with PID %d",
			dbSession.LocalPort, dbSession.Pid)
	}
	if app.Session.ForwardTunnel && app.Session.LocalPort < 0 {
		app.Session.LocalPort, err = freeport.GetFreePort()
		if err != nil {
			log.Fatalf("error getting free port: %s", err)
		}
	}
	app.Session.Active = true
	err = app.DbHandler.Save(&app.Session)
	if err != nil {
		log.Warnf("error saving session: %s", err)
	}
	defer app.DbHandler.SetInactive(&app.Session)

	// Remember what the user asked for; the effective mode per connection is
	// decided in applyCustomDomainMode (it may start as plain http-forward
	// while we wait for the domain's CNAME to point at us, then upgrade).
	app.passthrough.wantPassthrough = app.Session.TlsPassthrough
	app.passthrough.wantDomain = app.Session.CustomDomain

	go app.ConnectedState.DoState()

	for {
		app.applyCustomDomainMode()
		response, err2 := app.RequestPortForward(&app.Session, publicKey)
		if err2 != nil {
			log.Error(err2)
			log.Infof("Will sleep for %f seconds", httpSleeper.SleepTime.Seconds())
			httpSleeper.Sleep()
			continue
		}
		httpSleeper.Reset()
		app.passthrough.noteForwardAddress(app.Session.HttpForwardAddress)

		var err error
		if app.Session.ForwardTunnel {
			err = app.StartForwardTunnel(key, app.Session, response.Message)
		} else {

			if app.Session.UseWS {
				wsClient := ws_channel.NewWSClient()
				protocol := "wss"
				if app.Session.NoSSL {
					protocol = "ws"
					log.Warn("**************************************************************************")
					log.Warn("* --no-ssl is set: the connection to the Openport server is UNENCRYPTED. *")
					log.Warn("* Anyone on the network path can read and modify the tunnelled traffic.  *")
					log.Warn("* Remove --no-ssl unless you fully trust the entire network path.        *")
					log.Warn("**************************************************************************")
				}
				primaryServer := fmt.Sprintf("%s://%s/ws", protocol, app.Session.SshServer)
				fallbackServer := fmt.Sprintf("%s://%s/ws", protocol, app.Session.FallbackSshServerIp)
				log.Debugf("Connecting to %s", primaryServer)
				err = wsClient.Connect(primaryServer, fallbackServer, app.Session.Proxy)
				if err != nil {
					log.Warn(err)
				} else {
					callback := func() {
						printSessionMessage(app.Session, response.Message, false)
						app.MarkConnected()
					}
					app.passthrough.setInterrupt(func() { wsClient.Close() })
					err = wsClient.StartReverseTunnel(app.Session, callback)
					app.passthrough.clearInterrupt()
				}
			} else {
				err = app.StartReverseTunnel(key, app.Session, response.Message)
			}
		}
		if !app.Stopped {
			app.MarkDisconnected()
			log.Warn(err)
			if app.Session.AutomaticRestart {
				time.Sleep(10 * time.Second)
			}
			app.Session.AutomaticRestart = true
		} else {
			break
		}
	}
}

func (app *App) StartReverseTunnel(key ssh.Signer, session db.Session, message string) error {
	sshClient, keepAliveDone, err2 := Connect(key, session)
	if err2 != nil {
		return err2
	}
	defer func() { keepAliveDone <- true }()

	log.Debugf("Connected")
	s := fmt.Sprintf("0.0.0.0:%d", session.RemotePort)
	addr, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		return err
	}

	listener, err := sshClient.ListenTCP(addr)
	if err != nil {
		log.Errorf("Could not listen on remote port: %s", err)
		return err
	}
	defer listener.Close()
	// ExitHook
	stopFunc := func() {
		log.Debug("Closing ssh connection and listeners")
		sshClient.Close()
		listener.Close()
	}
	stopFuncRef := app.StopHooks.PushBack(stopFunc)
	defer app.StopHooks.Remove(stopFuncRef)

	// Let the custom-domain poller end just this connection (so the loop
	// reconnects and upgrades to passthrough) without stopping the app.
	app.passthrough.setInterrupt(func() { sshClient.Close(); listener.Close() })
	defer app.passthrough.clearInterrupt()

	// Also set up UDP forwarding on the same port, over the same SSH connection
	udpActive := app.startUDPChannelHandler(sshClient, session)
	printSessionMessage(session, message, udpActive)

	app.MarkConnected()

	for {
		// Wait for a connection.
		conn, err := listener.Accept()
		if err != nil {
			log.Debugf("Could not accept connection: %s", err)
			return err
		}

		go func(c net.Conn) {
			log.Debugf("new request")
			conn, err := net.Dial("tcp", tunnelDialAddress(session))
			if err != nil {
				log.Warn(err)
			} else {
				go func() {
					defer c.Close()
					defer conn.Close()
					io.Copy(c, conn)
				}()
				go func() {
					io.Copy(conn, c)
				}()
			}
		}(conn)
	}
}

// startUDPChannelHandler requests the server to also listen on UDP for the same port,
// and handles incoming "forwarded-udp" channels by forwarding datagrams to the local service.
// Returns whether UDP forwarding is active on the server.
func (app *App) startUDPChannelHandler(sshClient *ssh.Client, session db.Session) bool {
	payload := ssh.Marshal(struct {
		Host string
		Port uint32
	}{Host: "0.0.0.0", Port: uint32(session.RemotePort)}) // #nosec G115 -- a TCP port, 0-65535

	ok, replyData, err := sshClient.Conn.SendRequest("udpip-forward", true, payload)
	if err != nil {
		log.Warnf("UDP forwarding not available: %s", err)
		return false
	}
	if !ok {
		log.Warn("UDP forwarding request rejected by server")
		return false
	}

	// ok alone proves nothing: deployed servers ack *every* unknown global
	// request (the request loop's default branch replies true), so a server
	// that actually implements udpip-forward must prove it by echoing the
	// address it is listening on. No payload means an older server that
	// silently dropped the request -- don't advertise UDP as active.
	reply := struct {
		Host string
		Port uint32
	}{}
	if len(replyData) == 0 || ssh.Unmarshal(replyData, &reply) != nil {
		log.Infof("The server does not support UDP forwarding; only TCP is forwarded on remote port %d.", session.RemotePort)
		return false
	}
	log.Debugf("UDP forwarding enabled on %s:%d", reply.Host, session.RemotePort)

	go func() {
		for newChannel := range sshClient.HandleChannelOpen("forwarded-udp") {
			go handleUDPChannel(newChannel, session.LocalPort)
		}
	}()
	return true
}

func handleUDPChannel(newChannel ssh.NewChannel, localPort int) {
	sshChan, reqs, err := newChannel.Accept()
	if err != nil {
		log.Errorf("Could not accept forwarded-udp channel: %s", err)
		return
	}
	go ssh.DiscardRequests(reqs)

	localAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("127.0.0.1:%d", localPort))
	if err != nil {
		log.Errorf("Could not resolve local UDP addr: %s", err)
		sshChan.Close()
		return
	}
	localConn, err := net.DialUDP("udp", nil, localAddr)
	if err != nil {
		log.Errorf("Could not dial local UDP: %s", err)
		sshChan.Close()
		return
	}

	// SSH channel -> local UDP service
	go func() {
		defer localConn.Close()
		defer sshChan.Close()
		for {
			data, err := utils.ReadFrame(sshChan)
			if err != nil {
				log.Debugf("UDP ReadFrame from SSH ended: %s", err)
				return
			}
			_, err = localConn.Write(data)
			if err != nil {
				log.Debugf("UDP write to local service failed: %s", err)
				return
			}
		}
	}()

	// Local UDP service -> SSH channel
	go func() {
		defer localConn.Close()
		defer sshChan.Close()
		buf := make([]byte, 65535)
		for {
			n, err := localConn.Read(buf)
			if err != nil {
				log.Debugf("UDP read from local service ended: %s", err)
				return
			}
			err = utils.WriteFrame(sshChan, buf[:n])
			if err != nil {
				log.Debugf("UDP WriteFrame to SSH failed: %s", err)
				return
			}
		}
	}()
}

func Connect(key ssh.Signer, session db.Session) (*ssh.Client, chan bool, error) {
	hostKeyCallback, err := utils.HostKeyCallback(session.HostKey)
	if err != nil {
		return nil, nil, err
	}
	config := &ssh.ClientConfig{
		User: "open",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: hostKeyCallback,
		// Only offer algorithms for the key type the API published, so a
		// server with several host keys presents the one we can verify.
		HostKeyAlgorithms: utils.HostKeyAlgorithms(session.HostKey),
		Timeout:           time.Duration(session.KeepAliveSeconds) * time.Second,
	}

	var sshClient *ssh.Client
	sshAddress := fmt.Sprintf("%s:%d", session.SshServer, 22)
	fallbackSshAddress := fmt.Sprintf("%s:%d", session.FallbackSshServerIp, session.FallbackSshServerPort)
	if session.Proxy != "" {
		conn, sshAddress, err := utils.GetProxyConn(session.Proxy, sshAddress, fallbackSshAddress)
		if err != nil {
			return nil, nil, err
		}
		c, chans, reqs, err := ssh.NewClientConn(conn, sshAddress, config)
		if err != nil {
			return nil, nil, err
		}
		sshClient = ssh.NewClient(c, chans, reqs)
	} else {
		sshClient, err = ssh.Dial("tcp", sshAddress, config)
		if err != nil {
			log.Debugf("%s -> falling back to %s", err, fallbackSshAddress)
			sshAddress = fallbackSshAddress
			sshClient, err = ssh.Dial("tcp", sshAddress, config)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	keepAliveDone := make(chan bool, 1)
	go KeepAlive(sshClient, time.Duration(int64(session.KeepAliveSeconds)*int64(time.Second)), keepAliveDone)
	return sshClient, keepAliveDone, nil
}

func KeepAlive(cl *ssh.Client, keepAliveInterval time.Duration, done <-chan bool) {
	t := time.NewTicker(keepAliveInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			_, _, err := cl.SendRequest("keep-alive", true, nil)
			if err != nil {
				log.Warn("failed to send keep alive ", err)
			}
		case <-done:
			return
		}
	}
}

func (app *App) StartForwardTunnel(key ssh.Signer, session db.Session, msg string) error {
	sshClient, keepAliveDone, err2 := Connect(key, session)
	if err2 != nil {
		return err2
	}
	defer func() { keepAliveDone <- true }()

	listener, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", session.LocalPort))
	if err != nil {
		return err
	}
	defer listener.Close()

	// Stop Hook
	stopFunc := func() {
		log.Debug("Closing ssh connection and listeners")
		sshClient.Close()
		listener.Close()
	}
	stopFuncRef := app.StopHooks.PushBack(stopFunc)
	defer app.StopHooks.Remove(stopFuncRef)

	log.Info(msg)
	app.MarkConnected()
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		log.Debugf("Incoming request on forward tunnel from %s", conn.RemoteAddr())
		go handleRequestOnForwardTunnel(sshClient, conn, session)
	}
}

func handleRequestOnForwardTunnel(sshClient *ssh.Client, localConn net.Conn, session db.Session) {
	remoteConn, err := sshClient.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", session.RemotePort))
	if err != nil {
		log.Errorf("server dial error: %s", err)
		return
	}

	var closeOnce sync.Once
	closeConns := func() {
		localConn.Close()
		remoteConn.Close()
	}
	copyConn := func(writer, reader net.Conn) {
		defer closeOnce.Do(closeConns)
		_, err := io.Copy(writer, reader)
		if err != nil {
			log.Debugf("io.Copy error: %s", err)
		}
	}
	go copyConn(localConn, remoteConn)
	go copyConn(remoteConn, localConn)
	return
}
