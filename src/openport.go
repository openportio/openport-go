package openport

import (
	"bytes"
	"container/list"
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jedib0t/go-pretty/table"
	"github.com/jedib0t/go-pretty/text"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	ogrek "github.com/kisielk/og-rek"
	db "github.com/openportio/openport-go/database"
	"github.com/openportio/openport-go/utils"
	"github.com/openportio/openport-go/ws_channel"
	"github.com/orandin/lumberjackrus"
	"github.com/phayes/freeport"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const VERSION = "2.2.2"
const USER_CONFIG_FILE = "/etc/openport/users.conf"
const DEFAULT_SERVER = "https://openport.io"

const EXIT_CODE_NO_CONNECTION = 4
const EXIT_CODE_REMOTE_STOP = 5
const EXIT_CODE_DAEMONIZED_OK = 0
const EXIT_CODE_KEY_REGISTERED_OK = 0
const EXIT_CODE_KEY_REGISTERED_FAILED = 1
const EXIT_CODE_INTERRUPTED = 2
const EXIT_CODE_USAGE = 6
const EXIT_CODE_INVALID_ARGUMENT = 7
const EXIT_CODE_DAEMONIZED_ERROR = 3
const EXIT_CODE_FATAL_SESSION_ERROR = 9
const EXIT_CODE_LIST = 0
const EXIT_CODE_HELP = 0
const EXIT_CODE_RM = 0

var LogPath = path.Join(utils.OPENPORT_HOME, "openport.log")

type PortResponse struct {
	ServerIP              string  `json:"server_ip"`
	FallbackSshServerIp   string  `json:"fallback_ssh_server_ip"`
	FallbackSshServerPort int     `json:"fallback_ssh_server_port"`
	SessionMaxBytes       int64   `json:"session_max_bytes"`
	OpenPortForIpLink     string  `json:"open_port_for_ip_link"`
	Message               string  `json:"message"`
	SessionEndTime        float64 `json:"session_end_time"`
	AccountId             int     `json:"account_id"`
	SessionToken          string  `json:"session_token"`
	SessionId             int     `json:"session_id"`
	HttpForwardAddress    string  `json:"http_forward_address"`
	ServerPort            int     `json:"server_port"`
	KeyId                 int     `json:"key_id"`
	Error                 string  `json:"error"`
	FatalError            bool    `json:"fatal_error"`
}

type RegisterKeyResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
}

type ServerResponseError struct {
	error string
}

type App struct {
	Session              db.Session
	Stopped              bool
	StopHooks            *list.List
	DbHandler            db.DBHandler
	ExitCode             chan int // Blocking channel waiting for the exit code.
	ExitOnFailureTimeout int
	Connected            chan bool
	ConnectedState       ConnectionState
}

func CreateApp() *App {
	app := &App{
		ExitOnFailureTimeout: -1,
		ExitCode:             make(chan int, 1),
		StopHooks:            list.New(),
		Connected:            make(chan bool, 1),
	}
	app.ConnectedState = &DisconnectedState{app: app}
	return app
}

func (app *App) SaveState() {
	err := app.DbHandler.Save(&app.Session)
	if err != nil {
		log.Warn(err)
	}
}

var httpSleeper = utils.IncrementalSleeper{
	SleepTime:        10 * time.Second,
	MaxSleepTime:     300 * time.Second,
	InitialSleepTime: 10 * time.Second,
}

func (s ServerResponseError) Error() string {
	return s.error
}

var stdOutLogHook writer.Hook

var interProcessHttpClient = http.Client{
	Timeout: 2 * time.Second,
}

var loggingReady = false

func InitLogging(verbose bool, logFilePath string) {
	if loggingReady {
		return
	}
	log.SetLevel(log.DebugLevel)
	log.WithField("pid", os.Getpid())
	hook, err := lumberjackrus.NewHook(
		&lumberjackrus.LogFile{
			Filename:   logFilePath,
			MaxSize:    10,
			MaxBackups: 1,
			Compress:   true,
		},
		log.DebugLevel,
		&log.TextFormatter{
			FullTimestamp: true,
		},
		&lumberjackrus.LogFileOpts{},
	)

	if err != nil {
		log.Warn(err)
	}
	log.AddHook(hook)
	log.SetOutput(io.Discard) // Send all logs to nowhere by default

	log.AddHook(&writer.Hook{ // Send logs with level higher than warning to stderr
		Writer: os.Stderr,
		LogLevels: []log.Level{
			log.PanicLevel,
			log.FatalLevel,
			log.ErrorLevel,
			log.WarnLevel,
		},
	})

	stdOutLogHook = writer.Hook{
		Writer: os.Stdout,
		LogLevels: []log.Level{
			log.InfoLevel,
		},
	}

	if verbose {
		stdOutLogHook.LogLevels = []log.Level{
			log.InfoLevel,
			log.DebugLevel,
		}
	}

	log.AddHook(&stdOutLogHook)
	log.SetFormatter(&log.TextFormatter{
		ForceColors:            true,
		DisableTimestamp:       true,
		DisableLevelTruncation: true,
	})
	loggingReady = true
}

func (app *App) InitFiles() {
	utils.EnsureHomeFolderExists()
	app.DbHandler.InitDB()
}

func (app *App) StartDaemon(args []string) {
	// TODO: there might be an issue with this?
	loc := Find(args, "-d")
	var command []string
	if loc < 0 {
		loc = Find(args, "--daemonize")
	}
	if loc >= 0 && len(args) > 1 {
		command = append(args[:loc], args[loc+1:]...)
	} else {
		log.Debugf("%s", args)
		log.Fatalf("Use -d or --daemonize to start in the background")
	}
	cmd := exec.Command(command[0], command[1:]...)
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
		app.ExitCode <- EXIT_CODE_DAEMONIZED_ERROR
	} else {
		log.Info("Process started in background")
		app.ExitCode <- EXIT_CODE_DAEMONIZED_OK
	}
}

func Find(a []string, x string) int {
	for i, n := range a {
		if x == n {
			return i
		}
	}
	return -1
}

func (app *App) RegisterKey(keyBindingToken string, name string, proxy string, server string) {
	utils.EnsureHomeFolderExists()
	publicKey, _, err := utils.EnsureKeysExist()
	if err != nil {
		log.Fatalf("Could not get key: %s", err)
	}

	httpClient := GetHttpClient(proxy)
	postUrl := fmt.Sprintf("%s/linkKey", server)
	getParameters := url.Values{
		"public_key":        {string(publicKey)},
		"key_binding_token": {keyBindingToken},
		"key_name":          {name},
		"client_version":    {VERSION},
		"platform":          {runtime.GOOS},
	}
	log.Debugf("parameters: %s", getParameters)
	resp, err := httpClient.PostForm(postUrl, getParameters)
	if err != nil {
		log.Fatalf("HTTP error: %s", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Body error: %s", err)
	}
	log.Debugf(string(body))
	response := RegisterKeyResponse{}
	jsonErr := json.Unmarshal(body, &response)
	if jsonErr != nil {
		log.Fatalf("Json Decode error: %s", err)
	}
	if response.Status != "ok" {
		log.Fatalf("Could not register key: %s", response.Error)
		app.ExitCode <- EXIT_CODE_KEY_REGISTERED_FAILED
	} else {
		log.Info("key successfully registered")
		app.ExitCode <- EXIT_CODE_KEY_REGISTERED_OK
	}
}

func SessionIsLive(session db.Session) bool {
	url := fmt.Sprintf("http://127.0.0.1:%d/info", session.AppManagementPort)
	log.Debug(url)
	resp, err := interProcessHttpClient.Get(url)
	if err != nil {
		log.Debugf("Error while requesting %s: %s", url, err)
		return false
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debugf("Error while getting the body of %s: %s", url, err)
		return false
	}
	log.Debugf("Got response on url %s: %s", url, body)
	return string(body)[:8] == "openport"
}

func (app *App) ListSessions() {
	tw := table.NewWriter()
	tw.SetStyle(table.StyleRounded)
	tw.Style().Format.Header = text.FormatTitle
	tw.SetOutputMirror(os.Stdout)
	tw.AppendHeader(table.Row{
		"Local Port",
		"Server",
		"Remote Port",
		"Open-For-IP-Link",
		"Running",
		"Restart-On-Reboot",
		"Forward Tunnel",
	})
	tw.SetTitle("Active Openport Sessions")
	sessions, err := app.DbHandler.GetAllActive()
	if err != nil {
		panic(err)
	}
	for _, session := range sessions {
		log.Debug("adding row ", session)
		tw.AppendRow([]interface{}{
			session.LocalPort,
			session.SshServer,
			session.RemotePort,
			session.OpenPortForIpLink,
			SessionIsLive(session),
			session.RestartCommand != "",
			session.ForwardTunnel,
		})
	}
	tw.Render()
}

func (app *App) RestartSessions(appPath string, server string) {
	log.Debugf("Restarting Sessions -> %s %s %s", appPath, server, app.DbHandler.DbPath)
	app.restartSessionsForCurrentUser(appPath, server)
	app.restartSessionsForAllUsers(appPath)
}

func (app *App) restartSessionsForAllUsers(appPath string) {
	if strings.Contains(runtime.GOOS, "windows") {
		return
	}

	currentUser, err := user.Current()
	username := ""
	if err != nil {
		log.Debug("error getting current user:", err)
	} else {
		username = currentUser.Username
	}
	if username != "root" {
		return
	}

	buf, err := os.ReadFile(USER_CONFIG_FILE)
	if err != nil {
		log.Warnf("Could not read file %s: %s", USER_CONFIG_FILE, err)
	} else {
		users := strings.Split(string(buf), "\n")

		for _, username := range users {
			username = strings.TrimSpace(strings.Split(username, "#")[0])
			if username == "root" {
				continue
			}
			if username != "" {
				command := []string{"-u", username, "-H", appPath, "restart-sessions"}
				log.Debugf("Running command sudo %s", command)
				cmd := exec.Command("sudo", command...)
				err = cmd.Start()
				if err != nil {
					log.Warn(err)
				}
			}
		}
	}
}

func (app *App) restartSessionsForCurrentUser(appPath string, server string) {
	if !utils.FileExists(app.DbHandler.DbPath) {
		log.Debugf("DB file %s does not exist. Not restarting anything.", app.DbHandler.DbPath)
		return
	}

	sessions, err := app.DbHandler.GetSessionsToRestart()
	if err != nil {
		log.Error("Error getting sessions to restart: ", err)
		return
	}
	for _, session := range sessions {
		log.Debug("Restarting session: ", session.LocalPort)
		restartCommand := strings.Split(session.RestartCommand, " ")
		if (len(restartCommand) > 1 && restartCommand[1][0] != '-' && restartCommand[0] != "--port") ||
			strings.Contains(restartCommand[0], "\n") ||
			restartCommand[0][0] == 0x80 {
			log.Debugf("Migrating from older version: %s", session.RestartCommand)
			// Python pickle
			buf := bytes.NewBufferString(session.RestartCommand)
			dec := ogrek.NewDecoder(buf)
			unpickled, err := dec.Decode()
			if err != nil {
				log.Error(err)
				log.Warn("Session will not be restarted")
				continue
			}
			log.Debugf("this is unpickled : <%s>", unpickled)
			restartCommand = []string{}
			unpickledInterfaces, castWasOk := unpickled.([]interface{})
			if castWasOk {
				for _, part := range unpickledInterfaces {
					restartCommand = append(restartCommand, part.(string))
				}
			} else {
				unpickledString := unpickled.(string)
				if unpickledString == "" {
					continue
				}
				restartCommand = []string{unpickledString}
			}
			if strings.Contains(restartCommand[0], "openport") {
				restartCommand = restartCommand[1:]
			}
		}

		if server != DEFAULT_SERVER {
			restartCommand = append(restartCommand, "--server", server)
		}
		if app.DbHandler.DbPath != db.DEFAULT_OPENPORT_DB_PATH {
			restartCommand = append(restartCommand, "--database", app.DbHandler.DbPath)
		}
		if !slices.Contains(restartCommand, "--automatic") && !slices.Contains(restartCommand, "-a") {
			restartCommand = append(restartCommand, "--automatic-restart")
		}

		log.Infof("Running command %s with args %s", appPath, restartCommand)
		cmd := exec.Command(appPath, restartCommand...)
		err = cmd.Start()
		if err != nil {
			log.Warn(err)
		}
	}
}

func (app *App) KillAll() {
	sessions, err := app.DbHandler.GetAllActive()
	if err != nil {
		panic(err)
	}
	for _, session := range sessions {
		resp, err3 := interProcessHttpClient.Get(fmt.Sprintf("http://127.0.0.1:%d/exit", session.AppManagementPort))
		if err3 != nil {
			session.Active = false
			app.DbHandler.Save(&session)
			log.Warnf("Could not kill session for local port %d: %s", session.LocalPort, err3)
		} else {
			log.Infof("Killed session for local port %d", session.LocalPort)
			log.Debug(resp)
		}
	}
}

func (app *App) StopSession(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(w, "Ok")
	app.Stop(EXIT_CODE_REMOTE_STOP)

	// TODO: stop session from restarting.  Done?
	// TODO: Force flag
}

func (app *App) InfoRequest(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(w, "openport")
}

func (app *App) StartControlServer(controlPort int) int {
	if controlPort <= 0 {
		var err error
		controlPort, err = freeport.GetFreePort()
		if err != nil {
			log.Fatalf("Could not start control server: %s", err)
		}
	}
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/exit", app.StopSession)
	router.HandleFunc("/info", app.InfoRequest)
	log.Debugf("Listening for control on port %d", controlPort)
	go http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", controlPort), router)
	return controlPort
}

func HandleSignals(app *App) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT)
	restartMessage := ""
	if app.Session.RestartCommand != "" {
		restartMessage = " Session will not be restarted by \"restart-sessions\""
	}

	go func() {
		sig := <-sigs
		log.Infof("Got signal %d. Exiting.%s", sig, restartMessage)
		app.Stop(EXIT_CODE_INTERRUPTED)
	}()
}

func CheckUsernameInConfigFile() {

	if runtime.GOOS == "windows" {
		return
	}

	currentUser, err := user.Current()
	username := ""
	if err != nil {
		log.Debug(err)
	} else {
		username = currentUser.Username
	}
	if username == "root" {
		return
	}

	buf, err := os.ReadFile(USER_CONFIG_FILE)
	if err != nil {
		if os.IsNotExist(err) {
			log.Warnf("The file %s does not exist. Your sessions will not be automatically restarted "+
				"on reboot. You can restart your session with \"openport restart-sessions\"", USER_CONFIG_FILE)
		} else if os.IsPermission(err) {
			log.Warnf("You do not have the rights to read file %s, so we can not verify that your session will be restarted on reboot. "+
				"You can restart your session with \"openport restart-sessions\"", USER_CONFIG_FILE)
		} else {
			log.Warnf("Unexpected error when opening file %s : %s", USER_CONFIG_FILE, err)
		}
		return
	}
	users := strings.Split(string(buf), "\n")
	if Find(users, username) < 0 {
		log.Warnf("Your username (%s) is not in %s. Your sessions will not be automatically restarted "+
			"on reboot. You can restart your session with \"openport restart-sessions\"", username, USER_CONFIG_FILE,
		)
	}
}

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
	if dbSession.ID > 0 && SessionIsLive(dbSession) {
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

	go app.ConnectedState.DoState()

	for {
		response, err2 := app.RequestPortForward(&app.Session, publicKey)
		if err2 != nil {
			log.Error(err2)
			log.Infof("Will sleep for %f seconds", httpSleeper.SleepTime.Seconds())
			httpSleeper.Sleep()
			continue
		}
		httpSleeper.Reset()

		var err error
		if app.Session.ForwardTunnel {
			err = app.StartForwardTunnel(key, app.Session, response.Message)
		} else {

			if app.Session.UseWS {
				wsClient := ws_channel.NewWSClient()
				protocol := "wss"
				if app.Session.NoSSL {
					protocol = "ws"
				}
				primaryServer := fmt.Sprintf("%s://%s/ws", protocol, app.Session.SshServer)
				fallbackServer := fmt.Sprintf("%s://%s/ws", protocol, app.Session.FallbackSshServerIp)
				log.Debugf("Connecting to %s", primaryServer)
				err = wsClient.Connect(primaryServer, fallbackServer, app.Session.Proxy)
				if err != nil {
					log.Warn(err)
				} else {
					callback := func() {
						app.Session.PrintMessage(response.Message)
						app.MarkConnected()
					}
					err = wsClient.StartReverseTunnel(app.Session, callback)
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

func (app *App) Stop(exitCode int) {
	if app.Stopped {
		return
	}
	app.Stopped = true
	log.Debug("Stopping app")
	for i := app.StopHooks.Front(); i != nil; i = i.Next() {
		i.Value.(func())()
	}
	app.ExitCode <- exitCode
	//app.SetInactive(app.Session)
}

func GetHttpClient(proxy string) http.Client {
	if proxy == "" {
		return http.Client{
			Timeout: 60 * time.Second,
		}
	} else {
		p := strings.Replace(proxy, "socks5h", "socks5", 1)
		u, err := url.Parse(p)
		if err != nil {
			log.Fatalf("Could not parse proxy: %s", proxy)
		}
		tr := &http.Transport{
			Proxy: http.ProxyURL(u),
		}
		return http.Client{
			Transport: tr,
			Timeout:   60 * time.Second,
		}
	}
}

func (app *App) RequestPortForward(session *db.Session, publicKey []byte) (PortResponse, error) {
	httpClient := GetHttpClient(session.Proxy)

	postUrl := fmt.Sprintf("%s/api/v1/request-port", session.Server)
	getParameters := url.Values{
		"public_key":            {string(publicKey)},
		"request_port":          {strconv.Itoa(session.RemotePort)},
		"client_version":        {VERSION},
		"restart_session_token": {session.SessionToken},
		"local_port":            {strconv.Itoa(session.LocalPort)},
		"http_forward":          {strconv.FormatBool(session.HttpForward)},
		"platform":              {runtime.GOOS},
		"forward_tunnel":        {strconv.FormatBool(session.ForwardTunnel)},
		"request_server":        {session.SshServer},
		"automatic_restart":     {strconv.FormatBool(session.AutomaticRestart)},
	}
	switch strings.ToLower(session.UseIpLinkProtection) {
	case "true", "false":
		getParameters["ip_link_protection"] = []string{session.UseIpLinkProtection}
	case "":
	default:
		getParameters["ip_link_protection"] = []string{"True"}
	}
	log.Debugf("parameters: %s", getParameters)
	resp, err := httpClient.PostForm(postUrl, getParameters)
	if err != nil {
		log.Errorf("Error communicating with %s: %s", session.Server, err)
		return PortResponse{}, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debugf("http error")
		log.Warn(err)
		return PortResponse{}, err
	}
	log.Debugf(string(body))
	response := PortResponse{}
	jsonErr := json.Unmarshal(body, &response)
	if jsonErr != nil {
		log.Warnf("json error: %s", err)
		return PortResponse{}, jsonErr
	}

	if response.Error != "" {
		if response.FatalError {
			log.Infof("Stopping session on request of server: %s", response.Error)
			app.DbHandler.SetInactive(session)
			app.ExitCode <- EXIT_CODE_FATAL_SESSION_ERROR
		}
		return PortResponse{}, ServerResponseError{response.Error}
	}

	log.Debugf("ServerPort: %d", response.ServerPort)
	session.SessionToken = response.SessionToken
	session.RemotePort = response.ServerPort
	session.SshServer = response.ServerIP
	session.Pid = os.Getpid()
	session.AccountId = response.AccountId
	session.KeyId = response.KeyId
	session.HttpForwardAddress = response.HttpForwardAddress
	session.OpenPortForIpLink = response.OpenPortForIpLink
	session.FallbackSshServerIp = response.FallbackSshServerIp
	session.FallbackSshServerPort = response.FallbackSshServerPort
	err = app.DbHandler.Save(session)

	if err != nil {
		log.Warn(err)
	}
	return response, nil
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
	session.PrintMessage(message)
	// ExitHook
	stopFunc := func() {
		log.Debug("Closing ssh connection and listeners")
		sshClient.Close()
		listener.Close()
	}
	stopFuncRef := app.StopHooks.PushBack(stopFunc)
	defer app.StopHooks.Remove(stopFuncRef)

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
			conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", session.LocalPort))
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

func Connect(key ssh.Signer, session db.Session) (*ssh.Client, chan bool, error) {
	config := &ssh.ClientConfig{
		User: "open",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(session.KeepAliveSeconds) * time.Second,
	}

	var sshClient *ssh.Client
	var err error
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

func (app *App) KillSession(port int) {
	log.Debugf("Killing session on port %d", port)

	app.DbHandler.InitDB()
	session, err2 := app.DbHandler.GetSession(port)
	if err2 != nil {
		log.Fatal(err2)
	}
	if session.ID == 0 {
		log.Fatal("Session not found.")
	}
	resp, err3 := interProcessHttpClient.Get(fmt.Sprintf("http://127.0.0.1:%d/exit", session.AppManagementPort))
	if err3 != nil {
		log.Fatalf("Could not kill session: %s", err3)
	}
	log.Debug(resp)
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

type ConnectionState interface {
	DoState()
	IsConnected() bool
}

type ConnectedState struct {
	app *App
}

func (state *ConnectedState) DoState() {
	for {
		connected := <-state.app.Connected
		log.Debugf("Connected state: got Connected:  %t", connected)
		state.app.Session.Connected = connected
		state.app.SaveState()
		if connected {
			continue
		} else {
			state.app.ConnectedState = &DisconnectedState{
				app: state.app,
			}
			go state.app.ConnectedState.DoState()
			break
		}
	}
}

func (state *ConnectedState) IsConnected() bool {
	return true
}

type DisconnectedState struct {
	app *App
}

func (state *DisconnectedState) DoState() {

	var timeoutChannel <-chan time.Time
	if state.app.ExitOnFailureTimeout > 0 {
		timeoutChannel = time.After(time.Duration(state.app.ExitOnFailureTimeout) * time.Second)
	} else {
		// Hangs forever
		timeoutChannel = make(chan time.Time, 1)
	}

	select {
	case <-timeoutChannel:
		log.Errorf("Not Connected for %d seconds, exiting.", state.app.ExitOnFailureTimeout)
		state.app.ExitCode <- EXIT_CODE_NO_CONNECTION
	case connected := <-state.app.Connected:
		log.Debugf("disconnected state: got Connected:  %t", connected)
		state.app.Session.Connected = connected
		state.app.SaveState()
		if connected {
			state.app.ConnectedState = &ConnectedState{
				app: state.app,
			}
		} else {
			log.Errorf("Should not get an update about disconnected when already in the disconnected state. This is most likely a bug.")
			state.app.ConnectedState = &DisconnectedState{
				app: state.app,
			}
		}
		go state.app.ConnectedState.DoState()
	}
}

func (state *DisconnectedState) IsConnected() bool {
	return false
}

func (app *App) MarkDisconnected() {
	if app.ConnectedState.IsConnected() {
		app.Connected <- false
	}
}

func (app *App) MarkConnected() {
	app.Connected <- true
}

func (app *App) RemoveSession(port int) {
	session, err := app.DbHandler.GetSession(port)
	if err != nil {
		log.Fatal(err)
	}
	if session.ID == 0 {
		log.Fatal("Session not found.")
	}
	err = app.DbHandler.DeleteSession(session)
	if err != nil {
		log.Fatal(err)
	} else {
		log.Infof("Session for local port %d deleted.", port)
	}
}

func (app *App) RunSelfTest() {
	app.InitFiles()
	go app.CreateTunnel()

	// sleep until the tunnel is created
	for {
		log.Infof("Waiting for the tunnel to be created")
		time.Sleep(1 * time.Second)
		if app.ConnectedState.IsConnected() {
			break
		}

	}
	// click the open-for-ip link
	log.Info("Opening the open-for-ip link")
	httpClient := GetHttpClient(app.Session.Proxy)
	if app.Session.OpenPortForIpLink != "" {
		response, err := httpClient.Get(app.Session.OpenPortForIpLink)
		if err != nil {
			log.Fatal(err)

		}
		bodyBytes, err := io.ReadAll(response.Body)

		defer response.Body.Close()
		log.Infof("Response: %s", bodyBytes)
	}

	// Test the tunnel
	log.Info("Testing the tunnel")
	response, err := httpClient.Get(fmt.Sprintf("http://" + app.Session.SshServer + ":" + strconv.Itoa(app.Session.RemotePort) + "/info"))
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		log.Fatal(err)
	}
	body := strings.Trim(string(bodyBytes), "\n")
	log.Infof("Response: %s", body)

	if body != "openport" {
		log.Fatalf("wrong response: <%s>", body)
	}
	log.Info("Tunnel is working")
}
