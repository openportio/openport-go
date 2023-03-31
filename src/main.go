package main

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
	"github.com/orandin/lumberjackrus"
	"github.com/phayes/freeport"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const VERSION = "2.1.0"
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

var OPENPORT_LOG_PATH = utils.OPENPORT_HOME + "/openport.log"

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

type OpenportApp struct {
	Session              db.Session
	stopped              bool
	stopHooks            *list.List
	dbHandler            db.DBHandler
	exitCode             chan int // Blocking channel waiting for the exit code.
	exitOnFailureTimeout int
	connected            chan bool
	connectedState       ConnectionState
}

func createApp() *OpenportApp {
	app := &OpenportApp{
		exitOnFailureTimeout: -1,
		exitCode:             make(chan int, 1),
		stopHooks:            list.New(),
		connected:            make(chan bool, 1),
	}
	app.connectedState = &DisconnectedState{app: app}
	return app
}

var httpSleeper = utils.IncrementalSleeper{
	SleepTime:        10 * time.Second,
	MaxSleepTime:     300 * time.Second,
	InitialSleepTime: 10 * time.Second,
}

func (s ServerResponseError) Error() string {
	return s.error
}

func myUsage() {
	fmt.Printf("Usage: %s (<port> | forward | list | restart-sessions | kill <port> | kill-all | register-key | help [command] | version) [arguments]\n", os.Args[0])
}

var stdOutLogHook writer.Hook
var verbose bool = false
var flagSets = make(map[string]*flag.FlagSet)

var interProcessHttpClient = http.Client{
	Timeout: 2 * time.Second,
}

var loggingReady = false

func initLogging() {
	if loggingReady {
		return
	}
	log.SetLevel(log.DebugLevel)
	log.WithField("pid", os.Getpid())
	hook, err := lumberjackrus.NewHook(
		&lumberjackrus.LogFile{
			Filename:   OPENPORT_LOG_PATH,
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
	log.SetOutput(ioutil.Discard) // Send all logs to nowhere by default

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

func main() {
	app := createApp()
	go app.run(os.Args)
	os.Exit(<-app.exitCode)
}

func (app *OpenportApp) run(args []string) {

	var port int
	var controlPort int
	var server string
	var restartOnReboot bool
	var keepAliveSeconds int
	var socksProxy string
	var remotePort string
	var daemonize bool
	var exitOnFailureTimeout int

	addVerboseFlag := func(set *flag.FlagSet) {
		set.BoolVarP(&verbose, "verbose", "v", false, "Verbose logging")
	}

	addDatabaseFlag := func(set *flag.FlagSet) {
		set.StringVar(&app.dbHandler.DbPath, "database", db.OPENPORT_DB_PATH, "Database file")
		set.MarkHidden("database")
	}
	addLegacyFlag := func(set *flag.FlagSet, name string) {
		set.String(name, "legacy", "legacy: do not use")
		set.MarkHidden(name)
	}

	addServerFlag := func(set *flag.FlagSet) {
		set.StringVar(&server, "server", DEFAULT_SERVER, "The server to connect to.")
		set.MarkHidden("server")
	}

	addSharedFlags := func(set *flag.FlagSet) {
		set.IntVar(&port, "port", -1, "The local port you want to expose.")
		set.IntVar(&port, "local-port", -1, "The local port you want to expose.")
		set.StringVar(&remotePort, "remote-port", "-1", "The remote port on the server. [openport.io:1234]")
		set.IntVar(&controlPort, "listener-port", -1, "")
		set.BoolVarP(&restartOnReboot, "restart-on-reboot", "R", false, "Restart this session when 'restart-sessions' is called (on boot for example).")
		set.IntVar(&keepAliveSeconds, "keep-alive", 120, "The interval in between keep-alive messages in seconds.")
		set.StringVar(&socksProxy, "proxy", "", "Socks5 proxy to use. Format: socks5://user:pass@host:port")
		set.BoolVarP(&daemonize, "daemonize", "d", false, "Start the app in the background.")
		set.IntVar(&exitOnFailureTimeout, "exit-on-failure-timeout", -1, "Specify in seconds if you want the app to exit if it cannot properly connect.")
		addVerboseFlag(set)
		addDatabaseFlag(set)
		addServerFlag(set)
		set.MarkHidden("listener-port")
	}

	defaultFlagSet := flag.NewFlagSet(args[0], flag.ExitOnError)
	addSharedFlags(defaultFlagSet)
	useIpLinkProtection := defaultFlagSet.String("ip-link-protection", "",
		"Let users click a secret link before they can "+
			"access this port. This overwrites the setting in your profile. choices=[True, False]")
	httpForward := defaultFlagSet.Bool("http-forward", false, "Request an http forward, so you can connect to port 80 on the server.")
	sshServer := defaultFlagSet.String("request-server", "", "The requested tunnel server")
	defaultFlagSet.MarkHidden("request-server")

	forwardTunnelFlagSet := flag.NewFlagSet("forward", flag.ExitOnError)
	addSharedFlags(forwardTunnelFlagSet)

	// Legacy flags
	addLegacyFlag(defaultFlagSet, "request-port")
	addLegacyFlag(defaultFlagSet, "request-token")
	addLegacyFlag(defaultFlagSet, "start-manager")
	addLegacyFlag(defaultFlagSet, "manager-port")

	flagSets[""] = defaultFlagSet
	flagSets["forward"] = forwardTunnelFlagSet

	versionFlagSet := flag.NewFlagSet("version", flag.ExitOnError)
	flagSets["version"] = versionFlagSet

	killFlagSet := flag.NewFlagSet("kill", flag.ExitOnError)
	addVerboseFlag(killFlagSet)
	addDatabaseFlag(killFlagSet)
	killFlagSet.IntVar(&port, "port", -1, "The local port of the session to kill.")
	flagSets["kill"] = killFlagSet

	killAllFlagSet := flag.NewFlagSet("kill-all", flag.ExitOnError)
	addVerboseFlag(killAllFlagSet)
	addDatabaseFlag(killAllFlagSet)
	flagSets["kill-all"] = killAllFlagSet

	restartSessionsFlagSet := flag.NewFlagSet("restart-sessions", flag.ExitOnError)
	addVerboseFlag(restartSessionsFlagSet)
	addDatabaseFlag(restartSessionsFlagSet)
	addServerFlag(restartSessionsFlagSet)
	restartSessionsFlagSet.BoolVarP(&daemonize, "daemonize", "d", false, "Start the app in the background.")
	flagSets["restart-sessions"] = restartSessionsFlagSet

	listFlagSet := flag.NewFlagSet("list", flag.ExitOnError)
	addVerboseFlag(listFlagSet)
	addDatabaseFlag(listFlagSet)
	flagSets["list"] = listFlagSet

	registerKeyFlagSet := flag.NewFlagSet("register-key", flag.ExitOnError)
	addVerboseFlag(registerKeyFlagSet)
	addServerFlag(registerKeyFlagSet)
	registerKeyFlagSet.StringVar(&socksProxy, "proxy", "", "Socks5 proxy to use. Format: socks5://user:pass@host:port")
	registerKeyToken := registerKeyFlagSet.String("token", "", "Token to link your machine to your account. Find this token at https://openport.io/user/keys .")
	registerKeyName := registerKeyFlagSet.String("name", "", "The name for this machine.")
	flagSets["register-key"] = registerKeyFlagSet

	flag.Usage = myUsage

	if len(args) == 1 {
		myUsage()
		app.exitCode <- EXIT_CODE_USAGE
	}

	switch args[1] {
	case "help":
		if len(args) > 2 {
			command := args[2]
			flagSet := flagSets[command]
			if flagSet == nil {
				fmt.Printf("No such command: %s\n", command)
				myUsage()
			} else {
				fmt.Printf("Usage: %s %s [arguments]\n", args[0], command)
				flagSet.PrintDefaults()
			}
		} else {
			fmt.Printf("Usage: %s (<port> | forward | list | kill | kill-all | register | help )\n", args[0])
			fmt.Printf("Default: %s <port> [arguments]\n", args[0])
			defaultFlagSet.PrintDefaults()
		}
		app.exitCode <- EXIT_CODE_HELP
	case "register-key":
		_ = registerKeyFlagSet.Parse(args[2:])
		initLogging()
		tail := registerKeyFlagSet.Args()
		if *registerKeyToken == "" {
			if len(tail) == 0 {
				log.Fatalf("--token is required")
			} else {
				registerKeyToken = &tail[0]
			}
		}
		app.registerKey(*registerKeyToken, *registerKeyName, socksProxy, server)
	case "version":
		fmt.Println(VERSION)
	case "kill":
		_ = killFlagSet.Parse(args[2:])
		initLogging()
		utils.EnsureHomeFolderExists()
		tail := killFlagSet.Args()
		var err error
		if port == -1 {
			if len(tail) == 0 {
				log.Fatal("port missing")
			} else {
				port, err = strconv.Atoi(tail[0])
				if err != nil {
					log.Warnf("failing: %s %s", tail, err)
					killFlagSet.PrintDefaults()
					app.exitCode <- EXIT_CODE_INVALID_ARGUMENT
				}
			}
		}

		app.dbHandler.InitDB()
		session, err2 := app.dbHandler.GetSession(port)
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
	case "kill-all":
		_ = killAllFlagSet.Parse(args[2:])
		initLogging()
		utils.EnsureHomeFolderExists()
		app.dbHandler.InitDB()
		app.killAll()
	case "restart-sessions":
		_ = restartSessionsFlagSet.Parse(args[2:])
		initLogging()
		if daemonize {
			app.startDaemon(args)
		} else {
			utils.EnsureHomeFolderExists()
			app.restartSessions(args, server, app.dbHandler.DbPath)
		}
	case "list":
		_ = listFlagSet.Parse(args[2:])
		initLogging()
		utils.EnsureHomeFolderExists()
		app.dbHandler.InitDB()
		app.listSessions()
		app.exitCode <- EXIT_CODE_LIST
	default:
		forwardTunnel := args[1] == "forward"
		var remotePortInt int
		//var sshServer string = "openport.io"
		var err error
		if forwardTunnel {
			_ = defaultFlagSet.Parse(args[2:])
			remotePortInt, err = strconv.Atoi(remotePort)
			if err != nil {
				parsed, err := url.Parse(remotePort)
				if err != nil {
					log.Fatalf("invalid format for remote-port (host:port) : %s %s", remotePort, err)
				}
				//sshServer = parsed.Host
				parsedPort := parsed.Port()
				if remotePort == "" {
					log.Fatalf("Port missing in remote-port arg: %s", remotePort)
				}
				remotePortInt, _ = strconv.Atoi(parsedPort)
				//} else {
				//	parsed, err := url.Parse(server)
				//	if err != nil {
				//		log.Fatalf("invalid format for server : %s %s", server, err)
				//	}
				//sshServer = parsed.Host
			}

		} else {
			_ = defaultFlagSet.Parse(args[1:])
			remotePortInt, err = strconv.Atoi(remotePort)
			if err != nil {
				log.Fatalf("Remote port needs to be an integer: %s %s", remotePort, err)
			}
		}
		initLogging()
		app.exitOnFailureTimeout = exitOnFailureTimeout

		tail := defaultFlagSet.Args()
		if port == -1 {
			if len(tail) == 0 {
				if !forwardTunnel {
					myUsage()
					app.exitCode <- EXIT_CODE_INVALID_ARGUMENT
				}
			} else {
				var err error
				port, err = strconv.Atoi(tail[0])
				if err != nil {
					log.Warnf("failing: %s %s", tail, err)
					defaultFlagSet.PrintDefaults()
					app.exitCode <- EXIT_CODE_INVALID_ARGUMENT
				}
			}
		}

		if daemonize {
			app.startDaemon(args)
			return
		}

		app.Session = db.Session{
			LocalPort:           port,
			UseIpLinkProtection: *useIpLinkProtection,
			HttpForward:         *httpForward,
			Server:              server,
			KeepAliveSeconds:    keepAliveSeconds,
			Proxy:               socksProxy,
			Active:              true,
			ForwardTunnel:       forwardTunnel,
			RemotePort:          remotePortInt,
			SshServer:           *sshServer,
		}
		controlPort := app.startControlServer(controlPort)
		app.Session.AppManagementPort = controlPort

		if restartOnReboot {
			app.Session.RestartCommand = strings.Join(args[1:], " ")
		}
		app.createTunnel()
	}
	app.exitCode <- 0
}

func (app *OpenportApp) startDaemon(args []string) {
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
		app.exitCode <- EXIT_CODE_DAEMONIZED_ERROR
	} else {
		log.Info("Process started in background")
		app.exitCode <- EXIT_CODE_DAEMONIZED_OK
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

func (app *OpenportApp) registerKey(keyBindingToken string, name string, proxy string, server string) {
	utils.EnsureHomeFolderExists()
	publicKey, _, err := utils.EnsureKeysExist()
	if err != nil {
		log.Fatalf("Could not get key: %s", err)
	}

	httpClient := getHttpClient(proxy)
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
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Body error: %s", err)
	}
	log.Debugf(string(body))
	var jsonData = []byte(body)
	response := RegisterKeyResponse{}
	jsonErr := json.Unmarshal(jsonData, &response)
	if jsonErr != nil {
		log.Fatalf("Json Decode error: %s", err)
	}
	if response.Status != "ok" {
		log.Fatalf("Could not register key: %s", response.Error)
		app.exitCode <- EXIT_CODE_KEY_REGISTERED_FAILED
	} else {
		log.Info("key successfully registered")
		app.exitCode <- EXIT_CODE_KEY_REGISTERED_OK
	}
}

func sessionIsLive(session db.Session) bool {
	url := fmt.Sprintf("http://127.0.0.1:%d/info", session.AppManagementPort)
	log.Debug(url)
	resp, err := interProcessHttpClient.Get(url)
	if err != nil {
		log.Debugf("Error while requesting %s: %s", url, err)
		return false
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Debugf("Error while getting the body of %s: %s", url, err)
		return false
	}
	log.Debugf("Got response on url %s: %s", url, body)
	return string(body)[:8] == "openport"
}

func (app *OpenportApp) listSessions() {
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
	sessions, err := app.dbHandler.GetAllActive()
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
			sessionIsLive(session),
			session.RestartCommand != "",
			session.ForwardTunnel,
		})
	}
	tw.Render()
}

func (app *OpenportApp) restartSessions(args []string, server string, database string) {
	log.Debug("Restarting Sessions")
	sessions, err := app.dbHandler.GetSessionsToRestart()
	if err != nil {
		panic(err)
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
		if database != db.OPENPORT_DB_PATH {
			restartCommand = append(restartCommand, "--database", database)
		}
		log.Infof("Running command %s with args %s", args[0], restartCommand)
		cmd := exec.Command(args[0], restartCommand...)
		err = cmd.Start()
		if err != nil {
			log.Warn(err)
		}
	}

	if runtime.GOOS == "windows" {
		return
	}

	currentUser, err := user.Current()
	if err != nil {
		log.Debug(err)
	}
	username := currentUser.Username
	if username != "root" {
		return
	}

	buf, err := ioutil.ReadFile(USER_CONFIG_FILE)
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
				command := []string{"-u", username, "-H", args[0], "restart-sessions"}
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

func (app *OpenportApp) killAll() {
	sessions, err := app.dbHandler.GetAllActive()
	if err != nil {
		panic(err)
	}
	for _, session := range sessions {
		resp, err3 := interProcessHttpClient.Get(fmt.Sprintf("http://127.0.0.1:%d/exit", session.AppManagementPort))
		if err3 != nil {
			session.Active = false
			app.dbHandler.Save(&session)
			log.Warnf("Could not kill session for local port %d: %s", session.LocalPort, err3)
		} else {
			log.Infof("Killed session for local port %d", session.LocalPort)
			log.Debug(resp)
		}
	}
}

func (app *OpenportApp) stopSession(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Ok")
	app.Stop(EXIT_CODE_REMOTE_STOP)

	// TODO: stop session from restarting.  Done?
	// TODO: Force flag
}

func (app *OpenportApp) infoRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "openport")
}

func (app *OpenportApp) startControlServer(controlPort int) int {
	if controlPort <= 0 {
		var err error
		controlPort, err = freeport.GetFreePort()
		if err != nil {
			log.Fatalf("Could not start control server: %s", err)
		}
	}
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/exit", app.stopSession)
	router.HandleFunc("/info", app.infoRequest)
	log.Debugf("Listening for control on port %d", controlPort)
	go http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", controlPort), router)
	return controlPort
}

func handleSignals(app *OpenportApp) {
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

func checkUsernameInConfigFile() {

	if runtime.GOOS == "windows" {
		return
	}

	currentUser, err := user.Current()
	if err != nil {
		log.Debug(err)
	}
	username := currentUser.Username
	if username == "root" {
		return
	}

	buf, err := ioutil.ReadFile(USER_CONFIG_FILE)
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

func (app *OpenportApp) createTunnel() {
	if app.Session.RestartCommand != "" {
		checkUsernameInConfigFile()
	}
	handleSignals(app)
	publicKey, key, err := utils.EnsureKeysExist()
	if err != nil {
		log.Fatalf("Error during fetching/creating key: %s", err)
	}
	app.dbHandler.InitDB()
	dbSession := app.dbHandler.EnrichSessionWithHistory(&app.Session)
	if dbSession.ID > 0 && sessionIsLive(dbSession) {
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
	err = app.dbHandler.Save(&app.Session)
	if err != nil {
		log.Warnf("error saving session: %s", err)
	}
	defer app.setInactive(&app.Session)

	go app.connectedState.DoState()

	for {
		response, err2 := app.requestPortForward(&app.Session, publicKey)
		if err2 != nil {
			log.Error(err2)
			log.Infof("Will sleep for %f seconds", httpSleeper.SleepTime.Seconds())
			httpSleeper.Sleep()
			continue
		}
		httpSleeper.Reset()

		var err error
		if app.Session.ForwardTunnel {
			err = app.startForwardTunnel(key, app.Session, response.Message)
		} else {

			//// TMP!!!!
			//wsClient := ws_channel.NewWSClient()
			//
			//server := strings.Replace(app.Session.Server, "https://", "wss://", 1)
			//err = wsClient.Connect(server)
			//if err != nil {
			//	log.Fatalf("Could not connect to server %s: %s", server, err)
			//}
			//err = wsClient.StartReverseTunnel(app.Session.SessionToken, app.Session.LocalPort, app.Session.RemotePort)
			//
			err = app.startReverseTunnel(key, app.Session, response.Message)
		}
		if !app.stopped {
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

func (app *OpenportApp) Stop(exitCode int) {
	if app.stopped {
		return
	}
	app.stopped = true
	log.Debug("Stopping app")
	for i := app.stopHooks.Front(); i != nil; i = i.Next() {
		i.Value.(func())()
	}
	app.exitCode <- exitCode
	//app.setInactive(app.Session)
}

func getHttpClient(proxy string) http.Client {
	if proxy == "" {
		return http.Client{}
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
			Timeout:   30 * time.Second,
		}
	}
}

func (app *OpenportApp) requestPortForward(session *db.Session, publicKey []byte) (PortResponse, error) {
	httpClient := getHttpClient(session.Proxy)

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

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Debugf("http error")
		log.Warn(err)
		return PortResponse{}, err
	}
	log.Debugf(string(body))
	var jsonData = []byte(body)
	response := PortResponse{}
	jsonErr := json.Unmarshal(jsonData, &response)
	if jsonErr != nil {
		log.Warnf("json error: %s", err)
		return PortResponse{}, jsonErr
	}

	if response.Error != "" {
		if response.FatalError {
			log.Infof("Stopping session on request of server: %s", response.Error)
			app.setInactive(session)
			app.exitCode <- EXIT_CODE_FATAL_SESSION_ERROR
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
	err = app.dbHandler.Save(session)

	if err != nil {
		log.Warn(err)
	}
	return response, nil
}

func (app *OpenportApp) startReverseTunnel(key ssh.Signer, session db.Session, message string) error {
	sshClient, keepAliveDone, err2 := connect(key, session)
	if err2 != nil {
		return err2
	}
	defer func() { keepAliveDone <- true }()

	log.Debugf("connected")
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
	if session.HttpForward {
		log.Infof("Now forwarding remote address %s to localhost", session.HttpForwardAddress)
	} else {
		log.Infof("Now forwarding remote port %s:%d to localhost:%d", session.SshServer, session.RemotePort, session.LocalPort)
	}

	// ExitHook
	stopFunc := func() {
		log.Debug("Closing ssh connection and listeners")
		sshClient.Close()
		listener.Close()
	}
	stopFuncRef := app.stopHooks.PushBack(stopFunc)
	defer app.stopHooks.Remove(stopFuncRef)

	log.Infof(message)
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

func connect(key ssh.Signer, session db.Session) (*ssh.Client, chan bool, error) {
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
		// create a socks5 dialer
		u, err := url.Parse(session.Proxy)
		if err != nil {
			log.Fatalf("Could not parse proxy server: %s", err)
		}
		var proxyAuth *proxy.Auth = nil
		proxyPassword, proxyPasswordSet := u.User.Password()
		if proxyPasswordSet {
			proxyAuth = &proxy.Auth{
				User:     u.User.Username(),
				Password: proxyPassword,
			}
		}
		log.Debug(u)
		var proxyPort = u.Port()
		if proxyPort == "" {
			proxyPort = "1080"
		}
		proxyServer := fmt.Sprintf("%s:%s", u.Hostname(), proxyPort)
		log.Debug("proxy Server: ", proxyServer)

		proxyDialer, err := proxy.SOCKS5("tcp", proxyServer, proxyAuth, proxy.Direct)
		if err != nil {
			log.Warnf("can't connect to the proxy: %s", err)
			return nil, nil, err
		}
		conn, err := proxyDialer.Dial("tcp", sshAddress)
		if err != nil {
			log.Debugf("%s -> falling back to %s", err, fallbackSshAddress)
			sshAddress = fallbackSshAddress
			conn, err = proxyDialer.Dial("tcp", sshAddress)
			if err != nil {
				return nil, nil, err
			}
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
	go keepAlive(sshClient, time.Duration(int64(session.KeepAliveSeconds)*int64(time.Second)), keepAliveDone)
	return sshClient, keepAliveDone, nil
}

func keepAlive(cl *ssh.Client, keepAliveInterval time.Duration, done <-chan bool) {
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

func (app *OpenportApp) startForwardTunnel(key ssh.Signer, session db.Session, msg string) error {
	sshClient, keepAliveDone, err2 := connect(key, session)
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
	stopFuncRef := app.stopHooks.PushBack(stopFunc)
	defer app.stopHooks.Remove(stopFuncRef)

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

func (app *OpenportApp) setInactive(session *db.Session) {
	session.Active = false
	app.dbHandler.Save(session)
}

type ConnectionState interface {
	DoState()
	IsConnected() bool
}

type ConnectedState struct {
	app *OpenportApp
}

func (state *ConnectedState) DoState() {
	for {
		connected := <-state.app.connected
		log.Debugf("connected state: got connected:  %t", connected)
		if connected {
			continue
		} else {
			state.app.connectedState = &DisconnectedState{
				app: state.app,
			}
			go state.app.connectedState.DoState()
			break
		}
	}
}

func (state *ConnectedState) IsConnected() bool {
	return true
}

type DisconnectedState struct {
	app *OpenportApp
}

func (state *DisconnectedState) DoState() {

	var timeoutChannel <-chan time.Time
	if state.app.exitOnFailureTimeout > 0 {
		timeoutChannel = time.After(time.Duration(state.app.exitOnFailureTimeout) * time.Second)
	} else {
		// Hangs forever
		timeoutChannel = make(chan time.Time, 1)
	}

	select {
	case <-timeoutChannel:
		log.Errorf("Not connected for %d seconds, exiting.", state.app.exitOnFailureTimeout)
		state.app.exitCode <- EXIT_CODE_NO_CONNECTION
	case connected := <-state.app.connected:
		log.Debugf("disconnected state: got connected:  %t", connected)
		if connected {
			state.app.connectedState = &ConnectedState{
				app: state.app,
			}
		} else {
			log.Errorf("Should not get an update about disconnected when already in the disconnected state. This is most likely a bug.")
			state.app.connectedState = &DisconnectedState{
				app: state.app,
			}
		}
		go state.app.connectedState.DoState()
	}
}

func (state *DisconnectedState) IsConnected() bool {
	return false
}

func (app *OpenportApp) MarkDisconnected() {
	if app.connectedState.IsConnected() {
		app.connected <- false
	}
}

func (app *OpenportApp) MarkConnected() {
	app.connected <- true
}
