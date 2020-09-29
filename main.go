package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jedib0t/go-pretty/table"
	"github.com/jedib0t/go-pretty/text"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
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

const VERSION = "2.0.2"

var HOMEDIR = getHomeDir()

var OPENPORT_HOME = HOMEDIR + "/.openport"
var OPENPORT_PRIVATE_KEY_PATH = OPENPORT_HOME + "/id_rsa"
var OPENPORT_PUBLIC_KEY_PATH = OPENPORT_HOME + "/id_rsa.pub"
var OPENPORT_DB_PATH = OPENPORT_HOME + "/openport.db"
var OPENPORT_LOG_PATH = OPENPORT_HOME + "/openport.log"

var SSH_PRIVATE_KEY_PATH = HOMEDIR + "/.ssh/id_rsa"
var SSH_PUBLIC_KEY_PATH = HOMEDIR + "/.ssh/id_rsa.pub"

var USER_CONFIG_FILE = "/etc/openport/users.conf"

func getHomeDir() string {
	currentUser, err := user.Current()
	if err != nil {
		log.Warn(err)
		return "/root"
	} else {
		return currentUser.HomeDir
	}
}

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

func (s ServerResponseError) Error() string {
	return s.error
}

func myUsage() {
	fmt.Printf("Usage: %s (<port> | forward | list | restart-sessions | kill <port> | kill-all | register | help [command] | version) [arguments]\n", os.Args[0])
}

var stdOutLogHook writer.Hook
var verbose bool = false
var flagSets = make(map[string]*flag.FlagSet)

func initLogging() {
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
}

func main() {
	var port int
	var controlPort int
	var server string
	var restartOnReboot bool
	var keepAliveSeconds int
	var socksProxy string
	var remotePort string
	var daemonize bool

	addVerboseFlag := func(set *flag.FlagSet) {
		set.BoolVarP(&verbose, "verbose", "v", false, "Verbose logging")
	}

	addDatabaseFlag := func(set *flag.FlagSet) {
		set.StringVar(&dbPath, "database", OPENPORT_DB_PATH, "Database file")
		set.MarkHidden("database")
	}

	addServerFlag := func(set *flag.FlagSet) {
		set.StringVar(&server, "server", "https://openport.io", "The server to connect to.")
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
		addVerboseFlag(set)
		addDatabaseFlag(set)
		addServerFlag(set)
		set.MarkHidden("listener-port")
	}

	defaultFlagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	addSharedFlags(defaultFlagSet)
	useIpLinkProtection := defaultFlagSet.String("ip-link-protection", "",
		"Lets users click a secret link before they can "+
			"access this port. This overwrites the setting in your profile. choices=[True, False]")
	httpForward := defaultFlagSet.Bool("http-forward", false, "Request an http forward, so you can connect to port 80 on the server.")
	forwardTunnelFlagSet := flag.NewFlagSet("forward", flag.ExitOnError)
	addSharedFlags(forwardTunnelFlagSet)
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
	restartSessionsFlagSet.BoolVarP(&daemonize, "daemonize", "d", false, "Start the app in the background.")
	flagSets["restart-sessions"] = forwardTunnelFlagSet

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

	if len(os.Args) == 1 {
		myUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "help":
		if len(os.Args) > 2 {
			command := os.Args[2]
			flagSet := flagSets[command]
			if flagSet == nil {
				fmt.Printf("No such command: %s\n", command)
				myUsage()
			} else {
				fmt.Printf("Usage: %s %s [arguments]\n", os.Args[0], command)
				flagSet.PrintDefaults()
			}
		} else {
			fmt.Printf("Usage: %s (<port> | forward | list | kill | kill-all | register | help )\n", os.Args[0])
			fmt.Printf("Default: %s <port> [arguments]\n", os.Args[0])
			defaultFlagSet.PrintDefaults()
		}
		os.Exit(0)
	case "register-key":
		_ = registerKeyFlagSet.Parse(os.Args[2:])
		initLogging()
		tail := registerKeyFlagSet.Args()
		if *registerKeyToken == "" {
			if len(tail) == 0 {
				log.Fatalf("--token is required")
			} else {
				registerKeyToken = &tail[0]
			}
		}
		registerKey(*registerKeyToken, *registerKeyName, socksProxy, server)
	case "version":
		fmt.Println(VERSION)
	case "kill":
		_ = killFlagSet.Parse(os.Args[2:])
		initLogging()
		ensureHomeFolderExists()
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
					os.Exit(3)
				}
			}
		}

		initDB()
		session, err2 := getSession(port)
		if err2 != nil {
			log.Fatal(err2)
		}
		if session.ID == 0 {
			log.Fatal("Session not found.")
		}
		resp, err3 := http.Get(fmt.Sprintf("http://127.0.0.1:%d/exit", session.AppManagementPort))
		if err3 != nil {
			log.Fatalf("Could not kill session: %s", err3)
		}
		log.Debug(resp)
	case "kill-all":
		_ = killAllFlagSet.Parse(os.Args[2:])
		initLogging()
		ensureHomeFolderExists()
		initDB()
		killAll()
	case "restart-sessions":
		_ = restartSessionsFlagSet.Parse(os.Args[2:])
		initLogging()
		if daemonize {
			startDaemon()
			os.Exit(0)
		}
		ensureHomeFolderExists()
		restartSessions()
	case "list":
		_ = listFlagSet.Parse(os.Args[2:])
		initLogging()
		ensureHomeFolderExists()
		initDB()
		listSessions()
	default:
		forwardTunnel := os.Args[1] == "forward"
		var remotePortInt int
		var sshServer string = "openport.io"
		var err error
		if forwardTunnel {
			_ = defaultFlagSet.Parse(os.Args[2:])
			remotePortInt, err = strconv.Atoi(remotePort)
			if err != nil {
				parsed, err := url.Parse(remotePort)
				if err != nil {
					log.Fatalf("invalid format for remote-port (host:port) : %s %s", remotePort, err)
				}
				sshServer = parsed.Host
				parsedPort := parsed.Port()
				if remotePort == "" {
					log.Fatalf("Port missing in remote-port arg: %s", remotePort)
				}
				remotePortInt, _ = strconv.Atoi(parsedPort)
			} else {
				parsed, err := url.Parse(server)
				if err != nil {
					log.Fatalf("invalid format for server : %s %s", server, err)
				}
				sshServer = parsed.Host
			}

		} else {
			_ = defaultFlagSet.Parse(os.Args[1:])
			remotePortInt, err = strconv.Atoi(remotePort)
			if err != nil {
				log.Fatalf("Remote port needs to be an integer: %s %s", remotePort, err)
			}
		}

		initLogging()
		tail := defaultFlagSet.Args()
		if port == -1 {
			if len(tail) == 0 {
				if !forwardTunnel {
					myUsage()
					os.Exit(2)
				}
			} else {
				var err error
				port, err = strconv.Atoi(tail[0])
				if err != nil {
					log.Warnf("failing: %s %s", tail, err)
					defaultFlagSet.PrintDefaults()
					os.Exit(3)
				}
			}
		}

		if daemonize {
			startDaemon()
			os.Exit(0)
		}

		session := Session{
			LocalPort:           port,
			UseIpLinkProtection: *useIpLinkProtection,
			HttpForward:         *httpForward,
			Server:              server,
			KeepAliveSeconds:    keepAliveSeconds,
			Proxy:               socksProxy,
			Active:              true,
			ForwardTunnel:       forwardTunnel,
			RemotePort:          remotePortInt,
			SshServer:           sshServer,
		}
		controlPort := startControlServer(controlPort)
		session.AppManagementPort = controlPort

		if restartOnReboot {
			session.RestartCommand = strings.Join(os.Args[1:], " ")
		}
		createTunnel(session)
	}
}

func startDaemon() {
	loc := Find(os.Args, "-d")
	var command []string
	if loc < 0 {
		loc = Find(os.Args, "--daemonize")
	}
	if loc >= 0 && len(os.Args) > 1 {
		command = append(os.Args[:loc], os.Args[loc+1:]...)
	} else {
		log.Debugf("%s", os.Args)
		log.Fatalf("Use -d or --daemonize to start in the background")
	}
	cmd := exec.Command(command[0], command[1:]...)
	err := cmd.Start()
	if err != nil {
		log.Fatal(err)
	} else {
		log.Info("Process started in background")
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

func registerKey(keyBindingToken string, name string, proxy string, server string) {
	ensureHomeFolderExists()
	publicKey, _, err := ensureKeysExist()
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
	} else {
		log.Info("key successfully registered")
	}
}

func sessionIsLive(session Session) bool {
	url := fmt.Sprintf("http://127.0.0.1:%d/info", session.AppManagementPort)
	log.Debug(url)
	resp, err := http.Get(url) // TODO: timeout
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

func listSessions() {
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
	sessions, err := getAllActive()
	if err != nil {
		panic(err)
	}
	for _, session := range sessions {
		log.Debugf("adding row %s", session)
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

func createKeys() ([]byte, ssh.Signer, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	// generate and write private key as PEM
	privateKeyFile, err := os.Create(OPENPORT_PRIVATE_KEY_PATH)
	if err != nil {
		return nil, nil, err
	}
	defer privateKeyFile.Close()
	privateKeyPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}
	if err := pem.Encode(privateKeyFile, privateKeyPEM); err != nil {
		return nil, nil, err
	}

	// generate and write public key
	pub, err := ssh.NewPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	err = ioutil.WriteFile(OPENPORT_PUBLIC_KEY_PATH, ssh.MarshalAuthorizedKey(pub), 0655)
	if err != nil {
		return nil, nil, err
	}
	return readKeys()
}

func readKeys() ([]byte, ssh.Signer, error) {
	publicKey, err := ioutil.ReadFile(OPENPORT_PUBLIC_KEY_PATH)
	if err != nil {
		return nil, nil, err
	}

	buf, err := ioutil.ReadFile(OPENPORT_PRIVATE_KEY_PATH)
	if err != nil {
		return nil, nil, err
	}

	key, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		return nil, nil, err
	}
	log.Debugf(string(publicKey))
	return publicKey, key, nil
}

func ensureHomeFolderExists() {
	err := os.Mkdir(OPENPORT_HOME, 0600)
	if err != nil {
		if !os.IsExist(err) {
			log.Fatal(err)
		}
		log.Debug(err)
	} else {
		log.Debugf("Created directory %s", OPENPORT_HOME)
	}
}

func ensureKeysExist() ([]byte, ssh.Signer, error) {
	ensureHomeFolderExists()
	if _, err := os.Stat(OPENPORT_PRIVATE_KEY_PATH); err == nil {
		// File exists
		return readKeys()
	} else {
		if _, err := os.Stat(SSH_PRIVATE_KEY_PATH); err == nil {
			// ssh-key exists
			buf, err := ioutil.ReadFile(SSH_PRIVATE_KEY_PATH)
			if err != nil {
				log.Warn(err)
				return createKeys()
			}

			block, rest := pem.Decode(buf)
			if len(rest) > 0 {
				log.Debugf("Extra data included in key, creating new keys.")
				return createKeys()
			} else {
				if x509.IsEncryptedPEMBlock(block) {
					log.Debugf("Encrypted key, creating new keys.")
					return createKeys()
				} else {
					log.Debugf("Usable keys in %s, copying to %s", SSH_PUBLIC_KEY_PATH, OPENPORT_PUBLIC_KEY_PATH)
					err = ioutil.WriteFile(OPENPORT_PRIVATE_KEY_PATH, buf, 0600)
					if err != nil {
						log.Warn(err)
						return createKeys()
					}

					pubBuf, err := ioutil.ReadFile(SSH_PUBLIC_KEY_PATH)
					err = ioutil.WriteFile(OPENPORT_PUBLIC_KEY_PATH, pubBuf, 0600)
					if err != nil {
						log.Warn(err)
						return createKeys()
					}
					return readKeys()
				}
			}
		} else {
			return createKeys()
		}
	}
}

func restartSessions() {
	sessions, err := getAllActive()
	if err != nil {
		panic(err)
	}
	for _, session := range sessions {
		if session.RestartCommand != "" {
			log.Debugf("Running command %s with args %s", os.Args[0], session.RestartCommand)
			cmd := exec.Command(os.Args[0], strings.Split(session.RestartCommand, " ")...)
			err = cmd.Start()
			if err != nil {
				log.Warn(err)
			}
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
	if err == nil {
		log.Warnf("Could not read file %s: %s", USER_CONFIG_FILE, err)
	} else {
		users := strings.Split(string(buf), "\n")

		for _, username := range users {
			username = strings.TrimSpace(strings.Split(username, "#")[0])
			if username == "root" {
				continue
			}
			if username != "" {
				command := []string{"-u", username, "-H", os.Args[0], "restart-sessions"}
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

func killAll() {
	sessions, err := getAllActive()
	if err != nil {
		panic(err)
	}
	for _, session := range sessions {
		resp, err3 := http.Get(fmt.Sprintf("http://127.0.0.1:%d/exit", session.AppManagementPort))
		if err3 != nil {
			session.Active = false
			save(session)
			log.Warnf("Could not kill session: %s", err3)
		} else {
			log.Debug(resp)
		}
	}
}

func stopSession(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Ok")
	go os.Exit(5)
}

func infoRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "openport")
}

func startControlServer(controlPort int) int {
	if controlPort <= 0 {
		var err error
		controlPort, err = freeport.GetFreePort()
		if err != nil {
			log.Fatalf("Could not start control server: %s", err)
		}
	}
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/exit", stopSession)
	router.HandleFunc("/info", infoRequest)
	log.Debugf("Listening for control on port %d", controlPort)
	go http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", controlPort), router)
	return controlPort
}

func portIsAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Warnf("Can't listen on port %q: %s", port, err)
		return false
	}
	_ = ln.Close()
	return true
}

func enrichSessionWithHistory(session *Session) Session {
	if session.ForwardTunnel {
		if session.LocalPort < 0 {
			dbSession, err := getForwardSession(session.RemotePort, session.SshServer)
			if err != nil {
				log.Errorf("error fetching session %s", err)
			} else {
				if dbSession.LocalPort > 0 && portIsAvailable(dbSession.LocalPort) {
					session.LocalPort = dbSession.LocalPort
				}
			}
			return dbSession
		}
	} else {
		dbSession, err := getSession(session.LocalPort)
		if err != nil {
			log.Errorf("error fetching session %s", err)
		} else {
			if dbSession.RestartCommand != "" && session.RestartCommand == "" {
				log.Infof("Port forward for port %d that would be restarted on reboot will not be restarted anymore.", session.LocalPort)
			}

			if session.RemotePort < 0 || session.RemotePort == dbSession.RemotePort {
				session.SessionToken = dbSession.SessionToken
				session.RemotePort = dbSession.RemotePort
			}
		}
		return dbSession
	}
	return Session{}
}

func handleSignals(session Session) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT)
	restartMessage := ""
	if session.RestartCommand != "" {
		restartMessage = " Session will not be restarted by \"restart-sessions\""
	}

	go func() {
		sig := <-sigs
		log.Infof("Got signal %d. Exiting.%s", sig, restartMessage)
		setInactive(session)
		os.Exit(0)
	}()
}

func checkUsernameInConfigFile(session Session) {
	if session.RestartCommand == "" {
		return
	}
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

func createTunnel(session Session) {
	checkUsernameInConfigFile(session)
	handleSignals(session)
	publicKey, key, err := ensureKeysExist()
	if err != nil {
		log.Fatalf("Error during fetching/creating key: %s", err)
	}
	initDB()
	dbSession := enrichSessionWithHistory(&session)
	if dbSession.ID > 0 && sessionIsLive(dbSession) {
		log.Fatalf("Port forward already running for port %d with PID %d",
			dbSession.LocalPort, dbSession.Pid)
	}
	if session.ForwardTunnel && session.LocalPort < 0 {
		session.LocalPort, err = freeport.GetFreePort()
		if err != nil {
			log.Fatalf("error getting free port: %s", err)
		}
	}
	session.Active = true
	err = save(session)
	if err != nil {
		log.Warnf("error saving session: %s", err)
	}
	defer setInactive(session)
	for {
		response, err2 := requestPortForward(&session, publicKey)
		if err2 != nil {
			log.Error(err2)
			time.Sleep(10 * time.Second)
			continue
		}

		var err error
		if session.ForwardTunnel {
			err = startForwardTunnel(key, session, response.Message)
		} else {
			err = startReverseTunnel(key, session, response.Message)
		}
		log.Warn(err)
		if session.AutomaticRestart {
			time.Sleep(10 * time.Second)
		}
		session.AutomaticRestart = true
	}
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
		}
	}
}

func requestPortForward(session *Session, publicKey []byte) (PortResponse, error) {
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
		"ssh_server":            {session.SshServer},
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
			setInactive(*session)
			os.Exit(0)
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
	err = save(*session)

	if err != nil {
		log.Warn(err)
	}
	return response, nil
}
func startReverseTunnel(key ssh.Signer, session Session, message string) error {
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
	log.Infof(message)

	for {
		// Wait for a connection.
		conn, err := listener.Accept()
		if err != nil {
			log.Errorf("Could not accept connection: %s", err)
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

func connect(key ssh.Signer, session Session) (*ssh.Client, chan bool, error) {
	config := &ssh.ClientConfig{
		User: "open",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	var sshClient *ssh.Client
	var err error
	sshAddress := fmt.Sprintf("%s:%d", session.SshServer, 22)
	fallbackSshAddres := fmt.Sprintf("%s:%d", session.FallbackSshServerIp, session.FallbackSshServerPort)
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
			log.Debugf("%s -> falling back to %s", err, fallbackSshAddres)
			sshAddress = fallbackSshAddres
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
			log.Debugf("%s -> falling back to %s", err, fallbackSshAddres)
			sshAddress = fallbackSshAddres
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
				log.Warnf("failed to send keep alive", err)
			}
		case <-done:
			return
		}
	}
}

func startForwardTunnel(key ssh.Signer, session Session, msg string) error {
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

	log.Info(msg)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		log.Debugf("Incoming request on forward tunnel from %s", conn.RemoteAddr())
		go handleRequestOnForwardTunnel(sshClient, conn, session)
	}
}

func handleRequestOnForwardTunnel(sshClient *ssh.Client, localConn net.Conn, session Session) {
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

func setInactive(session Session) {
	session.Active = false
	save(session)
}

//////////////////////
// DBHandler //TODO: move to its own file
//////////////////////
var dbPath string

type Session struct {
	// gorm.Model
	ID           int64 `gorm:"AUTO_INCREMENT;PRIMARY_KEY"`
	Server       string
	SessionToken string

	SshServer      string
	RemotePort     int
	LocalPort      int
	Pid            int
	Active         bool
	RestartCommand string

	AccountId          int
	KeyId              int
	HttpForward        bool
	HttpForwardAddress string

	AppManagementPort   int
	OpenPortForIpLink   string
	UseIpLinkProtection string

	KeepAliveSeconds int
	Proxy            string
	ForwardTunnel    bool `sql:"default:false"`

	FallbackSshServerIp   string `gorm:"-"`
	FallbackSshServerPort int    `gorm:"-"`
	AutomaticRestart      bool   `gorm:"-"`
}

func initDB() {
	log.Debugf("db path: %s", dbPath)
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		log.Panicf("failed to connect database: %s", err)
	}
	defer db.Close()

	// Migrate the schema
	db.AutoMigrate(&Session{})
	log.Debugf("db created")
}

func getForwardSession(remote_port int, ssh_server string) (Session, error) {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var session Session
	db.First(&session, "remote_port = ? and ssh_server = ? and forward_tunnel = ?", remote_port, ssh_server, true)
	if db.Error != nil {
		return session, db.Error
	}
	return session, nil
}

func getSession(local_port int) (Session, error) {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var session Session
	db.First(&session, "local_port = ? and forward_tunnel = ?", local_port, false)
	if db.Error != nil {
		return session, db.Error
	}
	return session, nil
}

func save(session Session) error {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var existingSession Session
	if session.ForwardTunnel {
		existingSession, err = getForwardSession(session.RemotePort, session.SshServer)
	} else {
		existingSession, err = getSession(session.LocalPort)
	}
	if err == nil {
		session.ID = existingSession.ID
	} else {
		return err
	}
	db.Save(&session)
	return db.Error
}

func getAllActive() ([]Session, error) {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var sessions []Session
	db.Where("active = 1").Find(&sessions)
	return sessions, db.Error
}
