package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/gorilla/mux"
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
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const VERSION = "2.0.0"

var HOMEDIR = getHomeDir()

var OPENPORT_HOME = HOMEDIR + "/.openport"
var OPENPORT_PRIVATE_KEY_PATH = OPENPORT_HOME + "/id_rsa"
var OPENPORT_PUBLIC_KEY_PATH = OPENPORT_HOME + "/id_rsa.pub"
var OPENPORT_DB_PATH = OPENPORT_HOME + "/openport.db"
var OPENPORT_LOG_PATH = OPENPORT_HOME + "/openport.log"

var SSH_PRIVATE_KEY_PATH = HOMEDIR + "/.ssh/id_rsa"
var SSH_PUBLIC_KEY_PATH = HOMEDIR + "/.ssh/id_rsa.pub"

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
	FatalError            bool    `json:"key_id"`
}

func myUsage() {
	fmt.Printf("Usage: %s [OPTIONS] argument ...\n", os.Args[0])
	flag.PrintDefaults()
}

var stdOutLogHook writer.Hook
var verbose bool

func initLogging() {
	log.SetLevel(log.DebugLevel)
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
	defaultFlagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	var port int
	defaultFlagSet.IntVar(&port, "port", -1, "The local port you want to openport.")

	defaultFlagSet.IntVar(&port, "local-port", -1, "The local port you want to openport.")
	controlPort := defaultFlagSet.Int("listener-port", -1, "")
	server := defaultFlagSet.String("server", "https://openport.io", "The server to connect to")
	defaultFlagSet.BoolVar(&verbose, "verbose", false, "Verbose logging")
	defaultFlagSet.StringVar(&dbPath, "database", OPENPORT_HOME+"/openport.db", "Database file")
	ipLinkProtection := defaultFlagSet.String("ip-link-protection", "",
		"Set to True or False to set if you want users to click a secret link before they can "+
			"access this port. This overwrites the standard setting in your profile for this "+
			"session. choices=[True, False]")
	httpForward := defaultFlagSet.Bool("http-forward", false, "Request an http forward, so you can connect to port 80 on the server.")

	restartOnReboot := defaultFlagSet.Bool("restart-on-reboot", false, "Restart this share when 'restart-shares' is called (on boot for example).")
	keepAliveSeconds := defaultFlagSet.Int("keep-alive", 120, "The interval in between keep-alive messages in seconds.")

	socksProxy := defaultFlagSet.String("proxy", "", "Socks5 proxy to use. Format: socks5://user:pass@host:port")

	defaultFlagSet.MarkHidden("database")
	defaultFlagSet.MarkHidden("server")
	defaultFlagSet.MarkHidden("listener-port")

	flag.NewFlagSet("version", flag.ExitOnError)

	registerKeyCmd := flag.NewFlagSet("register-key", flag.ExitOnError)
	keyName := registerKeyCmd.String("name", "", "The name for this client.")

	killFlagSet := flag.NewFlagSet("kill", flag.ExitOnError)
	killFlagSet.StringVar(&dbPath, "database", OPENPORT_DB_PATH, "Database file")
	killFlagSet.BoolVar(&verbose, "verbose", false, "Verbose logging")

	killAllFlagSet := flag.NewFlagSet("kill-all", flag.ExitOnError)
	killAllFlagSet.StringVar(&dbPath, "database", OPENPORT_DB_PATH, "Database file")
	killAllFlagSet.BoolVar(&verbose, "verbose", false, "Verbose logging")

	restartSharesFlagSet := flag.NewFlagSet("restart-shares", flag.ExitOnError)
	restartSharesFlagSet.StringVar(&dbPath, "database", OPENPORT_DB_PATH, "Database file")
	restartSharesFlagSet.BoolVar(&verbose, "verbose", false, "Verbose logging")

	flag.Usage = myUsage

	if len(os.Args) == 1 {
		myUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "help":
		flag.Usage()
		os.Exit(0)
	case "register-key":
		registerKeyCmd.Parse(os.Args[2:])
		initLogging()
		ensureKeysExist()
		tail := defaultFlagSet.Args()
		token := tail[0]
		log.Debugf(*keyName)
		log.Debugf(token)
		// TODO!!
	case "version":
		fmt.Println(VERSION)
		os.Exit(0)
	case "kill":
		killFlagSet.Parse(os.Args[2:])
		initLogging()
		ensureHomeFolderExists()
		tail := killFlagSet.Args()
		if len(tail) == 0 {
			log.Fatal("port missing")
		}
		var err error
		port, err = strconv.Atoi(tail[0])
		if err != nil {
			log.Warnf("%s --- %s", tail, err)
			flag.Usage()
			os.Exit(6)
		}
		initDB()
		session, err2 := get(port)
		if err2 != nil {
			log.Fatalf("session not found? %s", err2)
		}
		resp, err3 := http.Get(fmt.Sprintf("http://127.0.0.1:%d/exit", session.AppManagementPort))
		if err3 != nil {
			log.Fatalf("Could not kill session: %s", err3)
		}
		log.Debug(resp)
	case "kill-all":
		killAllFlagSet.Parse(os.Args[2:])
		initLogging()
		ensureHomeFolderExists()
		initDB()
		killAll()
		os.Exit(0)
	case "restart-shares":
		restartSharesFlagSet.Parse(os.Args[2:])
		initLogging()
		ensureHomeFolderExists()
		restartShares()
		os.Exit(0)
	default:
		defaultFlagSet.Parse(os.Args[1:])
		initLogging()
		tail := defaultFlagSet.Args()
		if port == -1 {
			if len(tail) == 0 {
				myUsage()
				os.Exit(2)
			}

			var err error
			port, err = strconv.Atoi(tail[0])
			if err != nil {
				log.Warnf("failing: %s %s", tail, err)

				flag.Usage()
				os.Exit(3)
			}
		}

		session := Session{
			LocalPort:         port,
			OpenPortForIpLink: *ipLinkProtection,
			HttpForward:       *httpForward,
			Server:            *server,
			KeepAliveSeconds:  *keepAliveSeconds,
			Proxy:             *socksProxy,
			Active:            true,
		}
		controlPort := startControlServer(*controlPort)
		session.AppManagementPort = controlPort

		if *restartOnReboot {
			session.RestartCommand = strings.Join(os.Args[1:], " ")
		}
		forwardPort(session)
	}

	/*
	   group.add_argument('--list', '-l', action='store_true', help="List shares and exit.")
	   parser.add_argument('--listener-port', type=int, default=-1, help=argparse.SUPPRESS)
	   parser.add_argument('--forward-tunnel', action='store_true',
	                       help='Forward connections from your local port to the server port. Use this to connect two tunnels.')
	   parser.add_argument('--remote-port', type=int, help='The server port you want to forward to'
	                                                       ' (use in combination with --forward-tunnel).',
	                       default=-1)
	   parser.add_argument('--daemonize', '-d', action='store_true', help='Start the app in the background.')
	*/
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
		if ! os.IsExist(err) {
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

					pub_buf, err := ioutil.ReadFile(SSH_PUBLIC_KEY_PATH)
					err = ioutil.WriteFile(OPENPORT_PUBLIC_KEY_PATH, pub_buf, 0600)
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

func restartShares() {
	sessions, err := getAllActive()
	if err != nil {
		panic(err)
	}
	for _, session := range sessions {
		if session.RestartCommand != "" {
			cmd := exec.Command(os.Args[0], strings.Split(session.RestartCommand, " ")...)
			err = cmd.Start()
			if err != nil {
				log.Warn(err)
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

func startControlServer(controlPort int) int {
	if controlPort <= 0 {
		var err error
		controlPort, err = freeport.GetFreePort()
		if err != nil {
			log.Fatal(err)
		}
	}
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/exit", stopSession)
	log.Debugf("Listening for control on port %d", controlPort)
	go http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", controlPort), router)
	return controlPort
}

func forwardPort(session Session) error {
	publicKey, key, err := ensureKeysExist()
	initDB()
	port := session.LocalPort
	dbSession, err := get(port)
	if err != nil {
		dbSession = Session{}
	} else {
		session.SessionToken = dbSession.SessionToken
		session.RemotePort = dbSession.RemotePort
	}
	save(session)

	if session.Proxy != "" {
		os.Setenv("HTTPS_PROXY", session.Proxy)
		os.Setenv("HTTP_PROXY", session.Proxy)
	}

	postUrl := fmt.Sprintf("%s/api/v1/request-port", session.Server)
	getParameters := url.Values{
		"public_key":            {string(publicKey)},
		"request_port":          {strconv.Itoa(session.RemotePort)},
		"client_version":        {"2.0.0"},
		"restart_session_token": {session.SessionToken},
		"local_port":            {strconv.Itoa(session.LocalPort)},
		"http_forward":          {strconv.FormatBool(session.HttpForward)},
		"platform":              {runtime.GOOS},
		/*
			TODO:
			   automatic_restart = forms.BooleanField(required=False)
			   forward_tunnel = forms.BooleanField(required=False)
		*/
	}
	switch session.OpenPortForIpLink {
	case "True", "False":
		getParameters["ip_link_protection"] = []string{session.OpenPortForIpLink}
	case "":
	default:
		getParameters["ip_link_protection"] = []string{"True"}
	}
	log.Debugf("parameters: %s", getParameters)
	resp, err := http.PostForm(postUrl, getParameters)
	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Debugf("http error")
		log.Warn(err)
		return err
	}
	log.Debugf(string(body))
	var jsonData = []byte(body)
	response := PortResponse{}
	jsonErr := json.Unmarshal(jsonData, &response)
	if jsonErr != nil {
		log.Warnf("json error: %s", err)
		return jsonErr
	}

	log.Debugf("ServerPort: %d", response.ServerPort)
	session.SessionToken = response.SessionToken
	session.RemotePort = response.ServerPort
	session.Server = response.ServerIP
	session.Pid = os.Getpid()
	session.AccountId = response.AccountId
	session.KeyId = response.KeyId
	session.HttpForwardAddress = response.HttpForwardAddress
	session.OpenPortForIpLink = response.OpenPortForIpLink
	err = save(session)
	if err != nil {
		log.Warn(err)
	}
	for {
		err := startPortForward(key, session, response.Message)
		log.Warn(err)
		time.Sleep(10 * time.Second)
	}
}
func startPortForward(key ssh.Signer, session Session, message string) error {

	config := &ssh.ClientConfig{
		User: "open",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	var sshClient *ssh.Client
	var err error
	openportSshAddress := fmt.Sprintf("%s:%d", session.Server, 22)

	if session.Proxy != "" {
		// create a socks5 dialer

		u, err := url.Parse(session.Proxy)
		if err != nil {
			log.Fatal(err)
		}
		var proxyAuth proxy.Auth
		proxyPassword, proxyPasswordSet := u.User.Password()
		if proxyPasswordSet {
			proxyAuth = proxy.Auth{
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

		proxyDialer, err := proxy.SOCKS5("tcp", proxyServer, &proxyAuth, proxy.Direct)
		if err != nil {
			log.Warnf("can't connect to the proxy: %s", err)
			return err
		}
		conn, err := proxyDialer.Dial("tcp", openportSshAddress)
		if err != nil {
			return err
		}
		c, chans, reqs, err := ssh.NewClientConn(conn, openportSshAddress, config)
		if err != nil {
			return err
		}
		sshClient = ssh.NewClient(c, chans, reqs)
	} else {
		sshClient, err = ssh.Dial("tcp", openportSshAddress, config)
		if err != nil {
			panic("Failed to dial: " + err.Error())
		}
	}
	log.Debugf("connected")
	session.Active = true
	save(session)
	defer setInactive(session)

	s := fmt.Sprintf("0.0.0.0:%d", session.RemotePort)
	addr, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		return err
	}

	listener, err := sshClient.ListenTCP(addr)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer listener.Close()
	if session.HttpForward {
		log.Infof("Now forwarding remote address %s to localhost", session.HttpForwardAddress)
	} else {
		log.Infof("Now forwarding remote port %s:%d to localhost:%d", session.Server, session.RemotePort, session.LocalPort)
	}
	log.Infof(message)
	keepAliveDone := make(chan bool, 1)
	go keepAlive(sshClient, time.Duration(int64(session.KeepAliveSeconds)*int64(time.Second)), keepAliveDone)

	for {
		// Wait for a connection.
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
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

	RemotePort     int
	LocalPort      int
	Pid            int
	Active         bool
	RestartCommand string

	AccountId          int
	KeyId              int
	HttpForward        bool
	HttpForwardAddress string

	AppManagementPort int
	OpenPortForIpLink string

	KeepAliveSeconds int
	Proxy            string
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

func get(port int) (Session, error) {
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	var session Session
	db.First(&session, "local_port = ?", port)
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

	existingSession, err := get(session.LocalPort)
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
