package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/phayes/freeport"
	flag "github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"strconv"
	"strings"
)

const VERSION = "2.0.0"

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

func init() {
	log.SetOutput(os.Stdout)
}

func main() {
	defaultFlagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	var port int
	defaultFlagSet.IntVar(&port, "port", -1, "The local port you want to openport.")

	defaultFlagSet.IntVar(&port, "local-port", -1, "The local port you want to openport.")
	server := defaultFlagSet.String("server", "https://openport.io", "The server to connect to")
	defaultFlagSet.Bool("verbose", false, "Verbose logging")                                  // verbose :=
	defaultFlagSet.StringVar(&dbPath, "database", "~/.openport/openport.db", "Database file") //databaseFlag :=

	defaultFlagSet.MarkHidden("database")
	defaultFlagSet.MarkHidden("server")

	flag.NewFlagSet("version", flag.ExitOnError)

	registerKeyCmd := flag.NewFlagSet("register-key", flag.ExitOnError)
	keyName := registerKeyCmd.String("name", "", "The name for this client.")

	killFlagSet := flag.NewFlagSet("kill", flag.ExitOnError)
	killFlagSet.StringVar(&dbPath, "database", "~/.openport/openport.db", "Database file") //databaseFlag :=
	killFlagSet.Bool("verbose", false, "Verbose logging")                                  // verbose :=

	flag.Usage = myUsage

	if len(os.Args) == 1 {
		myUsage()
		os.Exit(1)
	}

	//	if *verbose {
	//		println("verbose logging enabled //TODO")
	//	}

	switch os.Args[1] {
	case "register-key":
		registerKeyCmd.Parse(os.Args[2:])
		println(*keyName)
		tail := defaultFlagSet.Args()
		token := tail[0]
		println(token)
	case "version":
		fmt.Println(VERSION)
		os.Exit(0)
	case "kill":
		killFlagSet.Parse(os.Args[2:])
		tail := killFlagSet.Args()
		if len(tail) == 0 {
			log.Fatal("port missing")
		}
		var err error
		port, err = strconv.Atoi(tail[0])
		if err != nil {
			log.Printf("%s --- %s", tail, err)
			flag.Usage()
			os.Exit(6)
		}
		initDB()
		session, err2 := get(port)
		if err2 != nil {
			log.Fatalf("session not found? %s", err2)
		}
		resp, err3 := http.Get(fmt.Sprintf("http://./127.0.0.1:%d/exit", session.AppManagementPort))
		if err3 != nil {
			log.Fatalf("Could not kill session: %s", err3)
		}
		println(resp)
	default:
		defaultFlagSet.Parse(os.Args[1:])
		tail := defaultFlagSet.Args()

		println("tail:")
		println(tail)
		println("----")

		if port == -1 {
			if len(tail) == 0 {
				myUsage()
				os.Exit(2)
			}

			var err error
			log.Printf("failing %d %s", len(tail), tail)
			port, err = strconv.Atoi(tail[0])
			if err != nil {
				flag.Usage()
				os.Exit(3)
			}
		}

		session := Session{
			LocalPort:      port,
			RestartCommand: strings.Join(os.Args, " "),
		}
		controlPort := startControlServer()
		forwardPort(*server, session, controlPort)
	}

	/*
	   parser.add_argument('--verbose', '-v', action='store_true', help='Be verbose.')
	   group.add_argument('--list', '-l', action='store_true', help="List shares and exit.")
	   group.add_argument('--kill-all', '-K', action='store_true', help="Stop all shares.")
	   group.add_argument('--restart-shares', action='store_true', help='Start all shares that were started with -R and are not running.')
	   parser.add_argument('--listener-port', type=int, default=-1, help=argparse.SUPPRESS)
	   parser.add_argument('--request-port', type=int, default=-1, metavar='REMOTE_PORT',
	                       help='Request the server port for the share. Do not forget to pass the token with --request-token.')
	   parser.add_argument('--request-token', default='', help='The token needed to restart the share.')
	   parser.add_argument('--keep-alive', type=int, default=DEFAULT_KEEP_ALIVE_INTERVAL_SECONDS,
	                       help='The interval in between keep-alive messages in seconds.')
	   parser.add_argument('--http-forward', action='store_true',
	                       help='Request an http forward, so you can connect to port 80 on the server.')
	   parser.add_argument('--restart-on-reboot', '-R', action='store_true',
	                       help='Restart this share when --restart-shares is called (on boot for example).')
	   parser.add_argument('--forward-tunnel', action='store_true',
	                       help='Forward connections from your local port to the server port. Use this to connect two tunnels.')
	   parser.add_argument('--remote-port', type=int, help='The server port you want to forward to'
	                                                       ' (use in combination with --forward-tunnel).',
	                       default=-1)
	   parser.add_argument('--ip-link-protection', type=ast.literal_eval,
	                       help='Set to True or False to set if you want users to click a secret link before they can '
	                            'access this port. This overwrites the standard setting in your profile for this '
	                            'session.', default=None, choices=[True, False])
	   parser.add_argument('--daemonize', '-d', action='store_true', help='Start the app in the background.')
	   parser.add_argument('--proxy', type=str, help='Socks5 proxy to use. Format: socks5h://user:pass@host:port')
	*/
}

func stopSession(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "Ok")
	go os.Exit(5)
}

func startControlServer() int {
	controlPort, err := freeport.GetFreePort()
	if err != nil {
		log.Fatal(err)
	}
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/exit", stopSession)
	log.Printf("Listening for control on port %d", controlPort)
	go http.ListenAndServe(fmt.Sprintf("127.0.0.1:%d", controlPort), router)
	return controlPort
}

func forwardPort(server string, session Session, controlPort int) {
	initDB()
	port := session.LocalPort
	dbSession, err := get(port)
	if err != nil {
		dbSession = Session{}
	}

	usr, _ := user.Current()
	file := usr.HomeDir + "/.openport/id_rsa"

	buf, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatal(err)
	}

	public_key, err := ioutil.ReadFile(file + ".pub")
	if err != nil {
		log.Fatal(err)
	}

	key, err := ssh.ParsePrivateKey(buf)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(string(public_key))

	postUrl := fmt.Sprintf("%s/api/v1/request-port", server)
	getParameters := url.Values{
		"public_key":     {string(public_key)},
		"request_port":   {strconv.Itoa(dbSession.RemotePort)},
		"client_version": {"2.0.0"},
		"restart_session_token":  {dbSession.SessionToken},
	}
	log.Printf("parameters: %s", getParameters)
	resp, err := http.PostForm(postUrl, getParameters)
	if err != nil {
		log.Fatal(err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	fmt.Println(string(body))

	if err != nil {
		fmt.Println("http error")
		log.Fatal(err)
	}
	fmt.Println(string(body))
	fmt.Println("here1")
	var jsonData = []byte(body)

	response := PortResponse{}

	json_err := json.Unmarshal(jsonData, &response)
	if json_err != nil {
		fmt.Println("json error")
		log.Fatal(json_err)
	}

	log.Printf("ServerPort: %s", response.ServerPort)
	session.SessionToken = response.SessionToken
	session.AppManagementPort = controlPort
	session.RemotePort = response.ServerPort
	save(session)

	config := &ssh.ClientConfig{
		User: "open",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(key),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", response.ServerIP, 22), config)
	if err != nil {
		panic("Failed to dial: " + err.Error())
	}

	log.Println("connected")
	session.Active = true
	save(session)
	defer setInactive(session)

	s := fmt.Sprintf("0.0.0.0:%d", response.ServerPort)
	addr, err := net.ResolveTCPAddr("tcp", s)
	if err != nil {
		panic("Could not get address: " + err.Error())
	}

	listener, err := conn.ListenTCP(addr)
	if err != nil {
		log.Fatal(err.Error())
	}
	defer listener.Close()
	log.Printf("Now forwarding remote port %s:%d to localhost:%d", response.ServerIP, response.ServerPort, port)

	for {
		// Wait for a connection.
		conn, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go func(c net.Conn) {
			log.Println("new request")
			conn, err := net.Dial("tcp", fmt.Sprintf("localhost:%d", port))
			if err != nil {
				log.Println(err)
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
}

func initDB() {

	log.Printf("db path: %s", dbPath)
	db, err := gorm.Open("sqlite3", dbPath)
	if err != nil {
		log.Panicf("failed to connect database: %s", err)
	}
	defer db.Close()

	// Migrate the schema
	db.AutoMigrate(&Session{})
	log.Printf("db created")
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
