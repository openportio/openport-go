package main

import (
	"fmt"
	o "github.com/openportio/openport-go"
	db "github.com/openportio/openport-go/database"
	"github.com/openportio/openport-go/utils"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
)

func main() {
	app := o.CreateApp()
	go run(app, os.Args)
	os.Exit(<-app.ExitCode)
}

var flagSets = make(map[string]*flag.FlagSet)
var verbose = false

func run(app *o.App, args []string) {

	var port int
	var controlPort int
	var server string
	var restartOnReboot bool
	var keepAliveSeconds int
	var socksProxy string
	var remotePort string
	var daemonize bool
	var automaticRestart bool
	var exitOnFailureTimeout int

	addVerboseFlag := func(set *flag.FlagSet) {
		set.BoolVarP(&verbose, "verbose", "v", false, "Verbose logging")
	}

	addDatabaseFlag := func(set *flag.FlagSet) {
		set.StringVar(&app.DbHandler.DbPath, "database", db.DEFAULT_OPENPORT_DB_PATH, "Database file")
		utils.FailOnError(set.MarkHidden("database"), "")
	}
	addLegacyFlag := func(set *flag.FlagSet, name string) {
		set.String(name, "legacy", "legacy: do not use")
		utils.FailOnError(set.MarkHidden(name), "")
	}

	addServerFlag := func(set *flag.FlagSet) {
		set.StringVar(&server, "server", o.DEFAULT_SERVER, "The server to connect to.")
		utils.FailOnError(set.MarkHidden("server"), "")
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
		set.BoolVarP(&automaticRestart, "automatic-restart", "a", false, "This is an automatic restart.")
		utils.FailOnError(set.MarkHidden("automatic-restart"), "")

		addVerboseFlag(set)
		addDatabaseFlag(set)
		addServerFlag(set)
		utils.FailOnError(set.MarkHidden("listener-port"), "")
	}

	defaultFlagSet := flag.NewFlagSet(args[0], flag.ExitOnError)
	addSharedFlags(defaultFlagSet)
	useIpLinkProtection := defaultFlagSet.String("ip-link-protection", "",
		"Let users click a secret link before they can "+
			"access this port. This overwrites the setting in your profile. choices=[True, False]")
	httpForward := defaultFlagSet.Bool("http-forward", false, "Request an http forward, so you can connect to port 80 on the server.")
	sshServer := defaultFlagSet.String("request-server", "", "The requested tunnel server")
	utils.FailOnError(defaultFlagSet.MarkHidden("request-server"), "")
	useWS := defaultFlagSet.Bool("ws", false, "Use the websockets protocol instead of ssh.")
	noSSL := defaultFlagSet.Bool("no-ssl", false, "Connect to the Openport servers without using SSL (only used if the --ws flag is set)")

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

	if len(args) <= 1 {
		myUsage()
		app.ExitCode <- o.EXIT_CODE_USAGE
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
			myUsage()
			fmt.Printf("Default: %s <port> [arguments]\n", args[0])
			defaultFlagSet.PrintDefaults()
		}
		app.ExitCode <- o.EXIT_CODE_HELP
	case "register-key", "register":
		_ = registerKeyFlagSet.Parse(args[2:])
		o.InitLogging(verbose, o.OPENPORT_LOG_PATH)
		tail := registerKeyFlagSet.Args()
		if *registerKeyToken == "" {
			if len(tail) == 0 {
				log.Fatalf("--token is required")
			} else {
				registerKeyToken = &tail[0]
			}
		}
		app.RegisterKey(*registerKeyToken, *registerKeyName, socksProxy, server)
	case "version":
		fmt.Println(o.VERSION)
	case "kill":
		_ = killFlagSet.Parse(args[2:])
		o.InitLogging(verbose, o.OPENPORT_LOG_PATH)
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
					app.ExitCode <- o.EXIT_CODE_INVALID_ARGUMENT
				}
			}
		}
		app.KillSession(port)

	case "kill-all":
		_ = killAllFlagSet.Parse(args[2:])
		o.InitLogging(verbose, o.OPENPORT_LOG_PATH)
		utils.EnsureHomeFolderExists()
		app.DbHandler.InitDB()
		app.KillAll()
	case "restart-sessions":
		_ = restartSessionsFlagSet.Parse(args[2:])
		o.InitLogging(verbose, o.OPENPORT_LOG_PATH)
		if daemonize {
			app.StartDaemon(args)
		} else {
			utils.EnsureHomeFolderExists()
			app.RestartSessions(args[0], server)
		}
	case "list":
		_ = listFlagSet.Parse(args[2:])
		o.InitLogging(verbose, o.OPENPORT_LOG_PATH)
		utils.EnsureHomeFolderExists()
		app.DbHandler.InitDB()
		app.ListSessions()
		app.ExitCode <- o.EXIT_CODE_LIST
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
		o.InitLogging(verbose, o.OPENPORT_LOG_PATH)
		app.ExitOnFailureTimeout = exitOnFailureTimeout

		tail := defaultFlagSet.Args()
		if port == -1 {
			if len(tail) == 0 {
				if !forwardTunnel {
					myUsage()
					app.ExitCode <- o.EXIT_CODE_INVALID_ARGUMENT
				}
			} else {
				var err error
				port, err = strconv.Atoi(tail[0])
				if err != nil {
					log.Warnf("failing: %s %s", tail, err)
					defaultFlagSet.PrintDefaults()
					app.ExitCode <- o.EXIT_CODE_INVALID_ARGUMENT
				}
			}
		}

		if daemonize {
			app.StartDaemon(args)
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
			UseWS:               *useWS,
			NoSSL:               *noSSL,
			AutomaticRestart:    automaticRestart,
		}
		controlPort := app.StartControlServer(controlPort)
		app.Session.AppManagementPort = controlPort

		if restartOnReboot {
			restartCommand := args[1:]
			slices.DeleteFunc(restartCommand, func(s string) bool {
				return s == "--automatic-restart" || s == "-a"
			})
			app.Session.RestartCommand = strings.Join(restartCommand, " ")
		}
		app.CreateTunnel()
	}
	app.ExitCode <- 0
}

func myUsage() {
	fmt.Printf("Usage: %s (<port> | forward | list | restart-sessions | kill <port> | kill-all | register-key | help [command] | version) [arguments]\n", os.Args[0])
}
