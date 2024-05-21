package main

import (
	"fmt"
	o "github.com/openportio/openport-go"
	db "github.com/openportio/openport-go/database"
	"github.com/openportio/openport-go/utils"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
	"net"
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
	var sshServer string
	var help = false
	var useIpLinkProtection string
	var useWS = false
	var noSSL = false

	addVerboseFlag := func(set *flag.FlagSet) {
		set.BoolVarP(&verbose, "verbose", "v", false, "Verbose logging")
	}
	addHelpFlag := func(set *flag.FlagSet) {
		set.BoolVarP(&help, "help", "h", false, "Show help message")
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
		set.StringVar(&remotePort, "remote-port", "-1", "The server and port you want to expose locally. [openport.io:1234]")
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
		addHelpFlag(set)
		utils.FailOnError(set.MarkHidden("listener-port"), "")
	}

	defaultFlagSet := flag.NewFlagSet(args[0], flag.ExitOnError)
	addSharedFlags(defaultFlagSet)

	addIpLinkProtectionFlag := func(set *flag.FlagSet) {
		set.StringVar(&useIpLinkProtection, "ip-link-protection", "",
			"Let users click a secret link before they can "+
				"access this port. This overwrites the setting in your profile. choices=[True, False]")
	}

	addIpLinkProtectionFlag(defaultFlagSet)

	httpForward := defaultFlagSet.Bool("http-forward", false, "Request an http forward, so you can connect to port 80 on the server.")

	addRequestServerFlag := func(set *flag.FlagSet) {
		set.StringVar(&sshServer, "request-server", "", "The requested tunnel server")
		utils.FailOnError(set.MarkHidden("request-server"), "")
	}
	addRequestServerFlag(defaultFlagSet)

	addWSFlags := func(set *flag.FlagSet) {
		set.BoolVar(&useWS, "ws", false, "Use the websockets protocol instead of ssh.")
		set.BoolVar(&noSSL, "no-ssl", false, "Connect to the Openport servers without using SSL (only used if the --ws flag is set)")

	}
	addWSFlags(defaultFlagSet)

	forwardTunnelFlagSet := flag.NewFlagSet("forward", flag.ExitOnError)
	addSharedFlags(forwardTunnelFlagSet)

	// Legacy flags
	addLegacyFlag(defaultFlagSet, "request-port")
	addLegacyFlag(defaultFlagSet, "request-token")
	addLegacyFlag(defaultFlagSet, "start-manager")
	addLegacyFlag(defaultFlagSet, "manager-port")

	flagSets[""] = defaultFlagSet

	selfTestFlagSet := flag.NewFlagSet("selftest", flag.ExitOnError)
	selfTestFlagSet.StringVar(&socksProxy, "proxy", "", "Socks5 proxy to use. Format: socks5://user:pass@host:port")
	addVerboseFlag(selfTestFlagSet)
	addDatabaseFlag(selfTestFlagSet)
	addServerFlag(selfTestFlagSet)
	addHelpFlag(selfTestFlagSet)
	addIpLinkProtectionFlag(selfTestFlagSet)
	addRequestServerFlag(selfTestFlagSet)
	addWSFlags(selfTestFlagSet)
	flagSets["selftest"] = selfTestFlagSet

	flagSets["forward"] = forwardTunnelFlagSet

	versionFlagSet := flag.NewFlagSet("version", flag.ExitOnError)
	addHelpFlag(versionFlagSet)
	flagSets["version"] = versionFlagSet

	killFlagSet := flag.NewFlagSet("kill", flag.ExitOnError)
	addVerboseFlag(killFlagSet)
	addDatabaseFlag(killFlagSet)
	addHelpFlag(killFlagSet)
	killFlagSet.IntVar(&port, "port", -1, "The local port of the session to kill.")
	flagSets["kill"] = killFlagSet

	killAllFlagSet := flag.NewFlagSet("kill-all", flag.ExitOnError)
	addVerboseFlag(killAllFlagSet)
	addDatabaseFlag(killAllFlagSet)
	addHelpFlag(killAllFlagSet)
	flagSets["kill-all"] = killAllFlagSet

	restartSessionsFlagSet := flag.NewFlagSet("restart-sessions", flag.ExitOnError)
	addVerboseFlag(restartSessionsFlagSet)
	addDatabaseFlag(restartSessionsFlagSet)
	addServerFlag(restartSessionsFlagSet)
	addHelpFlag(restartSessionsFlagSet)
	restartSessionsFlagSet.BoolVarP(&daemonize, "daemonize", "d", false, "Start the app in the background.")
	flagSets["restart-sessions"] = restartSessionsFlagSet

	listFlagSet := flag.NewFlagSet("list", flag.ExitOnError)
	addVerboseFlag(listFlagSet)
	addDatabaseFlag(listFlagSet)
	addHelpFlag(listFlagSet)
	flagSets["list"] = listFlagSet

	rmFlagSet := flag.NewFlagSet("rm", flag.ExitOnError)
	addVerboseFlag(rmFlagSet)
	addDatabaseFlag(rmFlagSet)
	addHelpFlag(rmFlagSet)
	rmFlagSet.IntVar(&port, "port", -1, "The port that you want to forget.")
	flagSets["rm"] = rmFlagSet

	registerKeyFlagSet := flag.NewFlagSet("register-key", flag.ExitOnError)
	addVerboseFlag(registerKeyFlagSet)
	addServerFlag(registerKeyFlagSet)
	addHelpFlag(registerKeyFlagSet)
	registerKeyFlagSet.StringVar(&socksProxy, "proxy", "", "Socks5 proxy to use. Format: socks5://user:pass@host:port")
	registerKeyToken := registerKeyFlagSet.String("token", "", "Token to link your machine to your account. Find this token at https://openport.io/user/keys .")
	registerKeyName := registerKeyFlagSet.String("name", "", "The name for this machine.")
	flagSets["register-key"] = registerKeyFlagSet

	flag.Usage = myUsage

	if len(args) <= 1 {
		myUsage()
		defaultFlagSet.PrintDefaults()
		app.ExitCode <- o.EXIT_CODE_USAGE
		return
	}

	switch args[1] {

	case "register-key", "register", "link":
		_ = registerKeyFlagSet.Parse(args[2:])
		if help {
			println("Use this command to register a key to your account.")
			println("Usage: openport register-key <token> [arguments]")
			registerKeyFlagSet.PrintDefaults()
			app.ExitCode <- o.EXIT_CODE_HELP
			return
		}
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
		_ = versionFlagSet.Parse(args[2:])
		if help {
			println("Shows the version of the client executable.")
			println("Usage: openport version")
			versionFlagSet.PrintDefaults()
			app.ExitCode <- o.EXIT_CODE_HELP
			return
		}
		fmt.Println(o.VERSION)
	case "kill":
		_ = killFlagSet.Parse(args[2:])
		if help {
			println("Use this command to kill a session exposing a port.")
			println("Usage: openport kill <local_port> [arguments]")
			killFlagSet.PrintDefaults()
			app.ExitCode <- o.EXIT_CODE_HELP
			return
		}
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

	case "kill-all", "killall":
		_ = killAllFlagSet.Parse(args[2:])
		if help {
			println("Use this command to kill all sessions.")
			println("Usage: openport kill-all [arguments]")
			killAllFlagSet.PrintDefaults()
			app.ExitCode <- o.EXIT_CODE_HELP
			return
		}
		o.InitLogging(verbose, o.OPENPORT_LOG_PATH)
		app.InitFiles()
		app.KillAll()
	case "restart-sessions", "restart", "restartsessions":
		_ = restartSessionsFlagSet.Parse(args[2:])
		if help {
			println("Use this command to restart all sessions that are started with the --restart-on-reboot flag.")
			println("Usage: openport restart-sessions [arguments]")
			restartSessionsFlagSet.PrintDefaults()
			app.ExitCode <- o.EXIT_CODE_HELP
			return
		}
		o.InitLogging(verbose, o.OPENPORT_LOG_PATH)
		if daemonize {
			app.StartDaemon(args)
		} else {
			app.RestartSessions(args[0], server)
		}
	case "list":
		_ = listFlagSet.Parse(args[2:])
		if help {
			println("Use this command to list all sessions.")
			println("Usage: openport list [arguments]")
			listFlagSet.PrintDefaults()
			app.ExitCode <- o.EXIT_CODE_HELP
			return
		}
		o.InitLogging(verbose, o.OPENPORT_LOG_PATH)
		app.InitFiles()
		app.ListSessions()
		app.ExitCode <- o.EXIT_CODE_LIST

	case "rm":
		_ = rmFlagSet.Parse(args[2:])
		if help {
			println("Use this command to remove a port from your local database. This resets the remote port.")
			println("Usage: openport rm <local_port> [arguments]")
			rmFlagSet.PrintDefaults()
			app.ExitCode <- o.EXIT_CODE_HELP
			return
		}
		o.InitLogging(verbose, o.OPENPORT_LOG_PATH)
		app.InitFiles()
		tail := rmFlagSet.Args()
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
		app.RemoveSession(port)
		app.ExitCode <- o.EXIT_CODE_RM

	case "selftest":
		// This is a test command that is used to test the client.
		utils.FailOnError(selfTestFlagSet.Parse(args[2:]), "error parsing args for selftest.")

		if help {
			println("Use this command to run a quick self-test of the application.")
			println("Usage: openport selftest [arguments]")
			selfTestFlagSet.PrintDefaults()
			app.ExitCode <- o.EXIT_CODE_HELP
			return
		}

		o.InitLogging(verbose, o.OPENPORT_LOG_PATH)
		controlPort := app.StartControlServer(-1)

		app.Session = db.Session{
			LocalPort:           controlPort,
			UseIpLinkProtection: useIpLinkProtection,
			HttpForward:         *httpForward,
			Server:              server,
			KeepAliveSeconds:    keepAliveSeconds,
			Proxy:               socksProxy,
			Active:              true,
			ForwardTunnel:       false,
			RemotePort:          -1,
			SshServer:           sshServer,
			UseWS:               useWS,
			NoSSL:               noSSL,
			AutomaticRestart:    automaticRestart,
			AppManagementPort:   controlPort,
		}

		app.RunSelfTest()

	default:
		forwardTunnel := args[1] == "forward"
		var remotePortInt int
		var err error
		if forwardTunnel {
			_ = defaultFlagSet.Parse(args[2:])
			if help {
				println("Use this command to expose the port of your peer on a local port on your machine.")
				println("See https://openport.readthedocs.io/en/latest/recipes_create_a_forward_tunnel.html for more information.")
				println("Usage: openport forward --remote-port <server:server_port> [arguments]")
				forwardTunnelFlagSet.PrintDefaults()
				app.ExitCode <- o.EXIT_CODE_HELP
				return
			}
			if useWS {
				log.Warn("Websockets are not supported for forward tunnels (yet). Let us know if you need this feature.")
				app.ExitCode <- o.EXIT_CODE_INVALID_ARGUMENT
				return
			}

			remotePortInt, err = strconv.Atoi(remotePort)
			if err != nil {
				parsedServer, parsedPort, err := net.SplitHostPort(remotePort)
				if err != nil {
					log.Fatalf("invalid format for remote-port (host:port) or (port) : %s %s", remotePort, err)
				}
				if parsedPort == "" {
					log.Fatalf("Port missing in remote-port arg: %s", remotePort)
				}
				sshServer = parsedServer
				remotePortInt, _ = strconv.Atoi(parsedPort)
			}

		} else {
			_ = defaultFlagSet.Parse(args[1:])
			if help {
				println("Use this command to expose a local port of your machine to the internet.")
				println("See https://openport.readthedocs.io/ or https://openport.io for more information.")
				println("Usage: openport <command> [arguments]")
				println("Commands:")
				println("  <port>                Expose a local port to the internet.")
				println("  forward               Expose a port of your peer to this machine.")
				println("  list                  List all sessions.")
				println("  kill <local_port>     Kill a session.")
				println("  kill-all              Kill all sessions.")
				println("  restart-sessions      Restart all sessions that are started with the --restart-on-reboot flag.")
				println("  rm <local_port>       Remove a port from your local database.")
				println("  register <token>      Link your device to your account.")
				println("  version               Show the version of the client executable.")
				println("Run 'openport <command> --help' for more information about the command.")
				println("")
				println("Default usage: openport <local_port> [arguments]")
				defaultFlagSet.PrintDefaults()
				app.ExitCode <- o.EXIT_CODE_HELP
				return
			}

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
					log.Error("Missing a local port or command.")
					myUsage()
					defaultFlagSet.PrintDefaults()
					app.ExitCode <- o.EXIT_CODE_INVALID_ARGUMENT
				}
			} else {
				var err error
				port, err = strconv.Atoi(tail[0])
				if err != nil {
					log.Warnf("Unknown command: %s", tail)
					myUsage()
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
			UseIpLinkProtection: useIpLinkProtection,
			HttpForward:         *httpForward,
			Server:              server,
			KeepAliveSeconds:    keepAliveSeconds,
			Proxy:               socksProxy,
			Active:              true,
			ForwardTunnel:       forwardTunnel,
			RemotePort:          remotePortInt,
			SshServer:           sshServer,
			UseWS:               useWS,
			NoSSL:               noSSL,
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
		app.InitFiles()
		app.CreateTunnel()
	}
	app.ExitCode <- 0
}

func myUsage() {
	fmt.Printf("Usage: %s (<port> | forward | list | restart-sessions | kill <port> | kill-all | register <token> | rm <port> | version) [arguments]\n", os.Args[0])
	fmt.Println("Type 'openport <command> --help' for more information about the different commands.")
	fmt.Println("Default: openport <port> [arguments]")
}
