package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	o "github.com/openportio/openport-go"
	db "github.com/openportio/openport-go/database"
	"github.com/openportio/openport-go/utils"
	log "github.com/sirupsen/logrus"
	flag "github.com/spf13/pflag"
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
	var dbPath string
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
		set.StringVar(&dbPath, "database", db.DEFAULT_OPENPORT_DB_PATH, "Database file")
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
		set.IntVar(&port, "port", -1, "Same as 'local-port'")
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
	defaultFlagSet.IntVar(&port, "local-port", -1, "The local port you want to expose.")

	addIpLinkProtectionFlag := func(set *flag.FlagSet) {
		set.StringVar(&useIpLinkProtection, "ip-link-protection", "",
			"Let users click a secret link before they can "+
				"access this port. This overwrites the setting in your profile. choices=[True, False]")
	}

	addIpLinkProtectionFlag(defaultFlagSet)

	httpForward := defaultFlagSet.Bool("http-forward", false, "Request an http forward, so you can connect to port 80 on the server.")

	tlsPassthrough := defaultFlagSet.Bool("tls-passthrough", false,
		"Terminate TLS on this machine instead of on the openport servers, so the tunnelled "+
			"traffic stays encrypted end-to-end. Certificates come from Let's Encrypt unless "+
			"--tls-cert and --tls-key are given. Implies --http-forward.")
	customDomain := defaultFlagSet.String("domain", "",
		"Your own domain for the tls-passthrough forward. Create a CNAME record pointing it to "+
			"your forwarding address first.")
	tlsCertPath := defaultFlagSet.String("tls-cert", "", "Path to the PEM certificate (chain) served for the tls-passthrough forward.")
	tlsKeyPath := defaultFlagSet.String("tls-key", "", "Path to the PEM private key for --tls-cert.")
	acmeDirectory := defaultFlagSet.String("acme-directory", "",
		"(testing) Alternative ACME directory URL for the tls-passthrough certificates.")
	localTLS := defaultFlagSet.Bool("local-tls", false,
		"With --tls-passthrough: the local service serves HTTPS itself, so relay the encrypted "+
			"bytes to it instead of terminating TLS here. You manage the certificate (renew via "+
			"DNS-01; http-01 does not reach a passthrough forward).")
	localProxyProtocol := defaultFlagSet.Bool("local-proxy-protocol", false,
		"With --local-tls: pass the PROXY protocol header (the visitor's real IP) through to "+
			"the local service instead of stripping it. The local service must expect it, e.g. "+
			"nginx 'listen 443 ssl proxy_protocol'.")

	addRequestServerFlag := func(set *flag.FlagSet) {
		set.StringVar(&sshServer, "request-server", "", "The requested tunnel server")
		utils.FailOnError(set.MarkHidden("request-server"), "")
	}
	addRequestServerFlag(defaultFlagSet)

	addWSFlags := func(set *flag.FlagSet) {
		set.BoolVar(&useWS, "ws", false, "Use the websockets protocol instead of ssh.")
		set.BoolVar(&noSSL, "no-ssl", false, "INSECURE: Connect to the Openport servers unencrypted, exposing all tunnelled traffic to the network (only used if the --ws flag is set)")

	}
	addWSFlags(defaultFlagSet)

	forwardTunnelFlagSet := flag.NewFlagSet("forward", flag.ExitOnError)
	addSharedFlags(forwardTunnelFlagSet)
	forwardTunnelFlagSet.IntVar(&port, "local-port", -1, "The remote port will be available at localhost:<local-port>")

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

	connectFlagSet := flag.NewFlagSet("connect", flag.ExitOnError)
	addSharedFlags(connectFlagSet)
	connectFlagSet.IntVar(&port, "local-port", -1, "The remote port will be available at localhost:<local-port>")
	flagSets["connect"] = connectFlagSet

	versionFlagSet := flag.NewFlagSet("version", flag.ExitOnError)
	addHelpFlag(versionFlagSet)
	addVerboseFlag(versionFlagSet)
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
		app.Stop(o.EXIT_CODE_USAGE)
		return
	}

	// Shared by "connect" and "ssh": a forward tunnel to one of your own
	// devices, resolved by its name (set with "openport register --name"),
	// optionally running a command once the tunnel is up.
	startConnectSession := func(device string, remoteLocalPort int, execCommand []string) {
		o.InitLogging(verbose, o.LogPath)
		app.ExitOnFailureTimeout = exitOnFailureTimeout
		if len(execCommand) > 0 {
			if restartOnReboot {
				log.Fatal("--restart-on-reboot cannot be combined with an exec command")
			}
			if daemonize {
				log.Fatal("--daemonize cannot be combined with an exec command")
			}
			app.SetExecCommand(execCommand)
		}
		if daemonize {
			app.StartDaemon(args)
			return
		}
		app.Session = db.Session{
			LocalPort:          port,
			Server:             server,
			KeepAliveSeconds:   keepAliveSeconds,
			Proxy:              socksProxy,
			Active:             true,
			ForwardTunnel:      true,
			RemotePort:         -1,
			ForwardToKeyName:   device,
			ForwardToLocalPort: remoteLocalPort,
			SshServer:          sshServer,
			AutomaticRestart:   automaticRestart,
		}
		managementPort := app.StartControlServer(controlPort)
		app.Session.AppManagementPort = managementPort
		if restartOnReboot {
			app.Session.RestartCommand = strings.Join(stripAutomaticRestart(args[1:]), " ")
		}
		app.InitFiles()
		app.CreateTunnel()
		app.Stop(0)
	}

	switch args[1] {

	case "connect":
		// Everything after "exec" belongs to the command, so its own flags
		// must not reach the openport flag parser.
		rest := args[2:]
		var execCommand []string
		for i, arg := range rest {
			if arg == "exec" {
				execCommand = rest[i+1:]
				rest = rest[:i]
				break
			}
		}
		_ = connectFlagSet.Parse(rest)
		app.DbHandler.SetPath(dbPath)
		if help {
			println("Use this command to reach a port of another device of yours, by the device's name.")
			println("The other device must be online (\"openport <port>\") and registered to your")
			println("account with a name: openport register <token> --name <device-name> .")
			println("Usage: openport connect <device-name> <port> [arguments] [exec <command>]")
			println("       openport connect <device-name>:<port> [arguments] [exec <command>]")
			println("In the exec command, $port is replaced by the local port of the tunnel (single-quote")
			println("it so your shell does not expand it first).")
			println("Example: openport connect device-a 22 exec 'ssh root@localhost -p $port'")
			connectFlagSet.PrintDefaults()
			app.Stop(o.EXIT_CODE_HELP)
			return
		}
		device, remoteLocalPort, err := parseConnectTarget(connectFlagSet.Args())
		if err != nil {
			log.Error(err)
			println("Usage: openport connect <device-name> <port> [arguments] [exec <command>]")
			app.Stop(o.EXIT_CODE_INVALID_ARGUMENT)
			return
		}
		startConnectSession(device, remoteLocalPort, execCommand)

	case "ssh":
		opFlags, sshOptions, destination, remoteCommand, devicePort := splitSSHArgs(args[2:], connectFlagSet)
		_ = connectFlagSet.Parse(opFlags)
		app.DbHandler.SetPath(dbPath)
		if help || destination == "" {
			println("Use this command to ssh into another device of yours, by the device's name.")
			println("The other device must run an ssh server, expose it (\"openport 22\") and be")
			println("registered to your account with a name: openport register <token> --name <device-name> .")
			println("Usage: openport ssh [arguments] [ssh-options] [user@]<device-name> [command]")
			println("-p <port> is the port of the ssh server on the device (default 22).")
			println("Example: openport ssh root@device-a")
			connectFlagSet.PrintDefaults()
			if help {
				app.Stop(o.EXIT_CODE_HELP)
			} else {
				app.Stop(o.EXIT_CODE_INVALID_ARGUMENT)
			}
			return
		}
		remoteLocalPort := 22
		if devicePort != "" {
			var err error
			remoteLocalPort, err = strconv.Atoi(devicePort)
			if err != nil || remoteLocalPort < 1 || remoteLocalPort > 65535 {
				log.Errorf("invalid port: %s", devicePort)
				app.Stop(o.EXIT_CODE_INVALID_ARGUMENT)
				return
			}
		}
		sshUser, device := splitUserDevice(destination)
		execCommand := buildSSHCommand(sshUser, device, remoteLocalPort, sshOptions, remoteCommand)
		startConnectSession(device, remoteLocalPort, execCommand)

	case "register-key", "register", "link":
		_ = registerKeyFlagSet.Parse(args[2:])
		app.DbHandler.SetPath(dbPath)
		if help {
			println("Use this command to register a key to your account.")
			println("Usage: openport register-key <token> [arguments]")
			registerKeyFlagSet.PrintDefaults()
			app.Stop(o.EXIT_CODE_HELP)
			return
		}
		o.InitLogging(verbose, o.LogPath)
		tail := registerKeyFlagSet.Args()
		if *registerKeyToken == "" {
			if len(tail) == 0 {
				log.Fatalf("--token is required")
			} else {
				registerKeyToken = &tail[0]
			}
		}
		app.RegisterKey(*registerKeyToken, *registerKeyName, socksProxy, server)
	case "rotate-key":
		_ = registerKeyFlagSet.Parse(args[2:])
		app.DbHandler.SetPath(dbPath)
		if help {
			println("Replaces this machine's key with a newly generated one and registers it,")
			println("retiring the old key. Your reserved ports are carried over.")
			println("Usage: openport rotate-key <token> [arguments]")
			println("Get the token at https://openport.io/user/keys .")
			registerKeyFlagSet.PrintDefaults()
			app.Stop(o.EXIT_CODE_HELP)
			return
		}
		o.InitLogging(verbose, o.LogPath)
		rotateTail := registerKeyFlagSet.Args()
		if *registerKeyToken == "" {
			if len(rotateTail) == 0 {
				log.Fatalf("--token is required. Get it at https://openport.io/user/keys .")
			} else {
				registerKeyToken = &rotateTail[0]
			}
		}
		app.RotateKey(*registerKeyToken, *registerKeyName, socksProxy, server)
	case "version":
		_ = versionFlagSet.Parse(args[2:])
		app.DbHandler.SetPath(dbPath)
		if help {
			println("Shows the version of the client executable.")
			println("Usage: openport version")
			versionFlagSet.PrintDefaults()
			app.Stop(o.EXIT_CODE_HELP)
			return
		}
		// Build scripts parse this output as the bare version — keep it single-line
		// unless verbose is asked for.
		fmt.Println(o.VERSION)
		if verbose {
			fmt.Println("git: " + o.GitSha)
		}
	case "kill":
		_ = killFlagSet.Parse(args[2:])
		app.DbHandler.SetPath(dbPath)
		if help {
			println("Use this command to kill a session exposing a port.")
			println("Usage: openport kill <local_port> [arguments]")
			killFlagSet.PrintDefaults()
			app.Stop(o.EXIT_CODE_HELP)
			return
		}
		o.InitLogging(verbose, o.LogPath)
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
					app.Stop(o.EXIT_CODE_INVALID_ARGUMENT)
				}
			}
		}
		app.KillSession(port)

	case "kill-all", "killall":
		_ = killAllFlagSet.Parse(args[2:])
		app.DbHandler.SetPath(dbPath)
		if help {
			println("Use this command to kill all sessions.")
			println("Usage: openport kill-all [arguments]")
			killAllFlagSet.PrintDefaults()
			app.Stop(o.EXIT_CODE_HELP)
			return
		}
		o.InitLogging(verbose, o.LogPath)
		app.InitFiles()
		app.KillAll()
	case "restart-sessions", "restart", "restartsessions":
		_ = restartSessionsFlagSet.Parse(args[2:])
		app.DbHandler.SetPath(dbPath)
		if help {
			println("Use this command to restart all sessions that are started with the --restart-on-reboot flag.")
			println("Usage: openport restart-sessions [arguments]")
			restartSessionsFlagSet.PrintDefaults()
			app.Stop(o.EXIT_CODE_HELP)
			return
		}
		o.InitLogging(verbose, o.LogPath)
		if daemonize {
			app.StartDaemon(args)
		} else {
			app.RestartSessions(args[0], server)
		}
	case "list":
		_ = listFlagSet.Parse(args[2:])
		app.DbHandler.SetPath(dbPath)
		if help {
			println("Use this command to list all sessions.")
			println("Usage: openport list [arguments]")
			listFlagSet.PrintDefaults()
			app.Stop(o.EXIT_CODE_HELP)
			return
		}
		o.InitLogging(verbose, o.LogPath)
		app.InitFiles()
		app.ListSessions()
		app.Stop(o.EXIT_CODE_LIST)

	case "rm":
		_ = rmFlagSet.Parse(args[2:])
		app.DbHandler.SetPath(dbPath)
		if help {
			println("Use this command to remove a port from your local database. This resets the remote port.")
			println("Usage: openport rm <local_port> [arguments]")
			rmFlagSet.PrintDefaults()
			app.Stop(o.EXIT_CODE_HELP)
			return
		}
		o.InitLogging(verbose, o.LogPath)
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
					app.Stop(o.EXIT_CODE_INVALID_ARGUMENT)
				}
			}
		}
		app.RemoveSession(port)
		app.Stop(o.EXIT_CODE_RM)

	case "selftest":
		// This is a test command that is used to test the client.
		utils.FailOnError(selfTestFlagSet.Parse(args[2:]), "error parsing args for selftest.")
		if help {
			println("Use this command to run a quick self-test of the application.")
			println("Usage: openport selftest [arguments]")
			selfTestFlagSet.PrintDefaults()
			app.Stop(o.EXIT_CODE_HELP)
			return
		}

		o.InitLogging(verbose, o.LogPath)
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
		var execCommand []string
		if forwardTunnel {
			// Everything after "exec" belongs to the command, so its own
			// flags must not reach the openport flag parser.
			forwardArgs := args[2:]
			for i, arg := range forwardArgs {
				if arg == "exec" {
					execCommand = forwardArgs[i+1:]
					forwardArgs = forwardArgs[:i]
					break
				}
			}
			_ = defaultFlagSet.Parse(forwardArgs)
			app.DbHandler.SetPath(dbPath)
			if help {
				println("Use this command to expose the port of your peer on a local port on your machine.")
				println("See https://openport.readthedocs.io/en/latest/recipes_create_a_forward_tunnel.html for more information.")
				println("Usage: openport forward --remote-port <server:server_port> [arguments] [exec <command>]")
				println("In the exec command, $port is replaced by the local port of the tunnel (single-quote")
				println("it so your shell does not expand it first).")
				forwardTunnelFlagSet.PrintDefaults()
				app.Stop(o.EXIT_CODE_HELP)
				return
			}
			if useWS {
				log.Warn("Websockets are not supported for forward tunnels (yet). Let us know if you need this feature.")
				app.Stop(o.EXIT_CODE_INVALID_ARGUMENT)
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
			app.DbHandler.SetPath(dbPath)
			if help {
				println("Use this command to expose a local port of your machine to the internet.")
				println("See https://openport.readthedocs.io/ or https://openport.io for more information.")
				println("Usage: openport <command> [arguments]")
				println("Commands:")
				println("  <port>                Expose a local port to the internet.")
				println("  forward               Expose a port of your peer to this machine.")
				println("  connect <name> <port> Reach a port of another device of yours, by name.")
				println("  ssh [user@]<name>     SSH into another device of yours, by name.")
				println("  list                  List all sessions.")
				println("  kill <local_port>     Kill a session.")
				println("  kill-all              Kill all sessions.")
				println("  restart-sessions      Restart all sessions that are started with the --restart-on-reboot flag.")
				println("  rm <local_port>       Remove a port from your local database.")
				println("  register <token>      Link your device to your account.")
				println("  rotate-key <token>    Replace this machine's key with a new one.")
				println("  version               Show the version of the client executable.")
				println("Run 'openport <command> --help' for more information about the command.")
				println("")
				println("Default usage: openport <local_port> [arguments]")
				defaultFlagSet.PrintDefaults()
				app.Stop(o.EXIT_CODE_HELP)
				return
			}

			remotePortInt, err = strconv.Atoi(remotePort)
			if err != nil {
				log.Fatalf("Remote port needs to be an integer: %s %s", remotePort, err)
			}
		}
		o.InitLogging(verbose, o.LogPath)
		app.ExitOnFailureTimeout = exitOnFailureTimeout

		tail := defaultFlagSet.Args()
		if port == -1 {
			if len(tail) == 0 {
				if !forwardTunnel {
					log.Error("Missing a local port or command.")
					myUsage()
					defaultFlagSet.PrintDefaults()
					app.Stop(o.EXIT_CODE_INVALID_ARGUMENT)
				}
			} else {
				var err error
				port, err = strconv.Atoi(tail[0])
				if err != nil {
					log.Warnf("Unknown command: %s", tail)
					myUsage()
					defaultFlagSet.PrintDefaults()
					app.Stop(o.EXIT_CODE_INVALID_ARGUMENT)
				}
			}
		}

		if *customDomain != "" && !*tlsPassthrough {
			log.Fatal("--domain requires --tls-passthrough")
		}
		if *tlsPassthrough && forwardTunnel {
			// A forward tunnel has no public side to terminate TLS for; the
			// terminator would start but nothing could ever dial it.
			log.Fatal("--tls-passthrough only applies to sessions that expose a local port, not to 'openport forward'")
		}
		if *tlsPassthrough {
			if (*tlsCertPath == "") != (*tlsKeyPath == "") {
				log.Fatal("--tls-cert and --tls-key must be given together")
			}
			if *customDomain == "" && *tlsCertPath == "" && !*localTLS {
				// Let's Encrypt would issue for the <xxxxx>.u.openport.io
				// address through the tunnel, but those certificates draw
				// from the openport.io per-domain rate limit that the
				// servers' own wildcard renewals depend on. Off the table
				// until u.openport.io is on the Public Suffix List.
				log.Fatal("--tls-passthrough needs one of --domain, --tls-cert or --local-tls")
			}
			// The paths are persisted and replayed by restart-sessions from a
			// different working directory, so relative spellings must be
			// pinned down now.
			if *tlsCertPath != "" {
				*tlsCertPath = mustAbs("--tls-cert", *tlsCertPath)
				*tlsKeyPath = mustAbs("--tls-key", *tlsKeyPath)
			}
			*httpForward = true
		}
		if *localTLS && !*tlsPassthrough {
			log.Fatal("--local-tls requires --tls-passthrough")
		}
		if *localTLS && (*tlsCertPath != "" || *tlsKeyPath != "") {
			log.Fatal("--local-tls means the local service owns the certificate; drop --tls-cert/--tls-key")
		}
		if *localProxyProtocol && !*localTLS {
			log.Fatal("--local-proxy-protocol requires --local-tls")
		}

		if len(execCommand) > 0 {
			if restartOnReboot {
				log.Fatal("--restart-on-reboot cannot be combined with an exec command")
			}
			if daemonize {
				log.Fatal("--daemonize cannot be combined with an exec command")
			}
			app.SetExecCommand(execCommand)
		}

		if daemonize {
			app.StartDaemon(args)
			return
		}

		app.Session = db.Session{
			LocalPort:           port,
			UseIpLinkProtection: useIpLinkProtection,
			HttpForward:         *httpForward,
			TlsPassthrough:      *tlsPassthrough,
			CustomDomain:        *customDomain,
			TlsCertPath:         *tlsCertPath,
			TlsKeyPath:          *tlsKeyPath,
			AcmeDirectory:       *acmeDirectory,
			LocalTLS:            *localTLS,
			LocalProxyProtocol:  *localProxyProtocol,
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
			restartCommand := stripAutomaticRestart(args[1:])
			if *tlsCertPath != "" {
				// Replayed from a different working directory on boot, so the
				// stored command must carry the absolutized paths.
				restartCommand = rewriteFlagValue(restartCommand, "--tls-cert", *tlsCertPath)
				restartCommand = rewriteFlagValue(restartCommand, "--tls-key", *tlsKeyPath)
			}
			app.Session.RestartCommand = strings.Join(restartCommand, " ")
		}
		app.InitFiles()
		app.CreateTunnel()
	}
	app.Stop(0)
}

// stripAutomaticRestart removes every spelling of the hidden
// --automatic-restart flag from a saved command line. The flag marks the
// current run as an automatic restart; persisting it would make every
// restart-sessions replay behave like one.
//
// pflag accepts more spellings than the bare tokens: "--automatic-restart=true",
// the shorthand combined with other flags ("-va"), and the shorthand with a
// value ("-a=true"). All of them have to go; the other flags in a combined
// group have to stay.
func stripAutomaticRestart(args []string) []string {
	result := make([]string, 0, len(args))
	for i, arg := range args {
		if arg == "--" {
			// Everything after the terminator is positional; keep it as-is.
			result = append(result, args[i:]...)
			break
		}
		if arg == "--automatic-restart" || strings.HasPrefix(arg, "--automatic-restart=") {
			continue
		}
		if len(arg) > 1 && arg[0] == '-' && arg[1] != '-' {
			letters, value, hasValue := strings.Cut(arg[1:], "=")
			if strings.ContainsRune(letters, 'a') {
				// A "=value" binds to the last shorthand in the group; drop it
				// only when that was the flag being stripped.
				if hasValue && strings.HasSuffix(letters, "a") {
					hasValue = false
				}
				letters = strings.ReplaceAll(letters, "a", "")
				if letters == "" {
					continue
				}
				arg = "-" + letters
				if hasValue {
					arg += "=" + value
				}
			}
		}
		result = append(result, arg)
	}
	return result
}

// mustAbs resolves a user-supplied flag path against the current working
// directory, so a relative spelling still points at the same file when the
// session is replayed from somewhere else.
func mustAbs(flagName, p string) string {
	abs, err := filepath.Abs(p)
	if err != nil {
		log.Fatalf("could not resolve %s path %q: %s", flagName, p, err)
	}
	return abs
}

// rewriteFlagValue replaces the value of a long flag in a saved command
// line, handling both the "--flag value" and "--flag=value" spellings.
// Everything after a "--" terminator is positional and stays untouched.
func rewriteFlagValue(args []string, flagName, value string) []string {
	result := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			result = append(result, args[i:]...)
			break
		}
		switch {
		case arg == flagName && i+1 < len(args):
			result = append(result, arg, value)
			i++
		case strings.HasPrefix(arg, flagName+"="):
			result = append(result, flagName+"="+value)
		default:
			result = append(result, arg)
		}
	}
	return result
}

// parseConnectTarget extracts the device name and that device's local port
// from the positional arguments of "openport connect": either two arguments
// ("device-a 22") or one joined with a colon ("device-a:22").
func parseConnectTarget(tail []string) (string, int, error) {
	var device, portString string
	switch len(tail) {
	case 1:
		colon := strings.LastIndex(tail[0], ":")
		if colon < 0 {
			return "", 0, fmt.Errorf("missing the port to connect to on '%s'", tail[0])
		}
		device, portString = tail[0][:colon], tail[0][colon+1:]
	case 2:
		device, portString = tail[0], tail[1]
	default:
		return "", 0, fmt.Errorf("expected <device-name> <port>, got: %s", strings.Join(tail, " "))
	}
	port, err := strconv.Atoi(portString)
	if err != nil || port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("invalid port: %s", portString)
	}
	if device == "" {
		return "", 0, fmt.Errorf("missing device name")
	}
	return device, port, nil
}

// The OpenSSH options that take a value, from ssh's getopt string. An ssh
// option before the destination must be kept out of the destination search,
// together with its value ("-i key.pem").
const sshOptionsWithValue = "BbceilmopDEFIJLOQRSWw"

// splitSSHArgs separates the arguments of "openport ssh" into openport's own
// flags (--long form, before the destination), ssh options (-short form,
// before the destination), the destination, and the remote command (all that
// follows the destination). Short options follow getopt: they can be grouped
// ("-Ai key.pem"), and a value can be attached ("-p2222"). "-p" is taken out
// of the ssh options: ssh always dials the tunnel, so it is the port of the
// ssh server on the device instead (0 when not given).
func splitSSHArgs(args []string, opFlagSet *flag.FlagSet) (opFlags []string, sshOptions []string, destination string, remoteCommand []string, devicePort string) {
	i := 0
	for i < len(args) {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "--"):
			opFlags = append(opFlags, arg)
			name, _, hasValue := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			f := opFlagSet.Lookup(name)
			if !hasValue && f != nil && f.Value.Type() != "bool" && i+1 < len(args) {
				i++
				opFlags = append(opFlags, args[i])
			}
		case strings.HasPrefix(arg, "-") && len(arg) > 1:
			flags := arg[1:]
			for j := 0; j < len(flags); j++ {
				if !strings.ContainsRune(sshOptionsWithValue, rune(flags[j])) {
					continue
				}
				option, value := flags[:j+1], flags[j+1:]
				if value == "" && i+1 < len(args) {
					i++
					value = args[i]
				}
				if flags[j] == 'p' {
					devicePort = value
					if j > 0 {
						sshOptions = append(sshOptions, "-"+flags[:j])
					}
				} else {
					sshOptions = append(sshOptions, "-"+option, value)
				}
				flags = ""
				break
			}
			if flags != "" {
				sshOptions = append(sshOptions, arg)
			}
		default:
			destination = arg
			remoteCommand = args[i+1:]
			return
		}
		i++
	}
	return
}

// splitUserDevice splits "root@device-a" into user and device name. Like ssh,
// the part before the last "@" is the user, so a user containing "@" still
// works; no "@" means no user (ssh falls back to the local username).
func splitUserDevice(destination string) (string, string) {
	at := strings.LastIndex(destination, "@")
	if at < 0 {
		return "", destination
	}
	return destination[:at], destination[at+1:]
}

// buildSSHCommand assembles the ssh invocation for "openport ssh". The tunnel
// ends on 127.0.0.1 at an ephemeral port, so HostKeyAlias pins the known_hosts
// entry to the device name instead: the host key stays verified across ports,
// and a different machine answering to the same name is flagged. Like ssh's
// own "[host]:port" entries, a non-default device port gets its own entry.
func buildSSHCommand(sshUser string, device string, devicePort int, sshOptions []string, remoteCommand []string) []string {
	hostKeyAlias := "openport-" + device
	if devicePort != 22 {
		hostKeyAlias = fmt.Sprintf("%s:%d", hostKeyAlias, devicePort)
	}
	command := []string{"ssh", "-p", "$port", "-o", "HostKeyAlias=" + hostKeyAlias}
	if sshUser != "" {
		command = append(command, "-l", sshUser)
	}
	command = append(command, sshOptions...)
	command = append(command, "127.0.0.1")
	return append(command, remoteCommand...)
}

func myUsage() {
	fmt.Printf("Usage: %s (<port> | forward | connect | ssh | list | restart-sessions | kill <port> | kill-all | register <token> | rotate-key <token> | rm <port> | version) [arguments]\n", os.Args[0])
	fmt.Println("Type 'openport <command> --help' for more information about the different commands.")
	fmt.Println("Default: openport <port> [arguments]")
}
