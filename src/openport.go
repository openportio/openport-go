package openport

import (
	"container/list"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	db "github.com/openportio/openport-go/database"
	"github.com/openportio/openport-go/utils"
	"github.com/orandin/lumberjackrus"
	log "github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/writer"
)

// Overridable at build time for release traceability (CRA-COMPLIANCE-PLAN.md item 20):
//
//	go build -ldflags "-X github.com/openportio/openport-go.VERSION=x.y.z \
//	                   -X github.com/openportio/openport-go.GitSha=$(git rev-parse --short HEAD)"
var VERSION = "2.2.4-beta"
var GitSha = "unknown"

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

type App struct {
	Session              db.Session
	Stopped              bool
	StopHooks            *list.List
	DbHandler            db.DBHandlerInterface
	ExitCode             chan int // Blocking channel waiting for the exit code.
	ExitOnFailureTimeout int
	Connected            chan bool
	ConnectedState       ConnectionState

	// Zero value for the common non-passthrough sessions; only carries
	// state when --tls-passthrough is used. See custom_domain.go.
	passthrough tlsPassthroughHandler
}

func CreateApp() *App {
	app := &App{
		ExitOnFailureTimeout: -1,
		ExitCode:             make(chan int, 1),
		StopHooks:            list.New(),
		Connected:            make(chan bool, 1),
		DbHandler:            &db.DBHandler{},
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
		app.Stop(EXIT_CODE_DAEMONIZED_ERROR)
	} else {
		log.Info("Process started in background")
		app.Stop(EXIT_CODE_DAEMONIZED_OK)
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

func (app *App) RunSelfTest() {
	app.DbHandler = &db.DummyDBHandler{}
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
	response, err := httpClient.Get("http://" + app.Session.SshServer + ":" + strconv.Itoa(app.Session.RemotePort) + "/info")
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
