package openport

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"slices"
	"strings"

	"github.com/jedib0t/go-pretty/table"
	"github.com/jedib0t/go-pretty/text"
	ogrek "github.com/kisielk/og-rek"
	db "github.com/openportio/openport-go/database"
	"github.com/openportio/openport-go/utils"
	log "github.com/sirupsen/logrus"
)

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
	log.Debugf("Restarting Sessions -> %s %s %s", appPath, server, app.DbHandler.Path())
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
				// Running with -H is needed because ubuntu < 19.10 did not set the HOME variable to the target user's home
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

func (app *App) getRestartCommandBasedOnSessionContent(session db.Session, server string) []string {
	var restartCommand []string
	if session.LocalPort != 0 {
		restartCommand = append(restartCommand, fmt.Sprintf("%d", session.LocalPort))
	}

	return restartCommand
}

func (app *App) getRestartCommand(session db.Session, server string) []string {
	restartCommand := strings.Split(session.RestartCommand, " ")
	if (len(restartCommand) > 1 && len(restartCommand[1]) > 0 && restartCommand[1][0] != '-' && restartCommand[0] != "--port") ||
		strings.Contains(restartCommand[0], "\n") ||
		(len(restartCommand[0]) > 0 && restartCommand[0][0] == 0x80) {
		log.Debugf("Migrating from older version: %s", session.RestartCommand)
		// Python pickle
		buf := bytes.NewBufferString(session.RestartCommand)
		dec := ogrek.NewDecoder(buf)
		unpickled, err := dec.Decode()
		if err != nil {
			log.Error(err)
			restartCommand = app.getRestartCommandBasedOnSessionContent(session, server)
		} else {
			log.Debugf("this is unpickled : <%s>", unpickled)
			// The pickle comes from the local DB (written by the old Python
			// client), never from the server -- but a corrupt entry must not
			// panic the client, so no unchecked type assertions here.
			restartCommand = []string{}
			switch unpickledValue := unpickled.(type) {
			case []interface{}:
				for _, part := range unpickledValue {
					if partString, ok := part.(string); ok {
						restartCommand = append(restartCommand, partString)
					} else {
						log.Warnf("Ignoring non-string element in pickled restart command: %v", part)
					}
				}
			case string:
				if unpickledValue != "" {
					restartCommand = []string{unpickledValue}
				}
			default:
				log.Warnf("Unexpected pickled restart command type %T", unpickled)
			}
			if len(restartCommand) == 0 {
				restartCommand = app.getRestartCommandBasedOnSessionContent(session, server)
			}
			if len(restartCommand) > 0 && strings.Contains(restartCommand[0], "openport") {
				restartCommand = restartCommand[1:]
			}
		}
	}
	if len(restartCommand) == 0 {
		log.Warnf("Session %d will not be restarted", session.LocalPort)
	}

	if server != DEFAULT_SERVER {
		restartCommand = append(restartCommand, "--server", server)
	}
	if app.DbHandler.Path() != db.DEFAULT_OPENPORT_DB_PATH {
		restartCommand = append(restartCommand, "--database", app.DbHandler.Path())
	}
	if !slices.Contains(restartCommand, "--automatic") && !slices.Contains(restartCommand, "-a") {
		restartCommand = append(restartCommand, "--automatic-restart")
	}
	return restartCommand

}

func (app *App) restartSessionsForCurrentUser(appPath string, server string) {
	if !utils.FileExists(app.DbHandler.Path()) {
		log.Debugf("DB file %s does not exist. Not restarting anything.", app.DbHandler.Path())
		return
	}

	sessions, err := app.DbHandler.GetSessionsToRestart()
	if err != nil {
		log.Error("Error getting sessions to restart: ", err)
		return
	}
	for _, session := range sessions {
		log.Debug("Restarting session: ", session.LocalPort)
		restartCommand := app.getRestartCommand(session, server)
		if len(restartCommand) == 0 {
			log.Warnf("Session %d will not be restarted", session.LocalPort)
			continue
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
