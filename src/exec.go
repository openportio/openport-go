package openport

import (
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
)

// ExecCommand, when set, is run once the forward tunnel is up ("openport
// connect ... exec <command>" / "openport ssh ..."). Every "$port" or
// "${port}" in it is replaced by the tunnel's local port, and the app exits
// with the command's exit code when it finishes.
type execHandler struct {
	Command []string
	once    sync.Once
	cmd     *exec.Cmd
	mu      sync.Mutex
}

// SetExecCommand attaches the command to run once the tunnel connects.
func (app *App) SetExecCommand(command []string) {
	app.Exec = &execHandler{Command: command}
}

// substitutePort fills the tunnel's local port into a command template.
// The $-spellings must be single-quoted by the user so their own shell does
// not expand them first.
func substitutePort(arg string, port int) string {
	p := strconv.Itoa(port)
	arg = strings.ReplaceAll(arg, "${port}", p)
	return strings.ReplaceAll(arg, "$port", p)
}

// StartExecOnce launches the exec command the first time the tunnel
// connects. Reconnects of the tunnel must not restart the command, and the
// command keeps running across them: it owns the session's lifetime.
func (app *App) StartExecOnce() {
	if app.Exec == nil || len(app.Exec.Command) == 0 {
		return
	}
	app.Exec.once.Do(func() {
		go app.runExecCommand()
	})
}

func (app *App) runExecCommand() {
	command := make([]string, len(app.Exec.Command))
	for i, arg := range app.Exec.Command {
		command[i] = substitutePort(arg, app.Session.LocalPort)
	}

	// A single argument with spaces was quoted as one command line by the
	// user; hand it to a shell so pipes and quoting work.
	var cmd *exec.Cmd
	if len(command) == 1 && strings.ContainsAny(command[0], " \t") {
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/C", command[0])
		} else {
			cmd = exec.Command("/bin/sh", "-c", command[0])
		}
	} else {
		cmd = exec.Command(command[0], command[1:]...)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	log.Debugf("executing: %s", strings.Join(command, " "))
	app.Exec.mu.Lock()
	err := cmd.Start()
	if err == nil {
		app.Exec.cmd = cmd
	}
	app.Exec.mu.Unlock()
	if err != nil {
		log.Errorf("could not start command: %s", err)
		app.Stop(EXIT_CODE_INVALID_ARGUMENT)
		return
	}

	err = cmd.Wait()
	exitCode := 0
	if err != nil {
		exitCode = 1
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
	}
	log.Debugf("command exited with code %d", exitCode)
	// The command owns the session: when it is done the tunnel is done, and
	// the session must not show up as active in "openport list".
	app.DbHandler.SetInactive(&app.Session)
	app.Stop(exitCode)
}

// handleExecSignals replaces the default SIGINT handling while a command is
// attached. Ctrl-c belongs to the command (an interactive ssh forwards it to
// the remote side), so the tunnel must not die on it: the session ends when
// the command exits. Until the command has started there is nobody else to
// handle ctrl-c, so it aborts the session as usual (e.g. while the device is
// still offline). SIGTERM still tears everything down, taking the command
// with it.
func handleExecSignals(app *App) {
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, syscall.SIGINT)
	go func() {
		for sig := range interrupts {
			app.Exec.mu.Lock()
			started := app.Exec.cmd != nil
			app.Exec.mu.Unlock()
			if !started {
				log.Infof("Got signal %d. Exiting.", sig)
				app.Stop(EXIT_CODE_INTERRUPTED)
				return
			}
			// Delivered to the whole foreground process group, so the child
			// got its own copy; nothing to forward, just don't exit.
			log.Debug("ignoring SIGINT; the exec command decides when the session ends")
		}
	}()

	terms := make(chan os.Signal, 1)
	signal.Notify(terms, syscall.SIGTERM)
	go func() {
		<-terms
		app.Exec.mu.Lock()
		cmd := app.Exec.cmd
		app.Exec.mu.Unlock()
		if cmd != nil && cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		app.Stop(EXIT_CODE_INTERRUPTED)
	}()
}
