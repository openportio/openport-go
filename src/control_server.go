package openport

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/phayes/freeport"
	log "github.com/sirupsen/logrus"
)

func (app *App) StopSession(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(w, "Ok")
	app.Stop(EXIT_CODE_REMOTE_STOP)

	// TODO: stop session from restarting.  Done?
	// TODO: Force flag
}

func (app *App) InfoRequest(w http.ResponseWriter, _ *http.Request) {
	fmt.Fprintln(w, "openport")
}

func (app *App) StartControlServer(controlPort int) int {
	if controlPort <= 0 {
		var err error
		controlPort, err = freeport.GetFreePort()
		if err != nil {
			log.Fatalf("Could not start control server: %s", err)
		}
	}
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/exit", app.StopSession)
	router.HandleFunc("/info", app.InfoRequest)
	log.Debugf("Listening for control on port %d", controlPort)
	server := &http.Server{
		Addr:              fmt.Sprintf("127.0.0.1:%d", controlPort),
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Errorf("Control server stopped: %s", err)
		}
	}()
	return controlPort
}
