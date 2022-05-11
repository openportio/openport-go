package main

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/phayes/freeport"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"io/ioutil"
	"net/http"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func assertEqual(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		debug.PrintStack()
		t.Fatalf("%s != %s", a, b)
	}
}

func failIfError(t *testing.T, err error) {
	if err != nil {
		debug.PrintStack()
		t.Fatal(err)
	}
}

func hello(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "hello\n")
}

func startHTTPServer(port int) *http.Server {
	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/", hello)
	log.Infof("Starting HTTP server on port %d", port)
	httpServer := &http.Server{Addr: fmt.Sprintf("0.0.0.0:%d", port), Handler: router}

	go httpServer.ListenAndServe()
	return httpServer
}

var httpClient = http.Client{
	Timeout: 2 * time.Second,
}

func ClickLink(t *testing.T, link string) {
	resp, err := httpClient.Get(link)
	failIfError(t, err)

	defer resp.Body.Close()

	responseBody, err := ioutil.ReadAll(resp.Body)
	failIfError(t, err)
	assert.True(t, strings.Contains(string(responseBody), "Port is now open"))
}

func CheckTcpForward(t *testing.T, localPort int, server string, remotePort int) {

	// LOCAL SERVER
	httpServer := startHTTPServer(localPort)
	defer httpServer.Close()

	time.Sleep(1 * time.Second)

	// Test Local Server
	resp, err := httpClient.Get(fmt.Sprintf("http://localhost:%d", localPort))
	failIfError(t, err)
	defer resp.Body.Close()
	responseBody, err := ioutil.ReadAll(resp.Body)
	failIfError(t, err)
	assertEqual(t, "hello", strings.TrimSpace(string(responseBody)))

	// Test Remote Server
	resp, err = httpClient.Get(fmt.Sprintf("http://%s:%d", server, remotePort))
	failIfError(t, err)
	defer resp.Body.Close()
	responseBody, err = ioutil.ReadAll(resp.Body)
	failIfError(t, err)
	assertEqual(t, "hello", strings.TrimSpace(string(responseBody)))

}

func CheckTcpForwardFails(t *testing.T, localPort int, server string, remotePort int) {
	// LOCAL SERVER
	httpServer := startHTTPServer(localPort)
	defer httpServer.Close()

	time.Sleep(1 * time.Second)

	// Test Remote Server
	_, err := httpClient.Get(fmt.Sprintf("http://%s:%d", server, remotePort))
	if err == nil {
		t.Fatalf("expected forward to fail")
	}
}

func waitForApp(t *testing.T, app *OpenportApp) {
	appReady := make(chan string, 1)

	go func() {
		for app.Session.RemotePort < 1 {
			time.Sleep(10 * time.Millisecond)
		}
		appReady <- fmt.Sprintf("ok, got port %d", app.Session.RemotePort)
	}()

	select {
	case res := <-appReady:
		fmt.Println(res)
	case <-time.After(10 * time.Second):
		app.Stop()
		t.Fatal("App did not connect in time")
	}
}

func timeoutFunction(t *testing.T, f func(), timeout time.Duration) {
	appReady := make(chan string, 1)

	go func() {
		f()
		appReady <- "ready"
	}()

	select {
	case res := <-appReady:
		fmt.Println(res)
	case <-time.After(timeout):
		t.Fatal("Function did not return in time")
	}
}

func getFreePort(t *testing.T) int {
	port, err := freeport.GetFreePort()
	failIfError(t, err)
	return port
}
