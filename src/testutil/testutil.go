// Package testutil holds test helpers shared across the project's test
// packages. It lives in its own package (not a _test.go file in package
// openport) so it can be imported by tests in other packages without pulling
// the testing framework into the production openport binary.
package testutil

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/phayes/freeport"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func AssertEqual(t *testing.T, a interface{}, b interface{}) {
	if a != b {
		debug.PrintStack()
		t.Fatalf("%s != %s", a, b)
	}
}

func FailIfError(t *testing.T, err error) {
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
	httpServer := &http.Server{
		Addr:              fmt.Sprintf("0.0.0.0:%d", port),
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go httpServer.ListenAndServe()
	return httpServer
}

var httpClient = http.Client{
	Timeout: 5 * time.Second,
}

func ClickLink(t *testing.T, link string) {
	log.Infof("Clicking link %s", link)
	resp, err := httpClient.Get(link)
	FailIfError(t, err)

	defer resp.Body.Close()

	responseBody, err := io.ReadAll(resp.Body)
	FailIfError(t, err)
	log.Debug(string(responseBody))
	assert.True(t, strings.Contains(string(responseBody), "is now available from your IP"))
}

func CheckTcpForward(t *testing.T, localPort int, server string, remotePort int) {

	// LOCAL SERVER
	httpServer := startHTTPServer(localPort)
	defer httpServer.Close()

	time.Sleep(1 * time.Second)

	// Test Local Server
	resp, err := httpClient.Get(fmt.Sprintf("http://localhost:%d", localPort))
	FailIfError(t, err)
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	FailIfError(t, err)
	AssertEqual(t, "hello", strings.TrimSpace(string(responseBody)))

	// Test Remote Server
	resp, err = httpClient.Get(fmt.Sprintf("http://%s:%d", server, remotePort))
	FailIfError(t, err)
	defer resp.Body.Close()
	responseBody, err = io.ReadAll(resp.Body)
	FailIfError(t, err)
	AssertEqual(t, "hello", strings.TrimSpace(string(responseBody)))

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

func TimeoutFunction(t *testing.T, f func() string, timeout time.Duration) string {
	appReady := make(chan string, 1)

	var result string
	go func() {
		result = f()
		appReady <- "ready"
	}()

	select {
	case res := <-appReady:
		fmt.Println(res)
	case <-time.After(timeout):
		debug.PrintStack()
		t.Fatal("Function did not return in time")
	}
	return result
}

func GetFreePort(t *testing.T) int {
	port, err := freeport.GetFreePort()
	FailIfError(t, err)
	return port
}

func DefaultEnv(key string, deflt string) string {
	result := deflt
	if os.Getenv(key) != "" {
		result = os.Getenv(key)
	}
	return result
}

func CopyFile(src, dst string) error {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}
