package openport

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	db "github.com/openportio/openport-go/database"
	"github.com/openportio/openport-go/utils"
	log "github.com/sirupsen/logrus"
)

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
	FatalError            bool    `json:"fatal_error"`
	// HostKey is the SSH server's public host key in authorized_keys format.
	// Empty when talking to a server that predates host key publication; the
	// client then falls back to trust-on-first-use. See utils/hostkey.go.
	HostKey string `json:"host_key"`
	// TlsPassthrough is the server's explicit acknowledgement that it will
	// route the forward's TLS bytes through without terminating them. Old
	// servers drop unknown form fields and leave this false; terminating
	// TLS locally against such a server would serve TLS into TLS.
	TlsPassthrough bool `json:"tls_passthrough"`
}

type RegisterKeyResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	// Set by servers that understand replaces_public_key ("processed" or
	// "no-active-key"). Empty means the server ignored the field: Django
	// drops unknown form fields silently, so without this acknowledgement a
	// "status: ok" proves nothing about the old key being retired.
	KeyRotation string `json:"key_rotation"`
}

type ServerResponseError struct {
	error string
}

func (s ServerResponseError) Error() string {
	return s.error
}

func (app *App) RegisterKey(keyBindingToken string, name string, proxy string, server string) {
	app.registerKey(keyBindingToken, name, proxy, server, false)
}

// RotateKey generates a fresh identity key and registers it, telling the
// server to retire the key it replaces.
func (app *App) RotateKey(keyBindingToken string, name string, proxy string, server string) {
	app.registerKey(keyBindingToken, name, proxy, server, true)
}

func (app *App) registerKey(keyBindingToken string, name string, proxy string, server string, forceRotate bool) {
	utils.EnsureHomeFolderExists()
	publicKey, signer, err := utils.EnsureKeysExist()
	if err != nil {
		log.Fatalf("Could not get key: %s", err)
	}

	// Registering is the natural moment to replace a weak key: the binding
	// token proves account ownership, so the new key can be attached to the
	// same account and the old one retired in a single request.
	//
	// Rotation is not done automatically outside this flow. The public key is
	// the account identity, so replacing it without a token would detach the
	// client from its account.
	var replacesPublicKey []byte
	restoreKey := func() {}
	weak, bits := utils.KeyIsWeak(signer)
	if forceRotate || weak {
		if weak {
			log.Infof("Replacing your %d-bit key with a %d-bit one.", bits, utils.KeyBits)
		} else {
			log.Infof("Generating a new %d-bit key.", utils.KeyBits)
		}
		replacesPublicKey, publicKey, restoreKey, err = utils.RotateKeys()
		if err != nil {
			log.Fatalf("Could not create a new key: %s", err)
		}
	}

	// If registration fails after rotating, put the old key back. Otherwise the
	// client is left holding a key the server has never seen, which means
	// losing access to the account entirely.
	//
	// This cannot be a deferred call: log.Fatalf exits the process and never
	// runs deferred functions, so every failure path has to restore first.
	fail := func(format string, args ...interface{}) {
		restoreKey()
		log.Fatalf(format, args...)
	}

	httpClient := GetHttpClient(proxy)
	postUrl := fmt.Sprintf("%s/linkKey", server)
	sendRegistration := func(publicKey []byte, replacesPublicKey []byte) RegisterKeyResponse {
		getParameters := url.Values{
			"public_key":        {string(publicKey)},
			"key_binding_token": {keyBindingToken},
			"key_name":          {name},
			"client_version":    {VERSION},
			"platform":          {runtime.GOOS},
		}
		if replacesPublicKey != nil {
			// Tells the server to retire the key this one replaces, and to move
			// its reserved ports across. Only honoured within the account the
			// token belongs to.
			getParameters["replaces_public_key"] = []string{string(replacesPublicKey)}
		}
		log.Debugf("parameters: %s", getParameters)
		resp, err := httpClient.PostForm(postUrl, getParameters)
		if err != nil {
			fail("HTTP error: %s", err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fail("Body error: %s", err)
		}
		log.Debugf("%s", string(body))
		response := RegisterKeyResponse{}
		if jsonErr := json.Unmarshal(body, &response); jsonErr != nil {
			fail("Json Decode error: %s", jsonErr)
		}
		return response
	}

	response := sendRegistration(publicKey, replacesPublicKey)
	if response.Status != "ok" {
		fail("Could not register key: %s", response.Error)
		app.Stop(EXIT_CODE_KEY_REGISTERED_FAILED)
	}

	// A rotation only happened if the server says it processed
	// replaces_public_key. Servers that predate the field return "ok" while
	// ignoring it entirely, which would leave the old key active server-side
	// as a live credential and the reserved ports behind on it.
	if replacesPublicKey != nil && response.KeyRotation == "" {
		restoreKey()
		if forceRotate {
			log.Fatalf("The server does not support key rotation yet; your " +
				"previous key has been restored and nothing was changed. " +
				"The key sent during this attempt is unused but registered: " +
				"you can remove it at https://openport.io/user/keys .")
		}
		// Plain "register" with a weak key: fall back to registering the
		// existing key so the command still does what it was asked to do,
		// and leave rotation for when the server supports it.
		log.Warnf("The server does not support key rotation; keeping your "+
			"existing %d-bit key and registering it unchanged. The new key "+
			"sent during this attempt is unused; you can remove it at "+
			"https://openport.io/user/keys .", bits)
		response = sendRegistration(replacesPublicKey, nil)
		if response.Status != "ok" {
			log.Fatalf("Could not register key: %s", response.Error)
		}
	}

	log.Info("key successfully registered")
	app.Stop(EXIT_CODE_KEY_REGISTERED_OK)
}

func GetHttpClient(proxy string) http.Client {
	if proxy == "" {
		return http.Client{
			Timeout: 60 * time.Second,
		}
	} else {
		p := strings.Replace(proxy, "socks5h", "socks5", 1)
		u, err := url.Parse(p)
		if err != nil {
			log.Fatalf("Could not parse proxy: %s", proxy)
		}
		tr := &http.Transport{
			Proxy: http.ProxyURL(u),
		}
		return http.Client{
			Transport: tr,
			Timeout:   60 * time.Second,
		}
	}
}

func (app *App) RequestPortForward(session *db.Session, publicKey []byte) (PortResponse, error) {
	httpClient := GetHttpClient(session.Proxy)

	postUrl := fmt.Sprintf("%s/api/v1/request-port", session.Server)
	getParameters := url.Values{
		"public_key":            {string(publicKey)},
		"request_port":          {strconv.Itoa(session.RemotePort)},
		"client_version":        {VERSION},
		"restart_session_token": {session.SessionToken},
		"local_port":            {strconv.Itoa(session.LocalPort)},
		"http_forward":          {strconv.FormatBool(session.HttpForward)},
		"platform":              {runtime.GOOS},
		"forward_tunnel":        {strconv.FormatBool(session.ForwardTunnel)},
		"request_server":        {session.SshServer},
		"automatic_restart":     {strconv.FormatBool(session.AutomaticRestart)},
	}
	if session.TlsPassthrough {
		getParameters["tls_passthrough"] = []string{"true"}
		if session.CustomDomain != "" {
			getParameters["custom_domain"] = []string{session.CustomDomain}
		}
	}
	switch strings.ToLower(session.UseIpLinkProtection) {
	case "true", "false":
		getParameters["ip_link_protection"] = []string{session.UseIpLinkProtection}
	case "":
	default:
		getParameters["ip_link_protection"] = []string{"True"}
	}
	log.Debugf("parameters: %s", getParameters)
	resp, err := httpClient.PostForm(postUrl, getParameters)
	if err != nil {
		log.Errorf("Error communicating with %s: %s", session.Server, err)
		return PortResponse{}, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debugf("http error")
		log.Warn(err)
		return PortResponse{}, err
	}
	log.Debug(string(body))
	response := PortResponse{}
	jsonErr := json.Unmarshal(body, &response)
	if jsonErr != nil {
		log.Warnf("json error: %s", err)
		return PortResponse{}, jsonErr
	}

	if response.Error != "" {
		if response.FatalError {
			log.Infof("Stopping session on request of server: %s", response.Error)
			app.DbHandler.SetInactive(session)
			app.Stop(EXIT_CODE_FATAL_SESSION_ERROR)
		}
		return PortResponse{}, ServerResponseError{response.Error}
	}

	if session.TlsPassthrough && !response.TlsPassthrough {
		// Without the explicit ack the server is still terminating TLS
		// itself, and serving TLS into that tunnel would break the forward.
		log.Error("This server does not support --tls-passthrough. Upgrade the server or drop the flag.")
		app.DbHandler.SetInactive(session)
		app.Stop(EXIT_CODE_FATAL_SESSION_ERROR)
		return PortResponse{}, ServerResponseError{"server does not support tls_passthrough"}
	}

	log.Debugf("ServerPort: %d", response.ServerPort)
	session.SessionToken = response.SessionToken
	session.RemotePort = response.ServerPort
	session.SshServer = response.ServerIP
	session.Pid = os.Getpid()
	session.AccountId = response.AccountId
	session.KeyId = response.KeyId
	session.HttpForwardAddress = response.HttpForwardAddress
	session.OpenPortForIpLink = response.OpenPortForIpLink
	session.FallbackSshServerIp = response.FallbackSshServerIp
	session.FallbackSshServerPort = response.FallbackSshServerPort
	// Only overwrite a stored host key when the server actually published one.
	// Otherwise a server that stops sending host_key would silently downgrade
	// a session that was previously verifying.
	if response.HostKey != "" {
		session.HostKey = response.HostKey
	}
	err = app.DbHandler.Save(session)

	if err != nil {
		log.Warn(err)
	}
	return response, nil
}
