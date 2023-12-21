package utils

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
	"net"
	"net/url"
)

func FailOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}

func GetProxyConn(proxyStr string, primaryAddr string, fallbackAddr string) (net.Conn, string, error) {
	// create a socks5 dialer
	u, err := url.Parse(proxyStr)
	if err != nil {
		log.Fatalf("Could not parse proxy server: %s", err)
	}
	var proxyAuth *proxy.Auth = nil
	proxyPassword, proxyPasswordSet := u.User.Password()
	if proxyPasswordSet {
		proxyAuth = &proxy.Auth{
			User:     u.User.Username(),
			Password: proxyPassword,
		}
	}
	log.Debug(u)
	var proxyPort = u.Port()
	if proxyPort == "" {
		proxyPort = "1080"
	}
	proxyServer := fmt.Sprintf("%s:%s", u.Hostname(), proxyPort)
	log.Debug("proxy Server: ", proxyServer)

	proxyDialer, err := proxy.SOCKS5("tcp", proxyServer, proxyAuth, proxy.Direct)
	if err != nil {
		log.Warnf("can't connect to the proxy: %s", err)
		return nil, "", err
	}
	connectedToHost := primaryAddr
	conn, err := proxyDialer.Dial("tcp", primaryAddr)
	if err != nil {
		log.Debugf("%s -> falling back to %s", err, fallbackAddr)
		connectedToHost = fallbackAddr
		conn, err = proxyDialer.Dial("tcp", fallbackAddr)
		if err != nil {
			return nil, "", err
		}
	}
	return conn, connectedToHost, err
}
