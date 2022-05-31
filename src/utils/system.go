package utils

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"net"
)

func PortIsAvailable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Warnf("Can't listen on port %q: %s", port, err)
		return false
	}
	_ = ln.Close()
	return true
}
