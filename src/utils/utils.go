package utils

import log "github.com/sirupsen/logrus"

func FailOnError(err error, msg string) {
	if err != nil {
		log.Panicf("%s: %s", msg, err)
	}
}
