package logger

import (
	log "github.com/sirupsen/logrus"
)

func Init(verbose bool) {
	if verbose {
		log.SetFormatter(&log.TextFormatter{
			FullTimestamp: true,
			ForceColors:   true,
		})
		log.SetLevel(log.DebugLevel)
	} else {
		log.SetFormatter(&log.TextFormatter{
			DisableTimestamp: true,
			ForceColors:      true,
		})
		log.SetLevel(log.InfoLevel)
	}
}
