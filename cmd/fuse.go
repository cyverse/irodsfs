package main

import (
	"os"
	"runtime"

	log "github.com/sirupsen/logrus"
)

type CheckFUSEStatus string

const (
	CheckFUSEStatusFound     CheckFUSEStatus = "found"
	CheckFUSEStatusNotFound  CheckFUSEStatus = "notfound"
	CheckFUSEStatusCannotRun CheckFUSEStatus = "cannotrun"
	CheckFUSEStatusUnknown   CheckFUSEStatus = "unknown"
)

func checkFuse() CheckFUSEStatus {
	if runtime.GOOS == "linux" {
		return checkDevFuse()
	} else if runtime.GOOS == "darwin" {
		return checkDevFuse()
	} else if runtime.GOOS == "windows" {
		return CheckFUSEStatusCannotRun
	}

	return CheckFUSEStatusUnknown
}

func checkDevFuse() CheckFUSEStatus {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "checkDevFuse",
	})

	fuseDevInfo, err := os.Stat("/dev/fuse")
	if err != nil {
		logger.WithError(err).Errorf("cannot find /dev/fuse, fuse is not installed or does not have enough privilege")
		return CheckFUSEStatusNotFound
	}

	if (fuseDevInfo.Mode() & os.ModeCharDevice) == os.ModeCharDevice {
		return CheckFUSEStatusFound
	}

	return CheckFUSEStatusUnknown
}
