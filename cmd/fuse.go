package main

import (
	"os"
	"runtime"

	log "github.com/sirupsen/logrus"
)

// CheckFUSEStatus is used to describe FUSE installation state
type CheckFUSEStatus string

const (
	CheckFUSEStatusFound     CheckFUSEStatus = "found"
	CheckFUSEStatusNotFound  CheckFUSEStatus = "notfound"
	CheckFUSEStatusCannotRun CheckFUSEStatus = "cannotrun"
	CheckFUSEStatusUnknown   CheckFUSEStatus = "unknown"
)

// checkFuse checks FUSE installation state
func checkFuse() CheckFUSEStatus {
	if runtime.GOOS == "linux" {
		// check if FUSE device exists
		return checkDevFuse()
	} else if runtime.GOOS == "darwin" {
		// cannot run on MacOS, bazil.org/fuse does not support
		return CheckFUSEStatusCannotRun
	} else if runtime.GOOS == "windows" {
		// no fuse on Windows
		return CheckFUSEStatusCannotRun
	}

	// unknown os?
	return CheckFUSEStatusUnknown
}

// checkDevFuse checks FUSE device
func checkDevFuse() CheckFUSEStatus {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "checkDevFuse",
	})

	// if /dev/fuse device exists, it's installed
	fuseDevInfo, err := os.Stat("/dev/fuse")
	if err != nil {
		logger.WithError(err).Errorf("cannot find /dev/fuse, fuse is not installed or does not have enough privilege")
		return CheckFUSEStatusNotFound
	}

	// /dev/fuse device must be a character device
	if (fuseDevInfo.Mode() & os.ModeCharDevice) == os.ModeCharDevice {
		return CheckFUSEStatusFound
	}

	return CheckFUSEStatusUnknown
}
