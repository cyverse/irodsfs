package commons

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
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

// CheckFuse checks FUSE installation state
func CheckFuse() CheckFUSEStatus {
	if runtime.GOOS == "linux" {
		// check if FUSE device exists
		return CheckDevFuse()
	} else if runtime.GOOS == "darwin" {
		// cannot run on MacOS, support is dropped by fuse library
		return CheckFUSEStatusCannotRun
	} else if runtime.GOOS == "windows" {
		// no fuse on Windows
		return CheckFUSEStatusCannotRun
	}

	// unknown os?
	return CheckFUSEStatusUnknown
}

// CheckDevFuse checks FUSE device
func CheckDevFuse() CheckFUSEStatus {
	logger := log.WithFields(log.Fields{
		"package":  "main",
		"function": "CheckDevFuse",
	})

	// if /dev/fuse device exists, it's installed
	fuseDevInfo, err := os.Stat("/dev/fuse")
	if err != nil {
		logger.WithError(err).Errorf("failed to find /dev/fuse, fuse is not installed or does not have enough privilege")
		return CheckFUSEStatusNotFound
	}

	// /dev/fuse device must be a character device
	if (fuseDevInfo.Mode() & os.ModeCharDevice) == os.ModeCharDevice {
		return CheckFUSEStatusFound
	}

	return CheckFUSEStatusUnknown
}

// unmountFuse unmounts FUSE device
func UnmountFuse(dir string) error {
	cmd := exec.Command("fusermount", "-zu", dir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if len(output) > 0 {
			output = bytes.TrimRight(output, "\n")
			msg := err.Error() + ": " + string(output)
			err = errors.New(msg)
		}
		return err
	}
	return nil
}
