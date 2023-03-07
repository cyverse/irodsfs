package utils

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
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

// Unmount calls fusermount -uz on the mount.
func UnmountFuse(mountPoint string) (err error) {
	bin, err := fusermountBinary()
	if err != nil {
		return err
	}
	errBuf := bytes.Buffer{}
	cmd := exec.Command(bin, "-uz", mountPoint)
	cmd.Stderr = &errBuf
	err = cmd.Run()
	if errBuf.Len() > 0 {
		return fmt.Errorf("%s (code %v)\n",
			errBuf.String(), err)
	}
	return err
}

func fusermountBinary() (string, error) {
	return lookPathFallback("fusermount", "/bin")
}

// lookPathFallback - search binary in PATH and, if that fails,
// in fallbackDir. This is useful if PATH is possible empty.
func lookPathFallback(file string, fallbackDir string) (string, error) {
	binPath, err := exec.LookPath(file)
	if err == nil {
		return binPath, nil
	}

	abs := path.Join(fallbackDir, file)
	return exec.LookPath(abs)
}
