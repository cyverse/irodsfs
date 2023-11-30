package utils

import (
	"bytes"
	"os"
	"os/exec"
	"path"
	"runtime"

	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
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
		fuseErr := xerrors.Errorf("failed to find /dev/fuse, fuse is not installed or does not have enough privilege: %w", err)
		logger.Errorf("%+v", fuseErr)
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
		return xerrors.Errorf("%q (code %v)", errBuf.String(), err)
	}
	return err
}

func fusermountBinary() (string, error) {
	if path, err := lookPathFallback("fusermount3", "/bin"); err == nil {
		return path, nil
	}
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
