package commons

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime"

	"github.com/cockroachdb/errors"
)

var ErrFuseInstallationError = errors.New("fuse is not installed")

// CheckFuse checks FUSE installation state
func CheckFuse(checkFusermount bool) error {
	if runtime.GOOS == "linux" {
		fuseDevInfo, err := os.Stat("/dev/fuse")
		if err != nil {
			return errors.Join(err, errors.Mark(
				errors.New("failed to find /dev/fuse"),
				ErrFuseInstallationError,
			))
		}

		if (fuseDevInfo.Mode() & os.ModeCharDevice) != os.ModeCharDevice {
			return errors.Mark(
				errors.New("/dev/fuse is not a character device"),
				ErrFuseInstallationError,
			)
		}

		if checkFusermount {
			if _, err = getFusermountBinary(); err != nil {
				return errors.Join(err, errors.Mark(
					errors.New("fusermount not found"),
					ErrFuseInstallationError,
				))
			}
		}

		return nil
	} else if runtime.GOOS == "darwin" {
		return errors.Mark(
			errors.New("FUSE is not available on MacOS"),
			ErrFuseInstallationError,
		)
	} else if runtime.GOOS == "windows" {
		return errors.Mark(
			errors.New("FUSE is not available on Windows"),
			ErrFuseInstallationError,
		)
	}

	return errors.Mark(
		errors.New(fmt.Sprintf("FUSE is not available for unknown OS %q", runtime.GOOS)),
		ErrFuseInstallationError,
	)
}

// UnmountFuse calls fusermount -uz on the mount.
func UnmountFuse(mountPoint string) error {
	bin, err := getFusermountBinary()
	if err != nil {
		return err
	}

	var errBuf bytes.Buffer
	cmd := exec.Command(bin, "-uz", mountPoint)
	cmd.Stderr = &errBuf
	err = cmd.Run()
	if errBuf.Len() > 0 && err != nil {
		return errors.Wrap(err, errBuf.String())
	}
	return err
}

func getFusermountBinary() (string, error) {
	if p, err := lookPathFallback("fusermount3", "/bin"); err == nil {
		return p, nil
	}
	return lookPathFallback("fusermount", "/bin")
}

func lookPathFallback(file string, fallbackDir string) (string, error) {
	if binPath, err := exec.LookPath(file); err == nil {
		return binPath, nil
	}
	return exec.LookPath(path.Join(fallbackDir, file))
}
