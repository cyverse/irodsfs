package commons

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/cockroachdb/errors"
)

var ErrFuseInstallationError = errors.New("fuse is not installed")

// CheckFuse checks whether FUSE and, when requested, fusermount are available.
func CheckFuse(checkFusermount bool) error {
	if runtime.GOOS != "linux" {
		return errors.Mark(
			errors.Errorf("FUSE is not available on %s", runtime.GOOS),
			ErrFuseInstallationError,
		)
	}

	fuseDevInfo, err := os.Stat("/dev/fuse")
	if err != nil {
		return errors.Join(err, errors.Mark(errors.New("failed to find /dev/fuse"), ErrFuseInstallationError))
	}
	if fuseDevInfo.Mode()&os.ModeCharDevice != os.ModeCharDevice {
		return errors.Mark(errors.New("/dev/fuse is not a character device"), ErrFuseInstallationError)
	}

	if checkFusermount {
		if _, err = getFusermountBinary(); err != nil {
			return errors.Join(err, errors.Mark(errors.New("fusermount not found"), ErrFuseInstallationError))
		}
	}

	return nil
}

// UnmountFuse lazily unmounts mountPoint using fusermount3 or fusermount.
func UnmountFuse(mountPoint string) error {
	bin, err := getFusermountBinary()
	if err != nil {
		return err
	}

	var stderr bytes.Buffer
	cmd := exec.Command(bin, "-uz", mountPoint)
	cmd.Stderr = &stderr
	if err = cmd.Run(); err != nil {
		if stderr.Len() > 0 {
			return errors.Wrap(err, stderr.String())
		}
		return err
	}
	return nil
}

func getFusermountBinary() (string, error) {
	if binary, err := lookPathFallback("fusermount3", "/bin"); err == nil {
		return binary, nil
	}
	return lookPathFallback("fusermount", "/bin")
}

func lookPathFallback(file string, fallbackDir string) (string, error) {
	if binary, err := exec.LookPath(file); err == nil {
		return binary, nil
	}
	binary, err := exec.LookPath(filepath.Join(fallbackDir, file))
	if err != nil {
		return "", errors.Wrapf(err, "failed to find %s", file)
	}
	return binary, nil
}
