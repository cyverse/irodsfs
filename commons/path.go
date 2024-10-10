package commons

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
)

func ExpandHomeDir(p string) (string, error) {
	// resolve "~/"
	if p == "~" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			return "", xerrors.Errorf("failed to get user home directory: %w", err)
		}

		return filepath.Abs(homedir)
	} else if strings.HasPrefix(p, "~/") {
		homedir, err := os.UserHomeDir()
		if err != nil {
			return "", xerrors.Errorf("failed to get user home directory: %w", err)
		}

		p = filepath.Join(homedir, p[2:])
		return filepath.Abs(p)
	}

	return filepath.Abs(p)
}
