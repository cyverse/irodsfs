package utils

import (
	"fmt"
	"os/user"
	"strconv"

	"golang.org/x/xerrors"
)

// GetCurrentSystemUser returns username, uid, gid of current user
func GetCurrentSystemUser() (string, int, int, error) {
	user, err := user.Current()
	if err != nil {
		return "root", 0, 0, xerrors.Errorf("failed to get current system user info - %v", err)
	}

	uid, err := strconv.ParseInt(user.Uid, 10, 32)
	if err != nil {
		return "root", 0, 0, xerrors.Errorf("failed to parse uid - %s", user.Uid)
	}

	gid, err := strconv.ParseInt(user.Gid, 10, 32)
	if err != nil {
		return "root", 0, 0, xerrors.Errorf("failed to parse gid - %s", user.Gid)
	}

	return user.Username, int(uid), int(gid), nil
}

// CorrectSystemUser returns username, uid, gid of given user
func CorrectSystemUser(username string, uid int, gid int) (string, int, int, error) {
	if len(username) > 0 {
		u, err := user.Lookup(username)
		if err != nil {
			return "root", 0, 0, xerrors.Errorf("failed to look up a user - %s", username)
		}

		newuid, err := strconv.ParseInt(u.Uid, 10, 32)
		if err != nil {
			return "root", 0, 0, xerrors.Errorf("failed to parse uid - %s", u.Uid)
		}

		newgid, err := strconv.ParseInt(u.Gid, 10, 32)
		if err != nil {
			return "root", 0, 0, xerrors.Errorf("failed to parse gid - %s", u.Gid)
		}

		return username, int(newuid), int(newgid), nil
	}

	// if uid is given, gid may be empty
	if uid >= 0 {
		u, err := user.LookupId(fmt.Sprintf("%d", uid))
		if err != nil {
			// user not existing --> possible case
			if gid < 0 {
				gid = uid
			}

			return "", uid, gid, nil
		}

		newuid, err := strconv.ParseInt(u.Uid, 10, 32)
		if err != nil {
			return "root", 0, 0, xerrors.Errorf("failed to parse uid - %s", u.Uid)
		}

		newgid, err := strconv.ParseInt(u.Gid, 10, 32)
		if err != nil {
			return "root", 0, 0, xerrors.Errorf("failed to parse gid - %s", u.Gid)
		}

		return u.Username, int(newuid), int(newgid), nil
	}

	// if nothing is given
	u, err := user.Current()
	if err != nil {
		return "root", 0, 0, xerrors.Errorf("failed to get current system user info - %v", err)
	}

	newuid, err := strconv.ParseInt(u.Uid, 10, 32)
	if err != nil {
		return "root", 0, 0, xerrors.Errorf("failed to parse uid - %s", u.Uid)
	}

	newgid, err := strconv.ParseInt(u.Gid, 10, 32)
	if err != nil {
		return "root", 0, 0, xerrors.Errorf("failed to parse gid - %s", u.Gid)
	}

	return u.Username, int(newuid), int(newgid), nil
}
