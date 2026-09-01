package commons

import (
	"os/user"
	"strconv"

	"github.com/cockroachdb/errors"
)

func parseUGIDString(id string) (int, error) {
	if len(id) == 0 {
		return -1, nil
	}

	parsedID, err := strconv.ParseInt(id, 10, 32)
	if err != nil {
		return -1, errors.Wrapf(err, "failed to parse id %q", id)
	}

	return int(parsedID), nil
}

func lookupUserIDs(u *user.User) (int, int, error) {
	uid, err := parseUGIDString(u.Uid)
	if err != nil {
		return -1, -1, err
	}

	gid, err := parseUGIDString(u.Gid)
	if err != nil {
		return -1, -1, errors.Wrapf(err, "failed to parse gid %q", u.Gid)
	}

	return uid, gid, nil
}

// CorrectSystemUser returns username, uid, gid of the resolved system user.
// If nothing is specified, falls back to the current process user.
func CorrectSystemUser(username string, uid int, gid int) (string, int, int, error) {
	if len(username) == 0 && uid < 0 && gid < 0 {
		u, err := user.Current()
		if err != nil {
			return "", -1, -1, errors.Wrap(err, "failed to get current system user")
		}

		newUID, newGID, err := lookupUserIDs(u)
		if err != nil {
			return "", -1, -1, err
		}

		return u.Username, newUID, newGID, nil
	}

	resultUsername := "root"
	resultUID := 0
	resultGID := 0

	if len(username) > 0 {
		u, err := user.Lookup(username)
		if err != nil {
			return "", -1, -1, errors.Wrapf(err, "failed to look up user %q", username)
		}

		newUID, newGID, err := lookupUserIDs(u)
		if err != nil {
			return "", -1, -1, err
		}

		resultUsername = u.Username
		resultUID = newUID
		resultGID = newGID
	}

	if uid >= 0 {
		resultUID = uid
	}

	if gid >= 0 {
		resultGID = gid
	}

	return resultUsername, resultUID, resultGID, nil
}
