package utils

import (
	"os/user"
	"strconv"

	"golang.org/x/xerrors"
)

func parseUGIDString(id string) (int, error) {
	if len(id) == 0 {
		return -1, nil
	}

	parsedID, err := strconv.ParseInt(id, 10, 32)
	if err != nil {
		return -1, xerrors.Errorf("failed to parse id %q: %w", id, err)
	}

	return int(parsedID), nil
}

// CorrectSystemUser returns username, uid, gid of given user
func CorrectSystemUser(username string, uid int, gid int) (string, int, int, error) {
	correctUsername := "root"
	correctUid := 0
	correctGid := 0

	if len(username) > 0 {
		u, err := user.Lookup(username)
		if err != nil {
			return correctUsername, correctUid, correctGid, xerrors.Errorf("failed to look up a user %q: %w", username, err)
		}

		correctUsername = u.Username

		newuid, err := parseUGIDString(u.Uid)
		if err != nil {
			return correctUsername, correctUid, correctGid, err
		}

		correctUid = newuid

		newgid, err := parseUGIDString(u.Gid)
		if err != nil {
			return correctUsername, correctUid, correctGid, xerrors.Errorf("failed to parse gid %q: %w", u.Gid, err)
		}

		correctGid = newgid
	}

	// if uid is given
	if uid >= 0 {
		correctUid = uid
		correctGid = gid
	}

	if gid >= 0 {
		correctGid = gid
	}

	if len(username) == 0 && uid < 0 && gid < 0 {
		// if nothing is given, return current user
		u, err := user.Current()
		if err != nil {
			return correctUsername, correctUid, correctGid, xerrors.Errorf("failed to get current system user info: %w", err)
		}

		correctUsername = u.Username

		newuid, err := parseUGIDString(u.Uid)
		if err != nil {
			return correctUsername, correctUid, correctGid, err
		}

		correctUid = newuid

		newgid, err := parseUGIDString(u.Gid)
		if err != nil {
			return correctUsername, correctUid, correctGid, xerrors.Errorf("failed to parse gid %q: %w", u.Gid, err)
		}

		correctGid = newgid
	}

	return correctUsername, correctUid, correctGid, nil
}
