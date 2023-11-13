package irodsfs

import (
	"os"
	"syscall"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
	log "github.com/sirupsen/logrus"
)

func GetPermission(level irodsclient_types.IRODSAccessLevelType) os.FileMode {
	switch level {
	case irodsclient_types.IRODSAccessLevelOwner, irodsclient_types.IRODSAccessLevelWrite:
		return 0o700
	case irodsclient_types.IRODSAccessLevelRead:
		return 0o500
	case irodsclient_types.IRODSAccessLevelNone:
		return 0o0
	default:
		return 0o0
	}
}

func GetACL(fs *IRODSFS, irodsEntry *irodsclient_fs.Entry, readonly bool) os.FileMode {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "getACL",
	})

	// we don't actually check permissions for reading file when vpathEntry is read only
	// because files with no-access for the user will not be visible
	if readonly {
		return 0o500
	}

	if fs.config.NoPermissionCheck {
		// skip perform permission check
		// give the highest permission, but this doesn't mean that the user can write data
		// since iRODS will check permission
		return 0o700
	}

	if irodsEntry.Owner == fs.config.ClientUser {
		// mine
		return 0o700
	}

	logger.Debugf("Checking ACL information of the Entry for %s and user %s", irodsEntry.Path, fs.config.ClientUser)
	defer logger.Debugf("Checked ACL information of the Entry for %s and user %s", irodsEntry.Path, fs.config.ClientUser)

	var err error
	var accesses []*irodsclient_types.IRODSAccess
	if irodsEntry.IsDir() {
		accesses, err = fs.fsClient.ListDirACLs(irodsEntry.Path)
	} else {
		accesses, err = fs.fsClient.ListFileACLs(irodsEntry.Path)
	}

	if err != nil {
		logger.Errorf("failed to get ACL information of the Entry for %s", irodsEntry.Path)
		return 0o500
	}

	var highestPermission os.FileMode = 0o500
	for _, access := range accesses {
		if access.UserType == irodsclient_types.IRODSUserRodsUser && access.UserName == fs.config.ClientUser {
			perm := GetPermission(access.AccessLevel)
			if perm == 0o700 {
				return perm
			}

			if perm > highestPermission {
				highestPermission = perm
			}
		} else if access.UserType == irodsclient_types.IRODSUserRodsGroup {
			if _, ok := fs.userGroupsMap[access.UserName]; ok {
				// my group
				perm := GetPermission(access.AccessLevel)
				if perm == 0o700 {
					return perm
				}

				if perm > highestPermission {
					highestPermission = perm
				}
			}
		}
	}

	logger.Debugf("failed to find ACL information of the Entry for %s and user %s", irodsEntry.Path, fs.config.ClientUser)
	return highestPermission
}

// IRODSStat returns a stat for the given irods path
func IRODSStat(fs *IRODSFS, p string, vpathReadonly bool, out *fuse.AttrOut) syscall.Errno {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Stat",
	})

	entry, err := fs.fsClient.Stat(p)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find a dir - %s", p)
			return syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	mode := GetACL(fs, entry, vpathReadonly)
	setAttrOutForIRODSEntry(entry, fs.uid, fs.gid, mode, &out.Attr)
	return fusefs.OK
}
