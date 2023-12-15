package irodsfs

import (
	"context"
	"os"
	"syscall"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
	log "github.com/sirupsen/logrus"
)

// IRODSGetACL returns permission flag from iRODS access level type
func IRODSGetPermission(level irodsclient_types.IRODSAccessLevelType) os.FileMode {
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

// IRODSGetOpenFlags converts file open flags to iRODS file open mode
func IRODSGetOpenFlags(flags uint32) irodsclient_types.FileOpenMode {
	if flags&uint32(os.O_WRONLY) == uint32(os.O_WRONLY) {
		openMode := irodsclient_types.FileOpenModeWriteOnly

		if flags&uint32(os.O_APPEND) == uint32(os.O_APPEND) {
			// append
			openMode = irodsclient_types.FileOpenModeAppend
		} else if flags&uint32(os.O_TRUNC) == uint32(os.O_TRUNC) {
			// truncate
			openMode = irodsclient_types.FileOpenModeWriteTruncate
		}

		return openMode
	} else if flags&uint32(os.O_RDWR) == uint32(os.O_RDWR) {
		return irodsclient_types.FileOpenModeReadWrite
	}

	return irodsclient_types.FileOpenModeReadOnly
}

// IRODSGetACL returns ACL flag from iRODS entry
func IRODSGetACL(ctx context.Context, fs *IRODSFS, entry *irodsclient_fs.Entry, readonly bool) os.FileMode {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSGetACL",
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

	if entry.Owner == fs.config.ClientUser {
		// mine
		return 0o700
	}

	logger.Debugf("Checking ACL information of the Entry for %q and user %q", entry.Path, fs.config.ClientUser)
	defer logger.Debugf("Checked ACL information of the Entry for %q and user %q", entry.Path, fs.config.ClientUser)

	var err error
	var accesses []*irodsclient_types.IRODSAccess
	if entry.IsDir() {
		accesses, err = fs.fsClient.ListDirACLs(entry.Path)
	} else {
		accesses, err = fs.fsClient.ListFileACLs(entry.Path)
	}

	if err != nil {
		logger.Errorf("failed to get ACL information of the Entry for %q", entry.Path)
		return 0o500
	}

	var highestPermission os.FileMode = 0o500
	for _, access := range accesses {
		if access.UserType == irodsclient_types.IRODSUserRodsUser && access.UserName == fs.config.ClientUser {
			perm := IRODSGetPermission(access.AccessLevel)
			if perm == 0o700 {
				return perm
			}

			if perm > highestPermission {
				highestPermission = perm
			}
		} else if access.UserType == irodsclient_types.IRODSUserRodsGroup {
			if _, ok := fs.userGroupsMap[access.UserName]; ok {
				// my group
				perm := IRODSGetPermission(access.AccessLevel)
				if perm == 0o700 {
					return perm
				}

				if perm > highestPermission {
					highestPermission = perm
				}
			}
		}
	}

	logger.Debugf("failed to find ACL information of the Entry for %q and user %q", entry.Path, fs.config.ClientUser)
	return highestPermission
}

// IRODSStat returns a stat for the given irods path
func IRODSStat(ctx context.Context, fs *IRODSFS, path string) (*irodsclient_fs.Entry, error) {
	return fs.fsClient.Stat(path)
}

// IRODSGetattr returns an attr for the given irods path
func IRODSGetattr(ctx context.Context, fs *IRODSFS, path string, vpathReadonly bool, out *fuse.AttrOut) syscall.Errno {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSGetattr",
	})

	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file or dir for path %q", path)
			return syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		if isTransitiveConnectionError(err) {
			// return dummy
			logger.Errorf("returning dummy attr for path %q", path)
			setAttrOutForDummy(fs.inodeManager, path, fs.uid, fs.gid, true, &out.Attr)
			return fusefs.OK
		}

		return syscall.EREMOTEIO
	}

	mode := IRODSGetACL(ctx, fs, entry, vpathReadonly)
	setAttrOutForIRODSEntry(fs.inodeManager, entry, fs.uid, fs.gid, mode, &out.Attr)
	return fusefs.OK
}

// IRODSLookup returns entry for the given irods path
func IRODSLookup(ctx context.Context, fs *IRODSFS, dir *Dir, path string, vpathReadonly bool, out *fuse.EntryOut) (int64, bool, syscall.Errno) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSLookup",
	})

	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file or dir for path %q", path)
			return 0, false, syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return 0, false, syscall.EREMOTEIO
	}

	mode := IRODSGetACL(ctx, fs, entry, vpathReadonly)

	setAttrOutForIRODSEntry(fs.inodeManager, entry, fs.uid, fs.gid, mode, &out.Attr)
	return entry.ID, entry.IsDir(), fusefs.OK
}

// IRODSListxattr returns all xattrs for the given irods path
func IRODSListxattr(ctx context.Context, fs *IRODSFS, path string, dest []byte) (uint32, syscall.Errno) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSListxattr",
	})

	irodsMetadata, err := fs.fsClient.ListXattr(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file or dir for path %q", path)
			return 0, syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return 0, syscall.EREMOTEIO
	}

	// convert to a byte array
	xattrNames := []byte{}
	for _, irodsMeta := range irodsMetadata {
		xattrNames = append(xattrNames, []byte(irodsMeta.Name)...)
		xattrNames = append(xattrNames, byte(0))
	}

	requiredBytesLen := len(xattrNames)
	if len(dest) < requiredBytesLen {
		return uint32(requiredBytesLen), syscall.ERANGE
	}

	// has any?
	if len(xattrNames) > 0 {
		copy(dest, xattrNames)
		return uint32(requiredBytesLen), fusefs.OK
	}

	// return empty
	return 0, fusefs.OK
}

// IRODSGetxattr returns an xattr for the given irods path and attr name
func IRODSGetxattr(ctx context.Context, fs *IRODSFS, path string, attr string, dest []byte) (uint32, syscall.Errno) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSGetxattr",
	})

	irodsMeta, err := fs.fsClient.GetXattr(path, attr)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file or dir for path %q", path)
			return 0, syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return 0, syscall.EREMOTEIO
	}

	if irodsMeta == nil {
		return 0, syscall.ENODATA
	}

	requiredBytesLen := len([]byte(irodsMeta.Value))

	if len(dest) < requiredBytesLen {
		return uint32(requiredBytesLen), syscall.ERANGE
	}

	copy(dest, []byte(irodsMeta.Value))
	return uint32(requiredBytesLen), fusefs.OK
}

// IRODSSetxattr sets an xattr for the given irods path and attr name
func IRODSSetxattr(ctx context.Context, fs *IRODSFS, path string, attr string, data []byte) syscall.Errno {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSSetxattr",
	})

	err := fs.fsClient.SetXattr(path, attr, string(data))
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file or dir for path %q", path)
			return syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// IRODSRemovexattr unsets an xattr for the given irods path and attr name
func IRODSRemovexattr(ctx context.Context, fs *IRODSFS, path string, attr string) syscall.Errno {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSRemovexattr",
	})

	irodsMeta, err := fs.fsClient.GetXattr(path, attr)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file or dir for path %q", path)
			return syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	if irodsMeta == nil {
		return syscall.ENODATA
	}

	err = fs.fsClient.RemoveXattr(path, attr)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file or dir for path %q", path)
			return syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// IRODSOpendir opens dir for the given irods path
func IRODSOpendir(ctx context.Context, fs *IRODSFS, path string) syscall.Errno {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSOpendir",
	})

	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file or dir for path %q", path)
			return syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		if isTransitiveConnectionError(err) {
			// return dummy
			logger.Errorf("opening dummy dir for path %q", path)
			return fusefs.OK
		}

		return syscall.EREMOTEIO
	}

	if !entry.IsDir() {
		logger.Errorf("entry type for path %q is not a directory", path)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// IRODSReaddir reads dir entries for the given irods path
func IRODSReaddir(ctx context.Context, fs *IRODSFS, path string) ([]fuse.DirEntry, syscall.Errno) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSReaddir",
	})

	dirEntries := []fuse.DirEntry{}

	entries, err := fs.fsClient.List(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find dir for path %q", path)
			return nil, syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		if isTransitiveConnectionError(err) {
			// return dummy
			logger.Errorf("returning dummy dir entries for path %q", path)
			return dirEntries, fusefs.OK
		}

		return nil, syscall.EREMOTEIO
	}

	for _, entry := range entries {
		entryType := uint32(fuse.S_IFREG)

		if entry.IsDir() {
			entryType = uint32(fuse.S_IFDIR)
		}

		dirEntry := fuse.DirEntry{
			Ino:  fs.inodeManager.GetInodeIDForIRODSEntryID(entry.ID),
			Mode: entryType,
			Name: entry.Name,
		}

		dirEntries = append(dirEntries, dirEntry)
	}

	return dirEntries, fusefs.OK
}

// IRODSRmdir removes dir for the given irods path
func IRODSRmdir(ctx context.Context, fs *IRODSFS, path string) syscall.Errno {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSRmdir",
	})

	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find dir for path %q", path)
			return syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	if !entry.IsDir() {
		logger.Errorf("failed to remove a file %q using rmdir", entry.Path)
		return syscall.EREMOTEIO
	}

	// dir
	err = fs.fsClient.RemoveDir(entry.Path, false, false)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find dir for path %q", entry.Path)
			return syscall.ENOENT
		} else if irodsclient_types.IsCollectionNotEmptyError(err) {
			logger.Debugf("the dir is not empty %q", entry.Path)
			return syscall.ENOTEMPTY
		}

		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// IRODSUnlink removes file for the given irods path
func IRODSUnlink(ctx context.Context, fs *IRODSFS, path string) syscall.Errno {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSUnlink",
	})

	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file for path %q", path)
			return syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	if entry.IsDir() {
		logger.Errorf("failed to remove a dir %q using unlink", entry.Path)
		return syscall.EREMOTEIO
	}

	// file
	err = fs.fsClient.RemoveFile(entry.Path, false)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file for path %q", path)
			return syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// IRODSMkdir removes dir for the given irods path
func IRODSMkdir(ctx context.Context, fs *IRODSFS, dir *Dir, path string, out *fuse.EntryOut) (int64, syscall.Errno) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSMkdir",
	})

	err := fs.fsClient.MakeDir(path, false)
	if err != nil {
		logger.Errorf("%+v", err)
		return 0, syscall.EREMOTEIO
	}

	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		logger.Errorf("%+v", err)
		return 0, syscall.EREMOTEIO
	}

	mode := IRODSGetACL(ctx, fs, entry, false)

	if !entry.IsDir() {
		logger.Errorf("failed to create a dir, but found a file")
		return 0, syscall.EREMOTEIO
	}

	setAttrOutForIRODSEntry(fs.inodeManager, entry, fs.uid, fs.gid, mode, &out.Attr)
	return entry.ID, fusefs.OK
}

// IRODSRename renames file or dir for the given irods path
func IRODSRename(ctx context.Context, fs *IRODSFS, dir *Dir, srcPath string, destPath string) syscall.Errno {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSRename",
	})

	srcEntry, err := fs.fsClient.Stat(srcPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file or dir for path %q", srcPath)
			return syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	if srcEntry.IsDir() {
		err = dir.fs.fsClient.RenameDirToDir(srcPath, destPath)
		if err != nil {
			logger.Errorf("%+v", err)
			return syscall.EREMOTEIO
		}

		return fusefs.OK
	}

	destEntry, err := fs.fsClient.Stat(destPath)
	if err != nil {
		if !irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file or dir for path %q", destPath)
			return syscall.EREMOTEIO
		}
	} else {
		// no error - file exists
		if destEntry.ID > 0 {
			// delete first
			if !destEntry.IsDir() {
				err = dir.fs.fsClient.RemoveFile(destPath, false)
				if err != nil {
					logger.Errorf("%+v", err)
					return syscall.EREMOTEIO
				}
			}
		}
	}

	err = dir.fs.fsClient.RenameFileToFile(srcPath, destPath)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// IRODSCreate creates file for the given irods path
func IRODSCreate(ctx context.Context, fs *IRODSFS, dir *Dir, path string, flags uint32, out *fuse.EntryOut) (int64, *FileHandle, syscall.Errno) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSCreate",
	})

	openMode := IRODSGetOpenFlags(flags)
	logger.Infof("Create file %q with flag %d, mode %q", path, flags, openMode)

	handle, err := fs.fsClient.CreateFile(path, "", string(openMode))
	if err != nil {
		logger.Errorf("%+v", err)
		return 0, nil, syscall.EREMOTEIO
	}

	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file or dir for path %q", path)
			return 0, nil, syscall.EREMOTEIO
		}

		logger.Errorf("%+v", err)
		return 0, nil, syscall.EREMOTEIO
	}

	if fs.instanceReportClient != nil {
		fs.instanceReportClient.StartFileAccess(handle)
	}

	fileHandle, err := NewFileHandle(fs, handle)
	if err != nil {
		logger.Errorf("%+v", err)
		return 0, nil, syscall.EREMOTEIO
	}

	mode := IRODSGetACL(ctx, fs, entry, false)
	setAttrOutForIRODSEntry(fs.inodeManager, entry, fs.uid, fs.gid, mode, &out.Attr)
	return entry.ID, fileHandle, fusefs.OK
}

// IRODSOpen opens file for the given irods path
func IRODSOpen(ctx context.Context, fs *IRODSFS, file *File, path string, flags uint32) (*FileHandle, syscall.Errno) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSOpen",
	})

	openMode := IRODSGetOpenFlags(flags)
	logger.Infof("Open file %q with flag %d, mode %q", path, flags, openMode)

	handle, err := fs.fsClient.OpenFile(path, "", string(openMode))
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find a file %q", path)
			return nil, syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return nil, syscall.EREMOTEIO
	}

	if fs.instanceReportClient != nil {
		fs.instanceReportClient.StartFileAccess(handle)
	}

	fileHandle, err := NewFileHandle(fs, handle)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, syscall.EREMOTEIO
	}

	return fileHandle, fusefs.OK
}

// IRODSOpenLazy opens file for the given irods path lazily when it first read or write
func IRODSOpenLazy(ctx context.Context, fs *IRODSFS, file *File, path string, flags uint32) (*FileHandle, syscall.Errno) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "IRODSOpenLazy",
	})

	openMode := IRODSGetOpenFlags(flags)

	fileHandle, err := NewFileHandleLazy(fs, path, openMode)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, syscall.EREMOTEIO
	}

	return fileHandle, fusefs.OK
}
