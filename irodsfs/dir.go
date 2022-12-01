package irodsfs

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	irodsfs_common_utils "github.com/cyverse/irodsfs-common/utils"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"

	log "github.com/sirupsen/logrus"
)

// Dir is a directory node
type Dir struct {
	fusefs.Inode

	fs      *IRODSFS
	entryID int64
	path    string
	mutex   sync.RWMutex
}

// NewDir creates a new Dir
func NewDir(fs *IRODSFS, entryID int64, path string) *Dir {
	return &Dir{
		fs:      fs,
		entryID: entryID,
		path:    path,
		mutex:   sync.RWMutex{},
	}
}

func (dir *Dir) newSubDirInode(ctx context.Context, entryID int64, path string) (*Dir, *fusefs.Inode) {
	subDir := NewDir(dir.fs, entryID, path)
	return subDir, dir.NewInode(ctx, subDir, subDir.getStableAttr())
}

func (dir *Dir) newSubFileInode(ctx context.Context, entryID int64, path string) (*File, *fusefs.Inode) {
	subFile := NewFile(dir.fs, entryID, path)
	return subFile, dir.NewInode(ctx, subFile, subFile.getStableAttr())
}

func (dir *Dir) getStableAttr() fusefs.StableAttr {
	return fusefs.StableAttr{
		Mode: fuse.S_IFDIR,
		Ino:  uint64(dir.entryID),
		Gen:  0,
	}
}

func (dir *Dir) setAttrOut(vpathEntry *irodsfs_common_vpath.VPathEntry, out *fuse.Attr) {
	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// vpath
		out.Ino = uint64(vpathEntry.VirtualDirEntry.ID)
		out.Uid = dir.fs.uid
		out.Gid = dir.fs.gid
		out.SetTimes(&vpathEntry.VirtualDirEntry.ModifyTime, &vpathEntry.VirtualDirEntry.ModifyTime, &vpathEntry.VirtualDirEntry.ModifyTime)
		out.Size = uint64(vpathEntry.VirtualDirEntry.Size)
		out.Mode = uint32(fuse.S_IFDIR | 0o400)
	} else if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		// irods
		out.Ino = uint64(vpathEntry.IRODSEntry.ID)
		out.Uid = dir.fs.uid
		out.Gid = dir.fs.gid
		out.SetTimes(&vpathEntry.IRODSEntry.ModifyTime, &vpathEntry.IRODSEntry.ModifyTime, &vpathEntry.IRODSEntry.ModifyTime)
		out.Size = uint64(vpathEntry.IRODSEntry.Size)
		out.Mode = uint32(fuse.S_IFDIR | dir.getACL(vpathEntry.IRODSEntry, vpathEntry.ReadOnly))
	}
}

func (dir *Dir) getPermission(level irodsclient_types.IRODSAccessLevelType) os.FileMode {
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

func (dir *Dir) getACL(irodsEntry *irodsclient_fs.Entry, readonly bool) os.FileMode {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "getACL",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// we don't actually check permissions for reading file when vpathEntry is read only
	// because files with no-access for the user will not be visible
	if readonly {
		return 0o500
	}

	if dir.fs.config.NoPermissionCheck {
		// skip perform permission check
		// give the highest permission, but this doesn't mean that the user can write data
		// since iRODS will check permission
		return 0o700
	}

	if irodsEntry.Owner == dir.fs.config.ClientUser {
		// mine
		return 0o700
	}

	logger.Debugf("Checking ACL information of the Entry for %s and user %s", irodsEntry.Path, dir.fs.config.ClientUser)
	defer logger.Debugf("Checked ACL information of the Entry for %s and user %s", irodsEntry.Path, dir.fs.config.ClientUser)

	accesses, err := dir.fs.fsClient.ListDirACLs(irodsEntry.Path)
	if err != nil {
		logger.Errorf("failed to get ACL information of the Entry for %s", irodsEntry.Path)
	}

	var highestPermission os.FileMode = 0o500
	for _, access := range accesses {
		if access.UserType == irodsclient_types.IRODSUserRodsUser && access.UserName == dir.fs.config.ClientUser {
			perm := dir.getPermission(access.AccessLevel)
			if perm == 0o700 {
				return perm
			}

			if perm > highestPermission {
				highestPermission = perm
			}
		} else if access.UserType == irodsclient_types.IRODSUserRodsGroup {
			if _, ok := dir.fs.userGroupsMap[access.UserName]; ok {
				// my group
				perm := dir.getPermission(access.AccessLevel)
				if perm == 0o700 {
					return perm
				}

				if perm > highestPermission {
					highestPermission = perm
				}
			}
		}
	}

	logger.Debugf("failed to find ACL information of the Entry for %s and user %s", irodsEntry.Path, dir.fs.config.ClientUser)
	return highestPermission
}

// We can set attr from Lookup
// Getattr returns stat of file entry
func (dir *Dir) Getattr(ctx context.Context, fh fusefs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Getattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Getattr (%d) - %s", operID, dir.path)
	defer logger.Infof("Called Getattr (%d) - %s", operID, dir.path)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", dir.path)
		return syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		if vpathEntry.Path == dir.path {
			dir.setAttrOut(vpathEntry, &out.Attr)
			return fusefs.OK
		}
		return syscall.ENOENT
	}

	if vpathEntry.Type != irodsfs_common_vpath.VPathIRODS {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return syscall.EREMOTEIO
	}

	if vpathEntry.IRODSEntry.Type != irodsclient_fs.DirectoryEntry {
		logger.Errorf("failed to get dir attributes")
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		logger.WithError(err).Errorf("failed to get iRODS path")
		return syscall.EREMOTEIO
	}

	irodsEntry, err := dir.fs.fsClient.Stat(irodsPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.WithError(err).Debugf("failed to find a dir - %s", irodsPath)
			return syscall.ENOENT
		}

		logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
		return syscall.EREMOTEIO
	}

	newVPathEntry := irodsfs_common_vpath.NewVPathEntryFromIRODSFSEntry(dir.path, irodsEntry, vpathEntry.ReadOnly)
	dir.setAttrOut(newVPathEntry, &out.Attr)
	return fusefs.OK
}

// Setattr sets dir attributes
func (dir *Dir) Setattr(ctx context.Context, fh fusefs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Setattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// do not return EOPNOTSUPP as it causes client errors, like git clone
	/*
		if _, ok := in.GetMode(); ok {
			// chmod
			// not supported
			return syscall.EOPNOTSUPP
		} else if _, ok := in.GetATime(); ok {
			// changing date
			// not supported
			return syscall.EOPNOTSUPP
		} else if _, ok := in.GetCTime(); ok {
			// changing date
			// not supported
			return syscall.EOPNOTSUPP
		} else if _, ok := in.GetMTime(); ok {
			// changing date
			// not supported
			return syscall.EOPNOTSUPP
		} else if _, ok := in.GetGID(); ok {
			// changing ownership
			// not supported
			return syscall.EOPNOTSUPP
		} else if _, ok := in.GetUID(); ok {
			// changing ownership
			// not supported
			return syscall.EOPNOTSUPP
		} else if size, ok := in.GetSize(); ok {
			// is this to truncate a file?
			// not supported
			logger.Errorf("cannot handle truncation of a directory - %s, size %d", dir.path, size)
			return syscall.EOPNOTSUPP
		}
	*/

	return fusefs.OK
}

// Listxattr lists xattr
// read all attributes (null terminated) into
// `dest`. If the `dest` buffer is too small, it should return ERANGE
// and the correct size.  If not defined, return an empty list and
// success.
func (dir *Dir) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	if dir.fs.terminated {
		return 0, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Listxattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Listxattr (%d) - %s", operID, dir.path)
	defer logger.Infof("Called Listxattr (%d) - %s", operID, dir.path)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", dir.path)
		return 0, syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// no data
		return 0, fusefs.OK
	}

	if vpathEntry.Type != irodsfs_common_vpath.VPathIRODS {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return 0, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		logger.WithError(err).Errorf("failed to get IRODS path")
		return 0, syscall.EREMOTEIO
	}

	irodsMetadata, err := dir.fs.fsClient.ListXattr(irodsPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("failed to find a dir - %s", irodsPath)
			return 0, syscall.ENOENT
		}

		logger.WithError(err).Errorf("failed to list xattrs - %s", irodsPath)
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

// Getxattr returns xattr
// return the number of bytes. If `dest` is too
// small, it should return ERANGE and the size of the attribute.
// If not defined, Getxattr will return ENOATTR.
func (dir *Dir) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	if dir.fs.terminated {
		return 0, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Getxattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Getxattr (%d) - %s", operID, dir.path)
	defer logger.Infof("Called Getxattr (%d) - %s", operID, dir.path)

	if IsUnhandledAttr(attr) {
		return 0, syscall.ENODATA
	}

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", dir.path)
		return 0, syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		return 0, syscall.ENODATA
	}

	if vpathEntry.Type != irodsfs_common_vpath.VPathIRODS {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return 0, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		logger.WithError(err).Errorf("failed to get IRODS path")
		return 0, syscall.EREMOTEIO
	}

	irodsMeta, err := dir.fs.fsClient.GetXattr(irodsPath, attr)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("failed to find a dir - %s", irodsPath)
			return 0, syscall.ENOENT
		}

		logger.WithError(err).Errorf("failed to get xattrs - %s", irodsPath)
		return 0, syscall.EREMOTEIO
	}

	if irodsMeta == nil {
		return 0, syscall.ENODATA
	}

	requiredBytesLen := len([]byte(irodsMeta.Value)) + 1 // with null termination

	if len(dest) < requiredBytesLen {
		return uint32(requiredBytesLen), syscall.ERANGE
	}

	copy(dest, []byte(irodsMeta.Value))
	dest[len([]byte(irodsMeta.Value))] = 0 // null termination
	return uint32(len([]byte(irodsMeta.Value)) + 1), fusefs.OK
}

// Setxattr sets xattr
// If not defined, Setxattr will return ENOATTR.
func (dir *Dir) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Setxattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Setxattr (%d) - %s", operID, dir.path)
	defer logger.Infof("Called Setxattr (%d) - %s", operID, dir.path)

	if IsUnhandledAttr(attr) {
		return syscall.EINVAL
	}

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", dir.path)
		return syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		return syscall.EACCES
	}

	if vpathEntry.Type != irodsfs_common_vpath.VPathIRODS {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		logger.WithError(err).Errorf("failed to get IRODS path")
		return syscall.EREMOTEIO
	}

	err = dir.fs.fsClient.SetXattr(irodsPath, attr, string(data))
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("failed to find a dir - %s", irodsPath)
			return syscall.ENOENT
		}

		logger.WithError(err).Errorf("failed to set xattrs - %s", irodsPath)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// Removexattr removes xattr
// If not defined, Removexattr will return ENOATTR.
func (dir *Dir) Removexattr(ctx context.Context, attr string) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Removexattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Removexattr (%d) - %s", operID, dir.path)
	defer logger.Infof("Called Removexattr (%d) - %s", operID, dir.path)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", dir.path)
		return syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		return syscall.EACCES
	}

	if vpathEntry.Type != irodsfs_common_vpath.VPathIRODS {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		logger.WithError(err).Errorf("failed to get IRODS path")
		return syscall.EREMOTEIO
	}

	irodsMeta, err := dir.fs.fsClient.GetXattr(irodsPath, attr)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("failed to find a dir - %s", irodsPath)
			return syscall.ENOENT
		}

		logger.WithError(err).Errorf("failed to get xattrs - %s", irodsPath)
		return syscall.EREMOTEIO
	}

	if irodsMeta == nil {
		return syscall.ENODATA
	}

	err = dir.fs.fsClient.RemoveXattr(irodsPath, attr)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("failed to find a dir - %s", irodsPath)
			return syscall.ENOENT
		}

		logger.WithError(err).Errorf("failed to remove xattrs - %s", irodsPath)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// Lookup returns a node for the path
func (dir *Dir) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fusefs.Inode, syscall.Errno) {
	if dir.fs.terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Lookup",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	targetPath := irodsfs_common_utils.JoinPath(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Lookup (%d) - %s", operID, targetPath)
	defer logger.Infof("Called Lookup (%d) - %s", operID, targetPath)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", targetPath)
		return nil, syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		if vpathEntry.Path == targetPath {
			subDir, subDirInode := dir.newSubDirInode(ctx, vpathEntry.VirtualDirEntry.ID, targetPath)
			subDir.setAttrOut(vpathEntry, &out.Attr)
			return subDirInode, fusefs.OK
		}
		return nil, syscall.ENOENT
	}

	if vpathEntry.Type != irodsfs_common_vpath.VPathIRODS {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return nil, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		logger.WithError(err).Errorf("failed to get IRODS path")
		return nil, syscall.EREMOTEIO
	}

	irodsEntry, err := dir.fs.fsClient.Stat(irodsPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.WithError(err).Debugf("failed to find a file - %s", irodsPath)
			return nil, syscall.ENOENT
		}

		logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
		return nil, syscall.EREMOTEIO
	}

	switch irodsEntry.Type {
	case irodsclient_fs.FileEntry:
		newVPathEntry := irodsfs_common_vpath.NewVPathEntryFromIRODSFSEntry(targetPath, irodsEntry, vpathEntry.ReadOnly)
		subFile, subFileInode := dir.newSubFileInode(ctx, irodsEntry.ID, targetPath)
		subFile.setAttrOut(newVPathEntry, &out.Attr)
		return subFileInode, fusefs.OK
	case irodsclient_fs.DirectoryEntry:
		newVPathEntry := irodsfs_common_vpath.NewVPathEntryFromIRODSFSEntry(targetPath, irodsEntry, vpathEntry.ReadOnly)
		subDir, subDirInode := dir.newSubDirInode(ctx, irodsEntry.ID, targetPath)
		subDir.setAttrOut(newVPathEntry, &out.Attr)
		return subDirInode, fusefs.OK
	default:
		logger.Errorf("unknown entry type - %s", irodsEntry.Type)
		return nil, syscall.EREMOTEIO
	}
}

// Opendir validates the existance of a dir
func (dir *Dir) Opendir(ctx context.Context) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Opendir",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Opendir (%d) - %s", operID, dir.path)
	defer logger.Infof("Called Opendir (%d) - %s", operID, dir.path)

	// we must not lock here.
	// rename locks mutex and calls opendir, so goes deadlock
	//dir.mutex.RLock()
	//defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", dir.path)
		return syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		if vpathEntry.Path == dir.path {
			return fusefs.OK
		}
		return syscall.ENOENT
	}

	if vpathEntry.Type != irodsfs_common_vpath.VPathIRODS {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		logger.WithError(err).Errorf("failed to get IRODS path")
		return syscall.EREMOTEIO
	}

	irodsEntry, err := dir.fs.fsClient.Stat(irodsPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
			return syscall.ENOENT
		}

		logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
		return syscall.EREMOTEIO
	}

	if irodsEntry.Type != irodsclient_fs.DirectoryEntry {
		logger.Errorf("entry type is not a directory - %s", irodsEntry.Type)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// Readdir returns directory entries
func (dir *Dir) Readdir(ctx context.Context) (fusefs.DirStream, syscall.Errno) {
	if dir.fs.terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Readdir",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Readdir (%d) - %s", operID, dir.path)
	defer logger.Infof("Called Readdir (%d) - %s", operID, dir.path)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", dir.path)
		return nil, syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		if vpathEntry.Path == dir.path {
			dirEntries := make([]fuse.DirEntry, len(vpathEntry.VirtualDirEntry.DirEntries))

			for idx, entry := range vpathEntry.VirtualDirEntry.DirEntries {
				if entry.Type == irodsfs_common_vpath.VPathVirtualDir {
					dirEntry := fuse.DirEntry{
						Ino:  uint64(entry.VirtualDirEntry.ID),
						Mode: fuse.S_IFDIR,
						Name: entry.VirtualDirEntry.Name,
					}

					dirEntries[idx] = dirEntry
				} else if entry.Type == irodsfs_common_vpath.VPathIRODS {
					entryType := uint32(fuse.S_IFREG)

					switch entry.IRODSEntry.Type {
					case irodsclient_fs.FileEntry:
						entryType = fuse.S_IFREG
					case irodsclient_fs.DirectoryEntry:
						entryType = fuse.S_IFDIR
					default:
						logger.Errorf("unknown entry type - %s", entry.Type)
						return nil, syscall.EREMOTEIO
					}

					dirEntry := fuse.DirEntry{
						Ino:  uint64(entry.IRODSEntry.ID),
						Mode: entryType,
						Name: irodsfs_common_utils.GetFileName(entry.Path),
					}

					dirEntries[idx] = dirEntry
				} else {
					logger.Errorf("unknown VPath Entry type : %s", entry.Type)
					return nil, syscall.EREMOTEIO
				}
			}

			return fusefs.NewListDirStream(dirEntries), fusefs.OK
		}
		return nil, syscall.ENOENT
	} else if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return nil, syscall.EREMOTEIO
		}

		irodsEntries, err := dir.fs.fsClient.List(irodsPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to list - %s", irodsPath)
			return nil, syscall.EREMOTEIO
		}

		dirEntries := make([]fuse.DirEntry, len(irodsEntries))

		for idx, irodsEntry := range irodsEntries {
			entryType := uint32(fuse.S_IFREG)

			switch irodsEntry.Type {
			case irodsclient_fs.FileEntry:
				entryType = fuse.S_IFREG
			case irodsclient_fs.DirectoryEntry:
				entryType = fuse.S_IFDIR
			default:
				logger.Errorf("unknown entry type - %s", irodsEntry.Type)
				return nil, syscall.EREMOTEIO
			}

			dirEntry := fuse.DirEntry{
				Ino:  uint64(irodsEntry.ID),
				Mode: entryType,
				Name: irodsEntry.Name,
			}

			dirEntries[idx] = dirEntry
		}

		if !dir.fs.config.NoPermissionCheck && !vpathEntry.ReadOnly {
			// list ACLs
			// this caches all ACLs of entries in irodsPath, so make future ACL queries fast
			logger.Debugf("Caching ACLs for entries in a dir - %s", irodsPath)
			_, err = dir.fs.fsClient.ListACLsForEntries(irodsPath)
			if err != nil {
				logger.WithError(err).Errorf("failed to list ACLs - %s", irodsPath)
				return nil, syscall.EREMOTEIO
			}
		}

		return fusefs.NewListDirStream(dirEntries), fusefs.OK
	} else {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return nil, syscall.EREMOTEIO
	}
}

// Rmdir removes a dir
func (dir *Dir) Rmdir(ctx context.Context, name string) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Rmdir",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	targetPath := irodsfs_common_utils.JoinPath(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Rmdir (%d) - %s", operID, targetPath)
	defer logger.Infof("Called Rmdir (%d) - %s", operID, targetPath)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", targetPath)
		return syscall.EREMOTEIO
	}

	if vpathEntry.Path == targetPath {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove mapped entry - %s", vpathEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove an entry on a read-only directory - %s", vpathEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	if vpathEntry.Type != irodsfs_common_vpath.VPathIRODS {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return syscall.EREMOTEIO
	}

	if vpathEntry.ReadOnly {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove an entry on a read-only directory - %s", vpathEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		logger.WithError(err).Errorf("failed to get IRODS path")
		return syscall.EREMOTEIO
	}

	irodsEntry, err := dir.fs.fsClient.Stat(irodsPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
			return syscall.ENOENT
		}

		logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
		return syscall.EREMOTEIO
	}

	switch irodsEntry.Type {
	case irodsclient_fs.FileEntry:
		logger.WithError(err).Errorf("failed to remove a file - %s", irodsPath)
		return syscall.EREMOTEIO
	case irodsclient_fs.DirectoryEntry:
		err = dir.fs.fsClient.RemoveDir(irodsPath, false, true)
		if err != nil {
			if irodsclient_types.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a dir - %s", irodsPath)
				return syscall.ENOENT
			} else if irodsclient_types.IsCollectionNotEmptyError(err) {
				logger.WithError(err).Errorf("the dir is not empty - %s", irodsPath)
				return syscall.ENOTEMPTY
			}

			logger.WithError(err).Errorf("failed to remove a dir - %s", irodsPath)
			return syscall.EREMOTEIO
		}
		return fusefs.OK
	default:
		logger.Errorf("unknown entry type - %s", irodsEntry.Type)
		return syscall.EREMOTEIO
	}
}

// Unlink removes a file for the path
func (dir *Dir) Unlink(ctx context.Context, name string) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Unlink",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	targetPath := irodsfs_common_utils.JoinPath(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Unlink (%d) - %s", operID, targetPath)
	defer logger.Infof("Called Unlink (%d) - %s", operID, targetPath)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", targetPath)
		return syscall.EREMOTEIO
	}

	if vpathEntry.Path == targetPath {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove mapped entry - %s", vpathEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove an entry on a read-only directory - %s", vpathEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	if vpathEntry.Type != irodsfs_common_vpath.VPathIRODS {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return syscall.EREMOTEIO
	}

	if vpathEntry.ReadOnly {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove an entry on a read-only directory - %s", vpathEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		logger.WithError(err).Errorf("failed to get IRODS path")
		return syscall.EREMOTEIO
	}

	irodsEntry, err := dir.fs.fsClient.Stat(irodsPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
			return syscall.ENOENT
		}

		logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
		return syscall.EREMOTEIO
	}

	switch irodsEntry.Type {
	case irodsclient_fs.FileEntry:
		err = dir.fs.fsClient.RemoveFile(irodsPath, true)
		if err != nil {
			if irodsclient_types.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to remove a file - %s", irodsPath)
			return syscall.EREMOTEIO
		}
		return fusefs.OK
	case irodsclient_fs.DirectoryEntry:
		logger.WithError(err).Errorf("failed to remove a dir - %s", irodsPath)
		return syscall.EREMOTEIO
	default:
		logger.Errorf("unknown entry type - %s", irodsEntry.Type)
		return syscall.EREMOTEIO
	}
}

// Mkdir makes a dir for the path
func (dir *Dir) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fusefs.Inode, syscall.Errno) {
	if dir.fs.terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Mkdir",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	targetPath := irodsfs_common_utils.JoinPath(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Mkdir (%d) - %s", operID, targetPath)
	defer logger.Infof("Called Mkdir (%d) - %s", operID, targetPath)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", targetPath)
		return nil, syscall.EREMOTEIO
	}

	if vpathEntry.Path == targetPath {
		// failed to create. read only
		err := fmt.Errorf("failed to recreate mapped entry - %s", vpathEntry.Path)
		logger.Error(err)
		return nil, syscall.EPERM
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// failed to create. read only
		err := fmt.Errorf("failed to make a new entry on a read-only directory  - %s", vpathEntry.Path)
		logger.Error(err)
		return nil, syscall.EPERM
	}

	if vpathEntry.Type != irodsfs_common_vpath.VPathIRODS {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return nil, syscall.EREMOTEIO
	}

	if vpathEntry.ReadOnly {
		err := fmt.Errorf("failed to make a new entry on a read-only directory - %s", vpathEntry.Path)
		logger.Error(err)
		return nil, syscall.EPERM
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		logger.WithError(err).Errorf("failed to get IRODS path")
		return nil, syscall.EREMOTEIO
	}

	err = dir.fs.fsClient.MakeDir(irodsPath, false)
	if err != nil {
		logger.WithError(err).Errorf("failed to make a dir - %s", irodsPath)
		return nil, syscall.EREMOTEIO
	}

	irodsEntry, err := dir.fs.fsClient.Stat(irodsPath)
	if err != nil {
		logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
		return nil, syscall.EREMOTEIO
	}

	newVPathEntry := irodsfs_common_vpath.NewVPathEntryFromIRODSFSEntry(targetPath, irodsEntry, vpathEntry.ReadOnly)
	subDir, subDirInode := dir.newSubDirInode(ctx, irodsEntry.ID, targetPath)
	subDir.setAttrOut(newVPathEntry, &out.Attr)

	return subDirInode, fusefs.OK
}

func (dir *Dir) renameNode(srcPath string, destPath string, node *fusefs.Inode) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "renameNode",
	})

	switch fsnode := node.Operations().(type) {
	case *Dir:
		relPath, err := irodsfs_common_utils.GetRelativePath(srcPath, fsnode.path)
		if err != nil {
			return err
		}

		newPath := irodsfs_common_utils.JoinPath(destPath, relPath)
		logger.Debugf("renaming a dir node %s to %s", fsnode.path, newPath)

		fsnode.path = newPath

		// recurse
		for _, childNode := range fsnode.Children() {
			err := dir.renameNode(srcPath, destPath, childNode)
			if err != nil {
				return err
			}
		}
	case *File:
		relPath, err := irodsfs_common_utils.GetRelativePath(srcPath, fsnode.path)
		if err != nil {
			return err
		}

		newPath := irodsfs_common_utils.JoinPath(destPath, relPath)
		logger.Debugf("renaming a file node %s to %s", fsnode.path, newPath)

		fsnode.path = newPath
	default:
		return fmt.Errorf("unknown node type")
	}

	return nil
}

// Rename renames a node for the path
func (dir *Dir) Rename(ctx context.Context, name string, newParent fusefs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Rename",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	targetSrcPath := irodsfs_common_utils.JoinPath(dir.path, name)

	newdir, ok := newParent.(*Dir)
	if !ok || newdir == nil {
		logger.Error("failed to convert newParent to Dir type")
		return syscall.EREMOTEIO
	}

	targetDestPath := irodsfs_common_utils.JoinPath(newdir.path, newName)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Rename (%d) - %s to %s", operID, targetSrcPath, targetDestPath)
	defer logger.Infof("Called Rename (%d) - %s to %s", operID, targetSrcPath, targetDestPath)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	if newdir != dir {
		newdir.mutex.Lock()
		defer newdir.mutex.Unlock()
	}

	vpathSrcEntry := dir.fs.vpathManager.GetClosestEntry(targetSrcPath)
	if vpathSrcEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", targetSrcPath)
		return syscall.EREMOTEIO
	}

	vpathDestEntry := dir.fs.vpathManager.GetClosestEntry(targetDestPath)
	if vpathDestEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", targetDestPath)
		return syscall.EREMOTEIO
	}

	if vpathSrcEntry.Path == targetSrcPath {
		// failed to remove. read only
		err := fmt.Errorf("failed to rename a read-only entry - %s", vpathSrcEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	if vpathDestEntry.Path == targetDestPath {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove a read-only entry - %s", vpathDestEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	if vpathSrcEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// failed to remove. read only
		err := fmt.Errorf("failed to rename a read-only entry - %s", vpathSrcEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	if vpathDestEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// failed to remove. read only
		err := fmt.Errorf("failed to rename a read-only entry - %s", vpathDestEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	if vpathSrcEntry.Type != irodsfs_common_vpath.VPathIRODS || vpathDestEntry.Type != irodsfs_common_vpath.VPathIRODS {
		logger.Errorf("unknown VPath Entry type : %s", vpathSrcEntry.Type)
		return syscall.EREMOTEIO
	}

	if vpathSrcEntry.ReadOnly {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove a read-only entry - %s", vpathSrcEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	if vpathDestEntry.ReadOnly {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove a read-only entry - %s", vpathDestEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	irodsSrcPath, err := vpathSrcEntry.GetIRODSPath(targetSrcPath)
	if err != nil {
		logger.WithError(err).Errorf("failed to get IRODS path")
		return syscall.EREMOTEIO
	}

	irodsDestPath, err := vpathDestEntry.GetIRODSPath(targetDestPath)
	if err != nil {
		logger.WithError(err).Errorf("failed to get IRODS path")
		return syscall.EREMOTEIO
	}

	irodsEntry, err := dir.fs.fsClient.Stat(irodsSrcPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("failed to find a file - %s", irodsSrcPath)
			return syscall.ENOENT
		}

		logger.WithError(err).Errorf("failed to stat - %s", irodsSrcPath)
		return syscall.EREMOTEIO
	}

	switch irodsEntry.Type {
	case irodsclient_fs.DirectoryEntry:
		// lock first
		openFilePaths := dir.fs.fileHandleMap.ListPathsInDir(irodsSrcPath)
		for _, openFilePath := range openFilePaths {
			handlesOpened := dir.fs.fileHandleMap.ListByPath(openFilePath)
			for _, handle := range handlesOpened {
				handle.mutex.Lock()
				defer handle.mutex.Unlock()
			}
		}

		err = dir.fs.fsClient.RenameDirToDir(irodsSrcPath, irodsDestPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to rename dir - %s to %s", irodsSrcPath, irodsDestPath)
			return syscall.EREMOTEIO
		}

		// update
		childNode := dir.GetChild(name)
		if childNode == nil {
			logger.Errorf("failed to update the dir node - %s", irodsSrcPath)
			return syscall.EREMOTEIO
		}

		dir.renameNode(targetSrcPath, targetDestPath, childNode)

		// report update to fileHandleMap
		dir.fs.fileHandleMap.RenameDir(irodsSrcPath, irodsDestPath)

		return fusefs.OK
	case irodsclient_fs.FileEntry:
		destEntry, err := dir.fs.fsClient.Stat(irodsDestPath)
		if err != nil {
			if !irodsclient_types.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to stat - %s", irodsDestPath)
				return syscall.EREMOTEIO
			}
		} else {
			// no error - file exists
			if destEntry.ID > 0 {
				// delete first
				err = dir.fs.fsClient.RemoveFile(irodsDestPath, true)
				if err != nil {
					logger.WithError(err).Errorf("failed to delete file - %s", irodsDestPath)
					return syscall.EREMOTEIO
				}
			}
		}

		// lock first
		handlesOpened := dir.fs.fileHandleMap.ListByPath(irodsSrcPath)
		for _, handle := range handlesOpened {
			handle.mutex.Lock()
			defer handle.mutex.Unlock()
		}

		err = dir.fs.fsClient.RenameFileToFile(irodsSrcPath, irodsDestPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to rename file - %s to %s", irodsSrcPath, irodsDestPath)
			return syscall.EREMOTEIO
		}

		// update
		childNode := dir.GetChild(name)
		if childNode == nil {
			logger.Errorf("failed to update the file node - %s", irodsSrcPath)
			return syscall.EREMOTEIO
		}

		dir.renameNode(targetSrcPath, targetDestPath, childNode)

		// report update to fileHandleMap
		dir.fs.fileHandleMap.Rename(irodsSrcPath, irodsDestPath)

		return fusefs.OK
	default:
		logger.Errorf("unknown entry type - %s", irodsEntry.Type)
		return syscall.EREMOTEIO
	}
}

// Create creates a file for the path and returns file handle
func (dir *Dir) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fusefs.Inode, fusefs.FileHandle, uint32, syscall.Errno) {
	if dir.fs.terminated {
		return nil, nil, 0, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Create",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	targetPath := irodsfs_common_utils.JoinPath(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Create (%d) - %s", operID, targetPath)
	defer logger.Infof("Called Create (%d) - %s", operID, targetPath)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	var openMode string
	fuseFlag := uint32(0)

	if flags&uint32(os.O_WRONLY) == uint32(os.O_WRONLY) {
		openMode = string(irodsclient_types.FileOpenModeWriteOnly)

		if flags&uint32(os.O_APPEND) == uint32(os.O_APPEND) {
			// append
			openMode = string(irodsclient_types.FileOpenModeAppend)
		} else if flags&uint32(os.O_TRUNC) == uint32(os.O_TRUNC) {
			// truncate
			openMode = string(irodsclient_types.FileOpenModeWriteTruncate)
		}

		// if we use Direct_IO, it will disable kernel cache, read-ahead, shared mmap
		//fuseFlag |= fuse.FOPEN_DIRECT_IO
	} else if flags&uint32(os.O_RDWR) == uint32(os.O_RDWR) {
		openMode = string(irodsclient_types.FileOpenModeReadWrite)
	} else {
		logger.Errorf("unknown file open mode - 0o%o", flags)
		return nil, nil, 0, syscall.EPERM
	}

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", targetPath)
		return nil, nil, 0, syscall.EREMOTEIO
	}

	if vpathEntry.Path == targetPath {
		// failed to create. read only
		err := fmt.Errorf("failed to recreate mapped entry - %s", vpathEntry.Path)
		logger.Error(err)
		return nil, nil, 0, syscall.EPERM
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// failed to create. read only
		err := fmt.Errorf("failed to make a new entry on a read-only directory - %s", vpathEntry.Path)
		logger.Error(err)
		return nil, nil, 0, syscall.EPERM
	}

	if vpathEntry.Type != irodsfs_common_vpath.VPathIRODS {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return nil, nil, 0, syscall.EREMOTEIO
	}

	if vpathEntry.ReadOnly {
		// failed to create. read only
		err := fmt.Errorf("failed to make a new entry on a read-only directory - %s", vpathEntry.Path)
		logger.Error(err)
		return nil, nil, 0, syscall.EPERM
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		logger.WithError(err).Errorf("failed to get IRODS path")
		return nil, nil, 0, syscall.EREMOTEIO
	}

	handle, err := dir.fs.fsClient.CreateFile(irodsPath, "", openMode)
	if err != nil {
		logger.WithError(err).Errorf("failed to create a file - %s", irodsPath)
		return nil, nil, 0, syscall.EREMOTEIO
	}

	irodsEntry, err := dir.fs.fsClient.Stat(irodsPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.WithError(err).Infof("failed to find a file - %s", irodsPath)
			return nil, nil, 0, syscall.EREMOTEIO
		}

		logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
		return nil, nil, 0, syscall.EREMOTEIO
	}

	newVPathEntry := irodsfs_common_vpath.NewVPathEntryFromIRODSFSEntry(targetPath, irodsEntry, vpathEntry.ReadOnly)
	subFile, subFileInode := dir.newSubFileInode(ctx, irodsEntry.ID, targetPath)
	subFile.setAttrOut(newVPathEntry, &out.Attr)

	if dir.fs.instanceReportClient != nil {
		dir.fs.instanceReportClient.StartFileAccess(handle)
	}

	fileHandle := NewFileHandle(subFile, handle)

	// add to file handle map
	dir.fs.fileHandleMap.Add(fileHandle)

	return subFileInode, fileHandle, fuseFlag, fusefs.OK
}

/*
func (dir *Dir) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
}

func (dir *Dir) Link(ctx context.Context, target InodeEmbedder, name string, out *fuse.EntryOut) (node *Inode, errno syscall.Errno) {
}

func (dir *Dir) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (node *Inode, errno syscall.Errno) {
}

func (dir *Dir) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
}
*/
