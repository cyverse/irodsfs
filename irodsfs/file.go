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

// File is a file node
type File struct {
	fusefs.Inode

	fs      *IRODSFS
	entryID int64
	path    string
	mutex   sync.RWMutex
}

// NewFile creates a new File
func NewFile(fs *IRODSFS, entryID int64, path string) *File {
	return &File{
		fs:      fs,
		entryID: entryID,
		path:    path,
	}
}

func (file *File) getStableAttr() fusefs.StableAttr {
	return fusefs.StableAttr{
		Mode: fuse.S_IFREG,
		Ino:  uint64(file.entryID),
		Gen:  0,
	}
}

func (file *File) setAttrOut(vpathEntry *irodsfs_common_vpath.VPathEntry, out *fuse.Attr) {
	if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		// irods
		out.Ino = uint64(vpathEntry.IRODSEntry.ID)
		out.Uid = file.fs.uid
		out.Gid = file.fs.gid
		out.Ctime = uint64(vpathEntry.IRODSEntry.CreateTime.UnixMilli())
		out.Mtime = uint64(vpathEntry.IRODSEntry.ModifyTime.UnixMilli())
		out.Atime = uint64(vpathEntry.IRODSEntry.ModifyTime.UnixMilli())
		out.Size = uint64(vpathEntry.IRODSEntry.Size)
		out.Mode = uint32(fuse.S_IFREG | file.getACL(vpathEntry.IRODSEntry, vpathEntry.ReadOnly))
	}
}

func (file *File) getPermission(level irodsclient_types.IRODSAccessLevelType) os.FileMode {
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

func (file *File) getACL(irodsEntry *irodsclient_fs.Entry, readonly bool) os.FileMode {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "getACL",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// we don't actually check permissions for reading file when vpathEntry is read only
	// because files with no-access for the user will not be visible
	if readonly {
		return 0o500
	}

	if file.fs.config.NoPermissionCheck {
		// skip perform permission check
		// give the highest permission, but this doesn't mean that the user can write data
		// since iRODS will check permission
		return 0o700
	}

	if irodsEntry.Owner == file.fs.config.ClientUser {
		// mine
		return 0o700
	}

	logger.Infof("Checking ACL information of the Entry for %s and user %s", irodsEntry.Path, file.fs.config.ClientUser)
	defer logger.Infof("Checked ACL information of the Entry for %s and user %s", irodsEntry.Path, file.fs.config.ClientUser)

	accesses, err := file.fs.fsClient.ListFileACLs(irodsEntry.Path)
	if err != nil {
		logger.Errorf("failed to get ACL information of the Entry for %s", irodsEntry.Path)
	}

	var highestPermission os.FileMode = 0o500
	for _, access := range accesses {
		if access.UserType == irodsclient_types.IRODSUserRodsUser && access.UserName == file.fs.config.ClientUser {
			perm := file.getPermission(access.AccessLevel)
			if perm == 0o700 {
				return perm
			}

			if perm > highestPermission {
				highestPermission = perm
			}
		} else if access.UserType == irodsclient_types.IRODSUserRodsGroup {
			if _, ok := file.fs.userGroupsMap[access.UserName]; ok {
				// my group
				perm := file.getPermission(access.AccessLevel)
				if perm == 0o700 {
					return perm
				}

				if perm > highestPermission {
					highestPermission = perm
				}
			}
		}
	}

	logger.Debugf("failed to find ACL information of the Entry for %s and user %s", irodsEntry.Path, file.fs.config.ClientUser)
	return highestPermission
}

// Getattr returns stat of file entry
func (file *File) Getattr(ctx context.Context, fh fusefs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Getattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	file.mutex.RLock()
	defer file.mutex.RUnlock()

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Getattr (%d) - %s", operID, file.path)
	defer logger.Infof("Called Getattr (%d) - %s", operID, file.path)

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", file.path)
		return syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		logger.Errorf("failed to get file attribute from a virtual dir mapping")
		return syscall.EREMOTEIO
	} else if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		if vpathEntry.IRODSEntry.Type != irodsclient_fs.FileEntry {
			logger.Errorf("failed to get file attributes")
			return syscall.EREMOTEIO
		}

		irodsPath, err := vpathEntry.GetIRODSPath(file.path)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return syscall.EREMOTEIO
		}

		irodsEntry, err := file.fs.fsClient.Stat(irodsPath)
		if err != nil {
			if irodsclient_types.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return syscall.EREMOTEIO
		}

		newVPathEntry := irodsfs_common_vpath.NewVPathEntryFromIRODSFSEntry(file.path, irodsEntry, vpathEntry.ReadOnly)
		file.setAttrOut(newVPathEntry, &out.Attr)
		return fusefs.OK
	}

	logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
	return syscall.EREMOTEIO
}

// Setattr sets file attributes
func (file *File) Setattr(ctx context.Context, fh fusefs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Setattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Setattr (%d) - %s", operID, file.path)
	defer logger.Infof("Called Setattr (%d) - %s", operID, file.path)

	if _, ok := in.GetMode(); ok {
		// chmod
		// not supported
		return syscall.EOPNOTSUPP
	} else if _, ok := in.GetATime(); ok {
		// changing date
		// not supported but return OK to not cause various errors in linux commands
		return fusefs.OK
	} else if _, ok := in.GetCTime(); ok {
		// changing date
		// not supported but return OK to not cause various errors in linux commands
		return fusefs.OK
	} else if _, ok := in.GetMTime(); ok {
		// changing date
		// not supported but return OK to not cause various errors in linux commands
		return fusefs.OK
	} else if _, ok := in.GetGID(); ok {
		// changing ownership
		// not supported
		return syscall.EOPNOTSUPP
	} else if _, ok := in.GetUID(); ok {
		// changing ownership
		// not supported
<<<<<<< HEAD
		//return syscall.EOPNOTSUPP
		// but do not return EOPNOTSUPP since it will cause various errors in fs clients
		return nil
=======
		return syscall.EOPNOTSUPP
	} else if size, ok := in.GetSize(); ok {
		// truncate file
		errno := file.Truncate(ctx, size)
		if errno != fusefs.OK {
			return errno
		}

		out.Size = size
		return fusefs.OK
>>>>>>> port to go-fuse
	}

	return fusefs.OK
}

// Truncate truncates file entry
func (file *File) Truncate(ctx context.Context, size uint64) syscall.Errno {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Truncate",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	file.mutex.Lock()
	defer file.mutex.Unlock()

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Truncate (%d) - %s, %d", operID, file.path, size)
	defer logger.Infof("Called Truncate (%d) - %s, %d", operID, file.path, size)

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", file.path)
		return syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		logger.Errorf("failed to truncate a virtual dir")
		return syscall.EREMOTEIO
	} else if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		irodsPath, err := vpathEntry.GetIRODSPath(file.path)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return syscall.EREMOTEIO
		}

		// redo to get fresh info
		irodsEntry, err := file.fs.fsClient.Stat(irodsPath)
		if err != nil {
			if irodsclient_types.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return syscall.EREMOTEIO
		}

		// check if there're opened file handles
		// handle ftruncate operation
		callFtruncate := false
		handlesOpened := file.fs.fileHandleMap.ListByPath(irodsPath)
		for _, handle := range handlesOpened {
			if handle.fileHandle.IsWriteMode() {
				// is writing
				logger.Infof("Found opened file handle %s - %s", handle.file.path, handle.fileHandle.GetID())

				errno := handle.Truncate(ctx, size)
				if errno != 0 {
					logger.Errorf("failed to truncate a file - %s, %d", irodsPath, size)
					return errno
				}

				callFtruncate = true

				// avoid truncating a file multiple times
				break
			}
		}

		if !callFtruncate {
			if irodsEntry.Size != int64(size) {
				err = file.fs.fsClient.TruncateFile(irodsPath, int64(size))
				if err != nil {
					if irodsclient_types.IsFileNotFoundError(err) {
						logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
						return syscall.ENOENT
					}

					logger.WithError(err).Errorf("failed to truncate a file - %s, %d", irodsPath, size)
					return syscall.EREMOTEIO
				}
			}
		}

		return fusefs.OK
	}

	logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
	return syscall.EREMOTEIO
}

// Open opens file for the path and returns file handle
func (file *File) Open(ctx context.Context, flags uint32) (fusefs.FileHandle, uint32, syscall.Errno) {
	if file.fs.terminated {
		return nil, 0, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Open",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	file.mutex.RLock()
	defer file.mutex.RUnlock()

	openMode := string(irodsclient_types.FileOpenModeReadOnly)
	fuseFlag := uint32(0)

	// if we use Direct_IO, it will disable kernel cache, read-ahead, shared mmap
	//fuseFlag |= fuse.FOPEN_DIRECT_IO

	if flags&uint32(os.O_RDONLY) == uint32(os.O_RDONLY) {
		openMode = string(irodsclient_types.FileOpenModeReadOnly)
		//fuseFlag |= fuse.FOPEN_KEEP_CACHE
	} else if flags&uint32(os.O_WRONLY) == uint32(os.O_WRONLY) {
		openMode = string(irodsclient_types.FileOpenModeWriteOnly)

		if flags&uint32(os.O_APPEND) == uint32(os.O_APPEND) {
			// append
			openMode = string(irodsclient_types.FileOpenModeAppend)
		} else if flags&uint32(os.O_TRUNC) == uint32(os.O_TRUNC) {
			// truncate
			openMode = string(irodsclient_types.FileOpenModeWriteTruncate)
		}
	} else if flags&uint32(os.O_RDWR) == uint32(os.O_RDWR) {
		openMode = string(irodsclient_types.FileOpenModeReadWrite)
	} else {
		logger.Errorf("unknown file open mode - 0o%o", flags)
		return nil, 0, syscall.EPERM
	}

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Open (%d) - %s, mode(%s)", operID, file.path, openMode)
	defer logger.Infof("Called Open (%d) - %s, mode(%s)", operID, file.path, openMode)

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", file.path)
		return nil, 0, syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// failed to open directory
		err := fmt.Errorf("failed to open mapped directory entry - %s", vpathEntry.Path)
		logger.Error(err)
		return nil, 0, syscall.EPERM
	} else if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		if vpathEntry.ReadOnly && openMode != string(irodsclient_types.FileOpenModeReadOnly) {
			logger.Errorf("failed to open a read-only file with non-read-only mode")
			return nil, 0, syscall.EREMOTEIO
		}

		irodsPath, err := vpathEntry.GetIRODSPath(file.path)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return nil, 0, syscall.EREMOTEIO
		}

		handle, err := file.fs.fsClient.OpenFile(irodsPath, "", openMode)
		if err != nil {
			if irodsclient_types.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return nil, 0, syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to open a file - %s", irodsPath)
			return nil, 0, syscall.EREMOTEIO
		}

		if file.fs.instanceReportClient != nil {
			file.fs.instanceReportClient.StartFileAccess(handle)
		}

		fileHandle := NewFileHandle(file, handle)

		// add to file handle map
		file.fs.fileHandleMap.Add(fileHandle)

		return fileHandle, fuseFlag, fusefs.OK
	}

	logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
	return nil, 0, syscall.EREMOTEIO
}

/*
func (dir *Dir) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
}

func (dir *Dir) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
}

func (dir *Dir) Removexattr(ctx context.Context, attr string) syscall.Errno {
}

func (dir *Dir) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
}

func (dir *Dir) Link(ctx context.Context, target InodeEmbedder, name string, out *fuse.EntryOut) (node *Inode, errno syscall.Errno) {
}

func (dir *Dir) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (node *Inode, errno syscall.Errno) {
}

func (dir *Dir) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
}
*/
