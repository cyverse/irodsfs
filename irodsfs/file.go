package irodsfs

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"

	fuse "bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	irodsfs_common_utils "github.com/cyverse/irodsfs-common/utils"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"

	log "github.com/sirupsen/logrus"
)

// File is a file node
type File struct {
	fs         *IRODSFS
	inodeID    int64
	path       string
	vpathEntry *irodsfs_common_vpath.VPathEntry
	mutex      sync.RWMutex // for accessing Path
}

// NewFile creates a new File
func NewFile(fs *IRODSFS, inodeID int64, path string, vpathEntry *irodsfs_common_vpath.VPathEntry) *File {
	return &File{
		fs:         fs,
		inodeID:    inodeID,
		path:       path,
		vpathEntry: vpathEntry,
		mutex:      sync.RWMutex{},
	}
}

func mapFileACL(vpathEntry *irodsfs_common_vpath.VPathEntry, file *File, irodsEntry *irodsclient_fs.Entry) os.FileMode {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "mapFileACL",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// we don't actually check permissions for reading file when vpathEntry is read only
	// because files with no-access for the user will not be visible
	if vpathEntry.ReadOnly {
		return 0o400
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

	var highestPermission os.FileMode = 0o400
	for _, access := range accesses {
		if access.UserType == irodsclient_types.IRODSUserRodsUser && access.UserName == file.fs.config.ClientUser {
			// found
			switch access.AccessLevel {
			case irodsclient_types.IRODSAccessLevelOwner:
				// highest, don't need to continue
				return 0o700
			case irodsclient_types.IRODSAccessLevelWrite:
				if highestPermission < 0o600 {
					highestPermission = 0o600
				}
			case irodsclient_types.IRODSAccessLevelRead:
				if highestPermission < 0o400 {
					highestPermission = 0o400
				}
			case irodsclient_types.IRODSAccessLevelNone:
				// nothing
			}
		} else if access.UserType == irodsclient_types.IRODSUserRodsGroup {
			if _, ok := file.fs.userGroupsMap[access.UserName]; ok {
				// my group
				switch access.AccessLevel {
				case irodsclient_types.IRODSAccessLevelOwner:
					// highest, don't need to continue
					return 0o700
				case irodsclient_types.IRODSAccessLevelWrite:
					if highestPermission < 0o600 {
						highestPermission = 0o600
					}
				case irodsclient_types.IRODSAccessLevelRead:
					if highestPermission < 0o400 {
						highestPermission = 0o400
					}
				case irodsclient_types.IRODSAccessLevelNone:
					// nothing
				}
			}
		}
	}

	logger.Debugf("failed to find ACL information of the Entry for %s and user %s", irodsEntry.Path, file.fs.config.ClientUser)
	return highestPermission
}

// Attr returns stat of file entry
func (file *File) Attr(ctx context.Context, attr *fuse.Attr) error {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Attr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// apply pending update if exists
	file.fs.fileMetaUpdater.Apply(file)

	file.mutex.RLock()
	defer file.mutex.RUnlock()

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Attr (%d) - %s", operID, file.path)
	defer logger.Infof("Called Attr (%d) - %s", operID, file.path)

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", file.path)
		return syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		logger.Errorf("failed to get file attribute from a virtual dir mapping")
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

		file.vpathEntry = irodsfs_common_vpath.NewVPathEntryFromIRODSFSEntry(file.path, irodsEntry, vpathEntry.ReadOnly)

		attr.Inode = uint64(irodsEntry.ID)
		attr.Uid = file.fs.uid
		attr.Gid = file.fs.gid
		attr.Ctime = irodsEntry.CreateTime
		attr.Mtime = irodsEntry.ModifyTime
		attr.Atime = irodsEntry.ModifyTime
		attr.Size = uint64(irodsEntry.Size)
		attr.Mode = mapFileACL(vpathEntry, file, irodsEntry)
		return nil
	}

	logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
	return syscall.EREMOTEIO
}

// Setattr sets file attributes
func (file *File) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Setattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// apply pending update if exists
	file.fs.fileMetaUpdater.Apply(file)

	// don't lock here
	//file.Mutex.RLock()
	//defer file.Mutex.RUnlock()

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Setattr (%d) - %s", operID, file.path)
	defer logger.Infof("Called Setattr (%d) - %s", operID, file.path)

	if req.Valid.Size() {
		// size changed
		// call Truncate()
		err := file.Truncate(ctx, req.Size)
		if err != nil {
			return err
		}
		resp.Attr.Size = req.Size
		return nil
	} else if req.Valid.Mode() {
		// chmod
		// not supported
		return syscall.EOPNOTSUPP
	} else if req.Valid.Atime() || req.Valid.AtimeNow() || req.Valid.Mtime() || req.Valid.MtimeNow() {
		// changing date
		// not supported
		return syscall.EOPNOTSUPP
	} else if req.Valid.Gid() || req.Valid.Uid() {
		// changing ownership
		// not supported
		return syscall.EOPNOTSUPP
	}

	return nil
}

// Truncate truncates file entry
func (file *File) Truncate(ctx context.Context, size uint64) error {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Truncate",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// apply pending update if exists
	file.fs.fileMetaUpdater.Apply(file)

	file.mutex.RLock()
	defer file.mutex.RUnlock()

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

				err = handle.Truncate(ctx, int64(size))
				if err != nil {
					logger.WithError(err).Errorf("failed to truncate a file - %s, %d", irodsPath, size)
					return syscall.EREMOTEIO
				}

				callFtruncate = true
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

		return nil
	}

	logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
	return syscall.EREMOTEIO
}

// Open opens file for the path and returns file handle
func (file *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fusefs.Handle, error) {
	if file.fs.terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Open",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// apply pending update if exists
	file.fs.fileMetaUpdater.Apply(file)

	file.mutex.RLock()
	defer file.mutex.RUnlock()

	openMode := string(irodsclient_types.FileOpenModeReadOnly)
	resp.Flags |= fuse.OpenDirectIO

	if req.Flags.IsReadOnly() {
		openMode = string(irodsclient_types.FileOpenModeReadOnly)
		//resp.Flags |= fuse.OpenKeepCache
	} else if req.Flags.IsWriteOnly() {
		openMode = string(irodsclient_types.FileOpenModeWriteOnly)

		if req.Flags&fuse.OpenAppend == fuse.OpenAppend {
			// append
			openMode = string(irodsclient_types.FileOpenModeAppend)
		} else if req.Flags&fuse.OpenTruncate == fuse.OpenTruncate {
			// truncate
			openMode = string(irodsclient_types.FileOpenModeWriteTruncate)
		}
	} else if req.Flags.IsReadWrite() {
		openMode = string(irodsclient_types.FileOpenModeReadWrite)
	} else {
		logger.Errorf("unknown file open mode - %s", req.Flags.String())
		return nil, syscall.EACCES
	}

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Open (%d) - %s, mode(%s)", operID, file.path, openMode)
	defer logger.Infof("Called Open (%d) - %s, mode(%s)", operID, file.path, openMode)

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", file.path)
		return nil, syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// failed to open directory
		err := fmt.Errorf("failed to open mapped directory entry - %s", vpathEntry.Path)
		logger.Error(err)
		return nil, syscall.EACCES
	} else if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		if vpathEntry.ReadOnly && openMode != string(irodsclient_types.FileOpenModeReadOnly) {
			logger.Errorf("failed to open a read-only file with non-read-only mode")
			return nil, syscall.EREMOTEIO
		}

		irodsPath, err := vpathEntry.GetIRODSPath(file.path)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return nil, syscall.EREMOTEIO
		}

		handle, err := file.fs.fsClient.OpenFile(irodsPath, "", openMode)
		if err != nil {
			if irodsclient_types.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return nil, syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to open a file - %s", irodsPath)
			return nil, syscall.EREMOTEIO
		}

		if file.fs.instanceReportClient != nil {
			file.fs.instanceReportClient.StartFileAccess(handle)
		}

		fileHandle := NewFileHandle(file, handle)

		// add to file handle map
		file.fs.fileHandleMap.Add(fileHandle)

		return fileHandle, nil
	}

	logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
	return nil, syscall.EREMOTEIO
}

// Fsync syncs file
func (file *File) Fsync(ctx context.Context, req *fuse.FsyncRequest) error {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	return nil
}
