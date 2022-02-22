package irodsfs

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"syscall"

	fuse "bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	"github.com/cyverse/irodsfs/pkg/io"
	"github.com/cyverse/irodsfs/pkg/irodsapi"
	"github.com/cyverse/irodsfs/pkg/vfs"
	log "github.com/sirupsen/logrus"
)

// File is a file node
type File struct {
	FS      *IRODSFS
	InodeID int64
	Path    string
	Entry   *vfs.VFSEntry
	Mutex   sync.RWMutex // for accessing Path
}

func mapFileACL(vfsEntry *vfs.VFSEntry, file *File, irodsEntry *irodsapi.IRODSEntry) os.FileMode {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "mapFileACL",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// we don't actually check permissions for reading file when vfsEntry is read only
	// because files with no-access for the user will not be visible
	if vfsEntry.ReadOnly {
		return 0o400
	}

	if irodsEntry.Owner == file.FS.Config.ClientUser {
		// mine
		return 0o700
	}

	logger.Infof("Checking ACL information of the Entry for %s and user %s", irodsEntry.Path, file.FS.Config.ClientUser)
	defer logger.Infof("Checked ACL information of the Entry for %s and user %s", irodsEntry.Path, file.FS.Config.ClientUser)

	accesses, err := file.FS.IRODSClient.ListFileACLs(irodsEntry.Path)
	if err != nil {
		logger.Errorf("failed to get ACL information of the Entry for %s", irodsEntry.Path)
	}

	var highestPermission os.FileMode = 0o400
	for _, access := range accesses {
		if access.UserType == irodsapi.IRODSUserRodsUser && access.UserName == file.FS.Config.ClientUser {
			// found
			switch access.AccessLevel {
			case irodsapi.IRODSAccessLevelOwner:
				// highest, don't need to continue
				return 0o700
			case irodsapi.IRODSAccessLevelWrite:
				if highestPermission < 0o600 {
					highestPermission = 0o600
				}
			case irodsapi.IRODSAccessLevelRead:
				if highestPermission < 0o400 {
					highestPermission = 0o400
				}
			case irodsapi.IRODSAccessLevelNone:
				// nothing
			}
		} else if access.UserType == irodsapi.IRODSUserRodsGroup {
			if _, ok := file.FS.UserGroupsMap[access.UserName]; ok {
				// my group
				switch access.AccessLevel {
				case irodsapi.IRODSAccessLevelOwner:
					// highest, don't need to continue
					return 0o700
				case irodsapi.IRODSAccessLevelWrite:
					if highestPermission < 0o600 {
						highestPermission = 0o600
					}
				case irodsapi.IRODSAccessLevelRead:
					if highestPermission < 0o400 {
						highestPermission = 0o400
					}
				case irodsapi.IRODSAccessLevelNone:
					// nothing
				}
			}
		}
	}

	logger.Errorf("failed to find ACL information of the Entry for %s and user %s", irodsEntry.Path, file.FS.Config.ClientUser)
	return highestPermission
}

// Attr returns stat of file entry
func (file *File) Attr(ctx context.Context, attr *fuse.Attr) error {
	if file.FS.Terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Attr",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	file.FS.FileMetaUpdater.Apply(file)

	file.Mutex.RLock()
	defer file.Mutex.RUnlock()

	operID := file.FS.GetNextOperationID()
	logger.Infof("Calling Attr (%d) - %s", operID, file.Path)
	defer logger.Infof("Called Attr (%d) - %s", operID, file.Path)

	vfsEntry := file.FS.VFS.GetClosestEntry(file.Path)
	if vfsEntry == nil {
		logger.Errorf("failed to get VFS Entry for %s", file.Path)
		return syscall.EREMOTEIO
	}

	if vfsEntry.Type == vfs.VFSVirtualDirEntryType {
		logger.Errorf("failed to get file attribute from a virtual dir mapping")
		return syscall.EREMOTEIO
	} else if vfsEntry.Type == vfs.VFSIRODSEntryType {
		irodsPath, err := vfsEntry.GetIRODSPath(file.Path)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return syscall.EREMOTEIO
		}

		// redo to get fresh info
		irodsEntry, err := file.FS.IRODSClient.Stat(irodsPath)
		if err != nil {
			if irodsapi.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return syscall.EREMOTEIO
		}

		file.Entry = vfs.NewVFSEntryFromIRODSFSEntry(file.Path, irodsEntry, vfsEntry.ReadOnly)

		attr.Inode = uint64(irodsEntry.ID)
		attr.Uid = file.FS.UID
		attr.Gid = file.FS.GID
		attr.Ctime = irodsEntry.CreateTime
		attr.Mtime = irodsEntry.ModifyTime
		attr.Atime = irodsEntry.ModifyTime
		attr.Size = uint64(irodsEntry.Size)
		attr.Mode = mapFileACL(vfsEntry, file, irodsEntry)
		return nil
	}

	logger.Errorf("unknown VFS Entry type : %s", vfsEntry.Type)
	return syscall.EREMOTEIO
}

// Setattr sets file attributes
func (file *File) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
	if file.FS.Terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Setattr",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	file.FS.FileMetaUpdater.Apply(file)

	file.Mutex.RLock()
	defer file.Mutex.RUnlock()

	operID := file.FS.GetNextOperationID()
	logger.Infof("Calling Setattr (%d) - %s", operID, file.Path)
	defer logger.Infof("Called Setattr (%d) - %s", operID, file.Path)

	if req.Valid.Size() {
		// size changed
		// call Truncate()
		return file.Truncate(ctx, req, resp)
	}
	return nil
}

// Truncate truncates file entry
func (file *File) Truncate(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
	if file.FS.Terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Truncate",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	file.FS.FileMetaUpdater.Apply(file)

	file.Mutex.RLock()
	defer file.Mutex.RUnlock()

	operID := file.FS.GetNextOperationID()
	logger.Infof("Calling Truncate (%d) - %s, %d", operID, file.Path, req.Size)
	defer logger.Infof("Called Truncate (%d) - %s, %d", operID, file.Path, req.Size)

	vfsEntry := file.FS.VFS.GetClosestEntry(file.Path)
	if vfsEntry == nil {
		logger.Errorf("failed to get VFS Entry for %s", file.Path)
		return syscall.EREMOTEIO
	}

	if vfsEntry.Type == vfs.VFSVirtualDirEntryType {
		logger.Errorf("failed to truncate a virtual dir")
		return syscall.EREMOTEIO
	} else if vfsEntry.Type == vfs.VFSIRODSEntryType {
		irodsPath, err := vfsEntry.GetIRODSPath(file.Path)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return syscall.EREMOTEIO
		}

		// redo to get fresh info
		_, err = file.FS.IRODSClient.Stat(irodsPath)
		if err != nil {
			if irodsapi.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return syscall.EREMOTEIO
		}

		err = file.FS.IRODSClient.TruncateFile(irodsPath, int64(req.Size))
		if err != nil {
			if irodsapi.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to truncate a file - %s, %d", irodsPath, req.Size)
			return syscall.EREMOTEIO
		}

		return nil
	}

	logger.Errorf("unknown VFS Entry type : %s", vfsEntry.Type)
	return syscall.EREMOTEIO
}

// Open opens file for the path and returns file handle
func (file *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fusefs.Handle, error) {
	if file.FS.Terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Open",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	file.FS.FileMetaUpdater.Apply(file)

	file.Mutex.RLock()
	defer file.Mutex.RUnlock()

	openMode := string(irodsapi.FileOpenModeReadOnly)

	if req.Flags.IsReadOnly() {
		openMode = string(irodsapi.FileOpenModeReadOnly)
		resp.Flags |= fuse.OpenKeepCache
		resp.Flags &^= fuse.OpenDirectIO // disable
	} else if req.Flags.IsWriteOnly() {
		openMode = string(irodsapi.FileOpenModeWriteOnly)

		if req.Flags&fuse.OpenAppend == fuse.OpenAppend {
			// append
			openMode = string(irodsapi.FileOpenModeAppend)
		} else if req.Flags&fuse.OpenTruncate == fuse.OpenTruncate {
			// truncate
			openMode = string(irodsapi.FileOpenModeWriteTruncate)
		}
		resp.Flags |= fuse.OpenDirectIO
	} else if req.Flags.IsReadWrite() {
		openMode = string(irodsapi.FileOpenModeReadWrite)
	} else {
		logger.Errorf("unknown file open mode - %s", req.Flags.String())
		return nil, syscall.EACCES
	}

	operID := file.FS.GetNextOperationID()
	logger.Infof("Calling Open (%d) - %s, mode(%s)", operID, file.Path, openMode)
	defer logger.Infof("Called Open (%d) - %s, mode(%s)", operID, file.Path, openMode)

	vfsEntry := file.FS.VFS.GetClosestEntry(file.Path)
	if vfsEntry == nil {
		logger.Errorf("failed to get VFS Entry for %s", file.Path)
		return nil, syscall.EREMOTEIO
	}

	if vfsEntry.Type == vfs.VFSVirtualDirEntryType {
		// failed to open directory
		err := fmt.Errorf("failed to open mapped directory entry - %s", vfsEntry.Path)
		logger.Error(err)
		return nil, syscall.EACCES
	} else if vfsEntry.Type == vfs.VFSIRODSEntryType {
		if vfsEntry.ReadOnly && openMode != string(irodsapi.FileOpenModeReadOnly) {
			logger.Errorf("failed to open a read-only file with non-read-only mode")
			return nil, syscall.EREMOTEIO
		}

		irodsPath, err := vfsEntry.GetIRODSPath(file.Path)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return nil, syscall.EREMOTEIO
		}

		handle, err := file.FS.IRODSClient.OpenFile(irodsPath, "", openMode)
		if err != nil {
			if irodsapi.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return nil, syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to open a file - %s", irodsPath)
			return nil, syscall.EREMOTEIO
		}

		handleMutex := &sync.Mutex{}

		if file.FS.MonitoringReporter != nil {
			file.FS.MonitoringReporter.ReportNewFileTransferStart(file.Entry.IRODSEntry.Path, handle, file.Entry.IRODSEntry.Size)
		}

		var writer io.Writer
		if req.Flags.IsWriteOnly() && len(file.FS.Config.PoolHost) == 0 {
			asyncWriter := io.NewAsyncWriter(irodsPath, handle, handleMutex, file.FS.Buffer, file.FS.MonitoringReporter)
			writer = io.NewBufferedWriter(irodsPath, asyncWriter)
		} else if req.Flags.IsReadWrite() {
			writer = io.NewSyncWriter(irodsPath, handle, handleMutex, file.FS.MonitoringReporter)
		} else {
			writer = nil
		}

		fileHandle := &FileHandle{
			FS:             file.FS,
			Path:           file.Path,
			Entry:          file.Entry,
			IRODSFSEntry:   file.Entry.IRODSEntry,
			FileHandle:     handle,
			FileHandleLock: handleMutex,

			Writer: writer,
		}

		return fileHandle, nil
	}

	logger.Errorf("unknown VFS Entry type : %s", vfsEntry.Type)
	return nil, syscall.EREMOTEIO
}

// Fsync syncs file
func (file *File) Fsync(ctx context.Context, req *fuse.FsyncRequest) error {
	if file.FS.Terminated {
		return syscall.ECONNABORTED
	}

	return nil
}
