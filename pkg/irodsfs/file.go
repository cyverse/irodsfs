package irodsfs

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"

	"bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	"github.com/cyverse/irodsfs/pkg/asyncwrite"
	"github.com/cyverse/irodsfs/pkg/irodsapi"
	"github.com/cyverse/irodsfs/pkg/vfs"
	log "github.com/sirupsen/logrus"
)

const (
	WriteBlockSize int = 1024 * 1024 * 8 // 8MB
)

// File is a file node
type File struct {
	FS      *IRODSFS
	InodeID int64
	Path    string
	Entry   *vfs.VFSEntry
	Mutex   sync.RWMutex // for accessing Path
}

// FileHandle is a file handle
type FileHandle struct {
	FS             *IRODSFS
	Path           string
	Entry          *vfs.VFSEntry
	IRODSFSEntry   *irodsapi.IRODSEntry
	FileHandle     irodsapi.IRODSFileHandle
	FileHandleLock *sync.Mutex

	Writer asyncwrite.Writer
}

func mapFileACL(vfsEntry *vfs.VFSEntry, file *File, irodsEntry *irodsapi.IRODSEntry) os.FileMode {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "mapFileACL",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Panic(r)
		}
	}()

	if irodsEntry.Owner == file.FS.Config.ClientUser {
		// mine
		if vfsEntry.ReadOnly {
			return 0o400
		}

		return 0o700
	}

	logger.Infof("Checking ACL information of the Entry for %s and user %s", irodsEntry.Path, file.FS.Config.ClientUser)
	defer logger.Infof("Checked ACL information of the Entry for %s and user %s", irodsEntry.Path, file.FS.Config.ClientUser)

	accesses, err := file.FS.IRODSClient.ListFileACLsWithGroupUsers(irodsEntry.Path)
	if err != nil {
		logger.Errorf("failed to get ACL information of the Entry for %s", irodsEntry.Path)
	}

	for _, access := range accesses {
		if access.UserName == file.FS.Config.ClientUser {
			// found
			switch access.AccessLevel {
			case irodsapi.IRODSAccessLevelOwner:
				if vfsEntry.ReadOnly {
					return 0o400
				}
				return 0o700
			case irodsapi.IRODSAccessLevelWrite:
				if vfsEntry.ReadOnly {
					return 0o400
				}
				return 0o600
			case irodsapi.IRODSAccessLevelRead:
				return 0o400
			case irodsapi.IRODSAccessLevelNone:
				return 0o000
			}
		}
	}

	logger.Errorf("failed to find ACL information of the Entry for %s and user %s", irodsEntry.Path, file.FS.Config.ClientUser)

	// others - no permission
	return 0o000
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
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	file.FS.FileMetaUpdater.Apply(file)

	file.Mutex.RLock()
	defer file.Mutex.RUnlock()

	logger.Infof("Calling Attr - %s", file.Path)
	defer logger.Infof("Called Attr - %s", file.Path)

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
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	file.FS.FileMetaUpdater.Apply(file)

	file.Mutex.RLock()
	defer file.Mutex.RUnlock()

	logger.Infof("Calling Setattr - %s", file.Path)
	defer logger.Infof("Called Setattr - %s", file.Path)

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
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	file.FS.FileMetaUpdater.Apply(file)

	file.Mutex.RLock()
	defer file.Mutex.RUnlock()

	logger.Infof("Calling Truncate - %s, %d", file.Path, req.Size)
	defer logger.Infof("Called Truncate - %s, %d", file.Path, req.Size)

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

	logger.Infof("Calling Open - %s, mode(%s)", file.Path, openMode)
	defer logger.Infof("Called Open - %s, mode(%s)", file.Path, openMode)

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

		var writer asyncwrite.Writer
		if req.Flags.IsWriteOnly() && len(file.FS.Config.PoolHost) == 0 {
			asyncWriter := asyncwrite.NewAsyncWriter(irodsPath, handle, handleMutex, file.FS.Buffer, file.FS.MonitoringReporter)
			//syncWriter := asyncwrite.NewSyncWriter(irodsPath, handle, handleMutex, file.FS.MonitoringReporter)
			writer = asyncwrite.NewBufferedWriter(irodsPath, asyncWriter)
		} else {
			writer = asyncwrite.NewSyncWriter(irodsPath, handle, handleMutex, file.FS.MonitoringReporter)
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

// Read reads file content
func (handle *FileHandle) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	if handle.FS.Terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Read",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Panic(r)
		}
	}()

	logger.Infof("Calling Read - %s, %d Offset, %d Bytes", handle.Path, req.Offset, req.Size)
	defer logger.Infof("Called Read - %s, %d Offset, %d Bytes", handle.Path, req.Offset, req.Size)

	if handle.FileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.Path)
		return syscall.EBADFD
	}

	if !handle.FileHandle.IsReadMode() {
		logger.Errorf("failed to read file opened with write mode - %s", handle.Path)
		return syscall.EBADFD
	}

	if req.Offset > handle.FileHandle.GetEntry().Size {
		resp.Data = resp.Data[:0]
		return nil
	}

	// Lock
	handle.FileHandleLock.Lock()
	defer handle.FileHandleLock.Unlock()

	data, err := handle.FileHandle.ReadAt(req.Offset, req.Size)
	if err != nil {
		logger.WithError(err).Errorf("failed to read - %s, %d", handle.Path, req.Size)
		return syscall.EREMOTEIO
	}

	copiedLen := copy(resp.Data[:req.Size], data)
	resp.Data = resp.Data[:copiedLen]

	// Report
	if handle.FS.MonitoringReporter != nil {
		handle.FS.MonitoringReporter.ReportFileTransfer(handle.IRODSFSEntry.Path, handle.FileHandle, req.Offset, int64(copiedLen))
	}

	return nil
}

// Write writes file content
func (handle *FileHandle) Write(ctx context.Context, req *fuse.WriteRequest, resp *fuse.WriteResponse) error {
	if handle.FS.Terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Write",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Panic(r)
		}
	}()

	logger.Infof("Calling Write - %s, %d Bytes", handle.Path, len(req.Data))
	defer logger.Infof("Called Write - %s, %d Bytes", handle.Path, len(req.Data))

	if handle.FileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.Path)
		return syscall.EBADFD
	}

	if !handle.FileHandle.IsWriteMode() {
		logger.Errorf("failed to write file opened with readonly mode - %s", handle.Path)
		return syscall.EBADFD
	}

	if len(req.Data) == 0 || req.Offset < 0 {
		return nil
	}

	err := handle.Writer.WriteAt(req.Offset, req.Data)
	if err != nil {
		logger.WithError(err).Errorf("failed to write data for file %s, offset %d, length %d", handle.Path, req.Offset, len(req.Data))
		return syscall.EREMOTEIO
	}

	resp.Size = len(req.Data)
	return nil
}

// Flush flushes content changes
func (handle *FileHandle) Flush(ctx context.Context, req *fuse.FlushRequest) error {
	if handle.FS.Terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Flush",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Panic(r)
		}
	}()

	logger.Infof("Calling Flush - %s", handle.Path)
	defer logger.Infof("Called Flush - %s", handle.Path)

	if handle.FileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.Path)
		return syscall.EREMOTEIO
	}

	// Flush
	err := handle.Writer.Flush()
	if err != nil {
		logger.WithError(err).Errorf("failed to flush - %s", handle.Path)
		return syscall.EREMOTEIO
	}

	return nil
}

// Release closes file handle
func (handle *FileHandle) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	if handle.FS.Terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Release",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Panic(r)
		}
	}()

	logger.Infof("Calling Release - %s", handle.Path)
	defer logger.Infof("Called Release - %s", handle.Path)

	if handle.FileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.Path)
		return syscall.EREMOTEIO
	}

	// Flush
	if handle.Writer != nil {
		// wait until all queued tasks complete
		handle.Writer.Release()

		err := handle.Writer.GetPendingError()
		if err != nil {
			logger.WithError(err).Errorf("got a write failure - %s, %v", handle.Path, err)
			return syscall.EREMOTEIO
		}
	}

	handle.FileHandleLock.Lock()
	defer handle.FileHandleLock.Unlock()

	err := handle.FileHandle.Close()
	if err != nil {
		logger.Errorf("failed to close - %s", handle.Path)
		return syscall.EREMOTEIO
	}

	// Report
	err = handle.FS.MonitoringReporter.ReportFileTransferDone(handle.IRODSFSEntry.Path, handle.FileHandle)
	if err != nil {
		logger.WithError(err).Error("failed to report the file transfer to monitoring service")
		return err
	}

	return nil
}
