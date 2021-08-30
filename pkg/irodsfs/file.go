package irodsfs

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"

	"bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	irodsfs_clienttype "github.com/cyverse/go-irodsclient/irods/types"
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
}

// FileHandle is a file handle
type FileHandle struct {
	FS             *IRODSFS
	Path           string
	Entry          *vfs.VFSEntry
	IRODSFSEntry   *irodsfs_client.Entry
	FileHandle     *irodsfs_client.FileHandle
	FileHandleLock *sync.Mutex

	WriteBuffer            bytes.Buffer
	WriteBufferStartOffset int64
	AsyncWrite             *AsyncWrite
}

func mapFileACL(vfsEntry *vfs.VFSEntry, file *File, fsEntry *irodsfs_client.Entry) os.FileMode {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "mapFileACL",
	})

	if fsEntry.Owner == file.FS.Config.ClientUser {
		// mine
		if vfsEntry.ReadOnly {
			return 0o400
		}

		return 0o700
	}

	logger.Infof("Checking ACL information of the Entry for %s and user %s", fsEntry.Path, file.FS.Config.ClientUser)

	accesses, err := file.FS.IRODSClient.ListFileACLsWithGroupUsers(fsEntry.Path)
	if err != nil {
		logger.Errorf("failed to get ACL information of the Entry for %s", fsEntry.Path)
	}

	for _, access := range accesses {
		if access.UserName == file.FS.Config.ClientUser {
			// found
			switch access.AccessLevel {
			case irodsfs_clienttype.IRODSAccessLevelOwner:
				if vfsEntry.ReadOnly {
					return 0o400
				}
				return 0o700
			case irodsfs_clienttype.IRODSAccessLevelWrite:
				if vfsEntry.ReadOnly {
					return 0o400
				}
				return 0o600
			case irodsfs_clienttype.IRODSAccessLevelRead:
				return 0o400
			case irodsfs_clienttype.IRODSAccessLevelNone:
				return 0o000
			}
		}
	}

	logger.Errorf("failed to find ACL information of the Entry for %s and user %s", fsEntry.Path, file.FS.Config.ClientUser)

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
		"function": "File.Attr",
	})

	logger.Infof("Calling Attr - %s", file.Path)

	if update, ok := file.FS.FileMetaUpdater.Pop(file.InodeID); ok {
		// update found
		logger.Infof("Update found - replace path from %s to %s", file.Path, update.Path)
		file.Path = update.Path
	}

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
		entry, err := file.FS.IRODSClient.Stat(irodsPath)
		if err != nil {
			if irodsfs_clienttype.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return syscall.EREMOTEIO
		}

		file.Entry = vfs.NewVFSEntryFromIRODSFSEntry(file.Path, entry, vfsEntry.ReadOnly)

		attr.Inode = uint64(entry.ID)
		attr.Uid = file.FS.UID
		attr.Gid = file.FS.GID
		attr.Ctime = entry.CreateTime
		attr.Mtime = entry.ModifyTime
		attr.Atime = entry.ModifyTime
		attr.Size = uint64(entry.Size)
		attr.Mode = mapFileACL(vfsEntry, file, entry)
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
		"function": "File.Setattr",
	})

	logger.Infof("Calling Setattr - %s", file.Path)

	if update, ok := file.FS.FileMetaUpdater.Pop(file.InodeID); ok {
		// update found
		logger.Infof("Update found - replace path from %s to %s", file.Path, update.Path)
		file.Path = update.Path
	}

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
		"function": "File.Truncate",
	})

	logger.Infof("Calling Truncate - %s, %d", file.Path, req.Size)

	if update, ok := file.FS.FileMetaUpdater.Pop(file.InodeID); ok {
		// update found
		logger.Infof("Update found - replace path from %s to %s", file.Path, update.Path)
		file.Path = update.Path
	}

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
			if irodsfs_clienttype.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return syscall.EREMOTEIO
		}

		err = file.FS.IRODSClient.TruncateFile(irodsPath, int64(req.Size))
		if err != nil {
			if irodsfs_clienttype.IsFileNotFoundError(err) {
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
		"function": "File.Open",
	})

	openMode := string(irodsfs_clienttype.FileOpenModeReadOnly)

	if req.Flags.IsReadOnly() {
		openMode = string(irodsfs_clienttype.FileOpenModeReadOnly)
		resp.Flags |= fuse.OpenKeepCache
		resp.Flags &^= fuse.OpenDirectIO // disable
	} else if req.Flags.IsWriteOnly() {
		openMode = string(irodsfs_clienttype.FileOpenModeWriteOnly)

		if req.Flags&fuse.OpenAppend == fuse.OpenAppend {
			// append
			openMode = string(irodsfs_clienttype.FileOpenModeAppend)
		} else if req.Flags&fuse.OpenTruncate == fuse.OpenTruncate {
			// truncate
			openMode = string(irodsfs_clienttype.FileOpenModeWriteTruncate)
		}
		resp.Flags |= fuse.OpenDirectIO
	} else if req.Flags.IsReadWrite() {
		openMode = string(irodsfs_clienttype.FileOpenModeReadWrite)
	} else {
		logger.Errorf("unknown file open mode - %s", req.Flags.String())
		return nil, syscall.EACCES
	}

	logger.Infof("Calling Open - %s, mode(%s)", file.Path, openMode)

	if update, ok := file.FS.FileMetaUpdater.Pop(file.InodeID); ok {
		// update found
		logger.Infof("Update found - replace path from %s to %s", file.Path, update.Path)
		file.Path = update.Path
	}

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
		if vfsEntry.ReadOnly && openMode != string(irodsfs_clienttype.FileOpenModeReadOnly) {
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
			if irodsfs_clienttype.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return nil, syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to open a file - %s", irodsPath)
			return nil, syscall.EREMOTEIO
		}

		logger.Infof("Conn %p, File Descriptor %d", handle.Connection, handle.IRODSHandle.FileDescriptor)

		handleMutex := &sync.Mutex{}

		if file.FS.MonitoringReporter != nil {
			file.FS.MonitoringReporter.ReportNewFileTransferStart(file.Entry.IRODSEntry.Path, handle, file.Entry.IRODSEntry.Size)
		}

		var asyncWrite *AsyncWrite
		if req.Flags.IsWriteOnly() {
			asyncWrite, err = NewAsyncWrite(file.FS, handle, handleMutex)
			if err != nil {
				logger.WithError(err).Errorf("failed to create a new async write - %s", irodsPath)
				return nil, syscall.EREMOTEIO
			}
		}

		fileHandle := &FileHandle{
			FS:             file.FS,
			Path:           file.Path,
			Entry:          file.Entry,
			IRODSFSEntry:   file.Entry.IRODSEntry,
			FileHandle:     handle,
			FileHandleLock: handleMutex,

			WriteBuffer:            bytes.Buffer{},
			WriteBufferStartOffset: 0,
			AsyncWrite:             asyncWrite,
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
		"function": "FileHandle.Read",
	})

	logger.Infof("Calling Read - %s, %d Offset, %d Bytes", handle.Path, req.Offset, req.Size)

	if handle.FileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.Path)
		return syscall.EBADFD
	}

	if !irodsfs_clienttype.IsFileOpenFlagRead(handle.FileHandle.OpenMode) {
		logger.Errorf("failed to read file opened with write mode - %s", handle.Path)
		return syscall.EBADFD
	}

	if req.Offset > handle.FileHandle.Entry.Size {
		resp.Data = resp.Data[:0]
		return nil
	}

	// Lock
	handle.FileHandleLock.Lock()
	defer handle.FileHandleLock.Unlock()

	if handle.FileHandle.GetOffset() != req.Offset {
		_, err := handle.FileHandle.Seek(req.Offset, irodsfs_clienttype.SeekSet)
		if err != nil {
			logger.WithError(err).Errorf("failed to seek - %s, %d", handle.Path, req.Offset)
			return syscall.EREMOTEIO
		}
	}

	data, err := handle.FileHandle.Read(req.Size)
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
		"function": "FileHandle.Write",
	})

	logger.Infof("Calling Write - %s, %d Bytes", handle.Path, len(req.Data))
	logger.Infof("Conn %p, File Descriptor %d", handle.FileHandle.Connection, handle.FileHandle.IRODSHandle.FileDescriptor)

	if handle.FileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.Path)
		return syscall.EBADFD
	}

	if !irodsfs_clienttype.IsFileOpenFlagWrite(handle.FileHandle.OpenMode) {
		logger.Errorf("failed to write file opened with readonly mode - %s", handle.Path)
		return syscall.EBADFD
	}

	if len(req.Data) == 0 || req.Offset < 0 {
		return nil
	}

	handle.FileHandleLock.Lock()
	defer handle.FileHandleLock.Unlock()

	if handle.AsyncWrite != nil {
		// write async
		// check if data is continuous from prior write
		if handle.WriteBuffer.Len() > 0 {
			// has data
			if handle.WriteBufferStartOffset+int64(handle.WriteBuffer.Len()) != req.Offset {
				// not continuous
				// Spill to disk cache
				err := handle.AsyncWrite.Write(handle.WriteBufferStartOffset, handle.WriteBuffer.Bytes())
				if err != nil {
					logger.WithError(err).Errorf("failed to write - %s, %d", handle.Path, handle.WriteBufferStartOffset)
					return err
				}

				handle.WriteBufferStartOffset = 0
				handle.WriteBuffer.Reset()

				// write to buffer
				_, err = handle.WriteBuffer.Write(req.Data)
				if err != nil {
					logger.WithError(err).Errorf("failed to buffer data for file %s, offset %d, length %d", handle.Path, req.Offset, len(req.Data))
					return err
				}
				handle.WriteBufferStartOffset = req.Offset
			} else {
				// continuous
				// write to buffer
				_, err := handle.WriteBuffer.Write(req.Data)
				if err != nil {
					logger.WithError(err).Errorf("failed to buffer data for file %s, offset %d, length %d", handle.Path, req.Offset, len(req.Data))
					return err
				}
			}
		} else {
			// write to buffer
			_, err := handle.WriteBuffer.Write(req.Data)
			if err != nil {
				logger.WithError(err).Errorf("failed to buffer data for file %s, offset %d, length %d", handle.Path, req.Offset, len(req.Data))
				return err
			}
			handle.WriteBufferStartOffset = req.Offset
		}

		if handle.WriteBuffer.Len() >= WriteBlockSize {
			// Spill to disk cache
			err := handle.AsyncWrite.Write(handle.WriteBufferStartOffset, handle.WriteBuffer.Bytes())
			if err != nil {
				logger.WithError(err).Errorf("failed to write - %s, %d", handle.Path, handle.WriteBufferStartOffset)
				return err
			}

			handle.WriteBufferStartOffset = 0
			handle.WriteBuffer.Reset()
		}

		resp.Size = len(req.Data)
	} else {
		// write immediately
		if handle.FileHandle.GetOffset() != req.Offset {
			_, err := handle.FileHandle.Seek(req.Offset, irodsfs_clienttype.SeekSet)
			if err != nil {
				logger.WithError(err).Errorf("failed to seek - %s, %d", handle.Path, req.Offset)
				return syscall.EREMOTEIO
			}
		}

		err := handle.FileHandle.Write(req.Data)
		if err != nil {
			logger.WithError(err).Errorf("failed to write - %s, %d", handle.Path, len(req.Data))
			return syscall.EREMOTEIO
		}

		resp.Size = len(req.Data)

		// Report
		handle.FS.MonitoringReporter.ReportFileTransfer(handle.IRODSFSEntry.Path, handle.FileHandle, req.Offset, int64(resp.Size))
	}

	return nil
}

// Flush flushes content changes
func (handle *FileHandle) Flush(ctx context.Context, req *fuse.FlushRequest) error {
	if handle.FS.Terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "FileHandle.Flush",
	})

	logger.Infof("Calling Flush - %s", handle.Path)

	if handle.FileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.Path)
		return syscall.EREMOTEIO
	}

	// Flush
	if handle.AsyncWrite != nil {
		// spill
		if handle.WriteBuffer.Len() > 0 {
			err := handle.AsyncWrite.Write(handle.WriteBufferStartOffset, handle.WriteBuffer.Bytes())
			if err != nil {
				logger.WithError(err).Errorf("failed to write - %s, %d", handle.Path, handle.WriteBufferStartOffset)
				return err
			}

			handle.WriteBufferStartOffset = 0
			handle.WriteBuffer.Reset()
		}

		// wait until all queued tasks complete
		handle.AsyncWrite.WaitBackgroundWrites()

		err := handle.AsyncWrite.GetAsyncError()
		if err != nil {
			logger.WithError(err).Errorf("got an async write failure - %s, %v", handle.Path, err)
			return err
		}
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
		"function": "FileHandle.Release",
	})

	logger.Infof("Calling Release - %s", handle.Path)
	logger.Infof("Conn %p, File Descriptor %d", handle.FileHandle.Connection, handle.FileHandle.IRODSHandle.FileDescriptor)

	if handle.FileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.Path)
		return syscall.EREMOTEIO
	}

	// Flush
	if handle.AsyncWrite != nil {
		// wait until all queued tasks complete
		handle.AsyncWrite.Release()
	}

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
