package irodsfs

import (
	"context"
	"path"
	"sync"
	"syscall"

	"bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	irodsfs_clienttype "github.com/cyverse/go-irodsclient/irods/types"
	log "github.com/sirupsen/logrus"
)

// File is a file node
type File struct {
	FS           *IRODSFS
	Path         string
	IRODSFSEntry *irodsfs_client.FSEntry
}

// FileHandle is a file handle
type FileHandle struct {
	FS             *IRODSFS
	Path           string
	IRODSFSEntry   *irodsfs_client.FSEntry
	FileHandle     *irodsfs_client.FileHandle
	FileHandleLock sync.Mutex
	BlockIO        *BlockIO
}

// Attr returns stat of directory entry
func (file *File) Attr(ctx context.Context, attr *fuse.Attr) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "File.Attr",
	})

	irodsPath := path.Join(file.FS.Config.IRODSPath, file.Path)
	logger.Infof("Calling Attr - %s", irodsPath)

	// redo to get fresh info
	entry, err := file.FS.IRODSClient.Stat(irodsPath)
	if err != nil {
		if irodsfs_clienttype.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("File not found - %s", irodsPath)
			return syscall.ENOENT
		}

		logger.WithError(err).Errorf("Stat error - %s", irodsPath)
		return syscall.EREMOTEIO
	}

	file.IRODSFSEntry = entry

	attr.Inode = uint64(file.IRODSFSEntry.ID)
	attr.Ctime = file.IRODSFSEntry.CreateTime
	attr.Mtime = file.IRODSFSEntry.ModifyTime
	attr.Atime = file.IRODSFSEntry.ModifyTime
	attr.Size = uint64(file.IRODSFSEntry.Size)

	if file.IRODSFSEntry.Owner == file.FS.Config.ClientUser {
		// mine
		attr.Mode = 0o600
	} else {
		// others - readonly
		attr.Mode = 0o400
	}
	return nil
}

// Open opens file for the path and returns file handle
func (file *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fusefs.Handle, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "File.Open",
	})

	irodsPath := path.Join(file.FS.Config.IRODSPath, file.Path)

	openMode := string(irodsfs_clienttype.FileOpenModeReadOnly)

	if req.Flags.IsReadOnly() {
		openMode = string(irodsfs_clienttype.FileOpenModeReadOnly)
		resp.Flags |= fuse.OpenKeepCache
	} else if req.Flags.IsWriteOnly() {
		openMode = string(irodsfs_clienttype.FileOpenModeWriteOnly)
	} else if req.Flags.IsReadWrite() {
		openMode = string(irodsfs_clienttype.FileOpenModeReadWrite)
	} else {
		logger.Errorf("Unknown file open mode - %s", req.Flags.String())
		return nil, syscall.EACCES
	}

	logger.Infof("Calling Open - %s, %p, mode(%s)", irodsPath, file, openMode)

	handle, err := file.FS.IRODSClient.OpenFile(irodsPath, "", openMode)
	if err != nil {
		if irodsfs_clienttype.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("File not found - %s", irodsPath)
			return nil, syscall.ENOENT
		}

		logger.WithError(err).Errorf("OpenFile error - %s", irodsPath)
		return nil, syscall.EREMOTEIO
	}

	logger.Infof("Conn %p, File Descriptor %d", handle.Connection, handle.IRODSHandle.FileDescriptor)

	fileHandle := &FileHandle{
		FS:           file.FS,
		Path:         file.Path,
		IRODSFSEntry: file.IRODSFSEntry,
		FileHandle:   handle,
		BlockIO:      nil,
	}

	if fileHandle.FS.Config.UseBlockIO {
		if req.Flags.IsReadOnly() && req.Flags.IsWriteOnly() {
			blockio, err := NewBlockIO(fileHandle.FS, handle)
			if err != nil {
				logger.WithError(err).Errorf("BlockIO error - %s", irodsPath)
				return nil, syscall.EREMOTEIO
			}

			fileHandle.BlockIO = blockio
		}
	}

	return fileHandle, nil
}

// Read reads file content
func (handle *FileHandle) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "FileHandle.Read",
	})

	irodsPath := path.Join(handle.FS.Config.IRODSPath, handle.Path)
	logger.Infof("Calling Read - %s, %d Offset, %d Bytes", irodsPath, req.Offset, req.Size)
	logger.Infof("Conn %p, File Descriptor %d", handle.FileHandle.Connection, handle.FileHandle.IRODSHandle.FileDescriptor)

	if handle.FileHandle == nil {
		logger.Errorf("File handle error - %s", handle.Path)
		return syscall.EREMOTEIO
	}

	if !irodsfs_clienttype.IsFileOpenFlagRead(handle.FileHandle.OpenMode) {
		logger.Errorf("Could not read file opened with write mode - %s", handle.Path)
		return syscall.EACCES
	}

	if req.Offset > handle.FileHandle.Entry.Size {
		resp.Data = resp.Data[:0]
		return nil
	}

	if handle.BlockIO != nil {
		data, err := handle.BlockIO.Read(req.Offset, req.Size)
		if err != nil {
			logger.WithError(err).Errorf("Read error - %s, %d", handle.Path, req.Size)
			return syscall.EREMOTEIO
		}

		copiedLen := copy(resp.Data[:req.Size], data)
		resp.Data = resp.Data[:copiedLen]
	} else {
		// Lock
		handle.FileHandleLock.Lock()
		defer handle.FileHandleLock.Unlock()

		if handle.FileHandle.GetOffset() != req.Offset {
			_, err := handle.FileHandle.Seek(req.Offset, irodsfs_clienttype.SeekSet)
			if err != nil {
				logger.WithError(err).Errorf("Seek error - %s, %d", handle.Path, req.Offset)
				return syscall.EREMOTEIO
			}
		}

		data, err := handle.FileHandle.Read(req.Size)
		if err != nil {
			logger.WithError(err).Errorf("Read error - %s, %d", handle.Path, req.Size)
			return syscall.EREMOTEIO
		}

		copiedLen := copy(resp.Data[:req.Size], data)
		resp.Data = resp.Data[:copiedLen]
	}

	return nil
}

// Write writes file content
func (handle *FileHandle) Write(ctx context.Context, req *fuse.WriteRequest, resp *fuse.WriteResponse) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "FileHandle.Write",
	})

	irodsPath := path.Join(handle.FS.Config.IRODSPath, handle.Path)
	logger.Infof("Calling Write - %s, %d Bytes", irodsPath, len(req.Data))
	logger.Infof("Conn %p, File Descriptor %d", handle.FileHandle.Connection, handle.FileHandle.IRODSHandle.FileDescriptor)

	if handle.FileHandle == nil {
		logger.Errorf("File handle error - %s", handle.Path)
		return syscall.EREMOTEIO
	}

	if !irodsfs_clienttype.IsFileOpenFlagWrite(handle.FileHandle.OpenMode) {
		logger.Errorf("Could not write file opened with readonly mode - %s", handle.Path)
		return syscall.EACCES
	}

	if handle.BlockIO != nil {
		err := handle.BlockIO.Write(req.Offset, req.Data)
		if err != nil {
			logger.WithError(err).Errorf("Write error - %s, %d", handle.Path, len(req.Data))
			return syscall.EREMOTEIO
		}

		resp.Size = len(req.Data)
	} else {
		// Lock
		handle.FileHandleLock.Lock()
		defer handle.FileHandleLock.Unlock()

		if handle.FileHandle.GetOffset() != req.Offset {
			_, err := handle.FileHandle.Seek(req.Offset, irodsfs_clienttype.SeekSet)
			if err != nil {
				logger.WithError(err).Errorf("Seek error - %s, %d", handle.Path, req.Offset)
				return syscall.EREMOTEIO
			}
		}

		err := handle.FileHandle.Write(req.Data)
		if err != nil {
			logger.WithError(err).Errorf("Write error - %s, %d", handle.Path, len(req.Data))
			return syscall.EREMOTEIO
		}

		resp.Size = len(req.Data)
	}

	return nil
}

// Flush flushes content changes
func (handle *FileHandle) Flush(ctx context.Context, req *fuse.FlushRequest) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "FileHandle.Flush",
	})

	irodsPath := path.Join(handle.FS.Config.IRODSPath, handle.Path)
	logger.Infof("Calling Flush - %s", irodsPath)

	if handle.FileHandle == nil {
		logger.Errorf("File handle error - %s", handle.Path)
		return syscall.EREMOTEIO
	}

	if irodsfs_clienttype.IsFileOpenFlagWrite(handle.FileHandle.OpenMode) {
		// Flush
		if handle.FS.Config.UseBlockIO && handle.BlockIO != nil {
			err := handle.BlockIO.Flush()
			if err != nil {
				logger.WithError(err).Errorf("Flush error - %s", handle.Path)
				return syscall.EREMOTEIO
			}
		}
	}

	return nil
}

// Release closes file handle
func (handle *FileHandle) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "FileHandle.Release",
	})

	irodsPath := path.Join(handle.FS.Config.IRODSPath, handle.Path)
	logger.Infof("Calling Release - %s", irodsPath)
	logger.Infof("Conn %p, File Descriptor %d", handle.FileHandle.Connection, handle.FileHandle.IRODSHandle.FileDescriptor)

	if handle.FileHandle == nil {
		logger.Errorf("File handle error - %s", handle.Path)
		return syscall.EREMOTEIO
	}

	if irodsfs_clienttype.IsFileOpenFlagWrite(handle.FileHandle.OpenMode) {
		// Flush
		if handle.FS.Config.UseBlockIO && handle.BlockIO != nil {
			err := handle.BlockIO.Flush()
			if err != nil {
				logger.WithError(err).Errorf("Flush error - %s", handle.Path)
				return syscall.EREMOTEIO
			}
		}
	}

	if handle.BlockIO != nil {
		handle.BlockIO.Release()
	}

	err := handle.FileHandle.Close()
	if err != nil {
		logger.Errorf("Close error - %s", handle.Path)
		return syscall.EREMOTEIO
	}

	return nil
}
