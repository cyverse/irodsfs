package irodsfs

import (
	"context"
	"fmt"
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
	FS      *IRODSFS
	InodeID int64
	Path    string
	Entry   *VFSEntry
}

// FileHandle is a file handle
type FileHandle struct {
	FS             *IRODSFS
	Path           string
	Entry          *VFSEntry
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

	logger.Infof("Calling Attr - %s", file.Path)

	if update, ok := file.FS.Updater.Get(file.InodeID); ok {
		// update found
		logger.Infof("Update found - replace path from %s to %s", file.Path, update.Path)
		file.Path = update.Path
		file.FS.Updater.Delete(file.InodeID)
	}

	vfsEntry := file.FS.VFS.GetClosestEntry(file.Path)
	if vfsEntry == nil {
		logger.Errorf("Could not get VFS Entry for %s", file.Path)
		return syscall.EREMOTEIO
	}

	if vfsEntry.Type == VFSVirtualDirEntryType {
		logger.Errorf("Could not get file attribute from a virtual dir mapping")
		return syscall.EREMOTEIO
	} else if vfsEntry.Type == VFSIRODSEntryType {
		irodsPath, err := vfsEntry.GetIRODSPath(file.Path)
		if err != nil {
			logger.WithError(err).Errorf("GetIRODSPath error")
			return syscall.EREMOTEIO
		}

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

		file.Entry = NewVFSEntryFromIRODSFSEntry(file.Path, entry)

		attr.Inode = uint64(entry.ID)
		attr.Ctime = entry.CreateTime
		attr.Mtime = entry.ModifyTime
		attr.Atime = entry.ModifyTime
		attr.Size = uint64(entry.Size)
		if entry.Owner == file.FS.Config.ClientUser {
			// mine
			attr.Mode = 0o600
		} else {
			// others - readonly
			attr.Mode = 0o400
		}
		return nil
	} else {
		logger.Errorf("Unknown VFS Entry type : %s", vfsEntry.Type)
		return syscall.EREMOTEIO
	}

}

// Open opens file for the path and returns file handle
func (file *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fusefs.Handle, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "File.Open",
	})

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

	logger.Infof("Calling Open - %s, mode(%s)", file.Path, openMode)

	if update, ok := file.FS.Updater.Get(file.InodeID); ok {
		// update found
		logger.Infof("Update found - replace path from %s to %s", file.Path, update.Path)
		file.Path = update.Path
		file.FS.Updater.Delete(file.InodeID)
	}

	vfsEntry := file.FS.VFS.GetClosestEntry(file.Path)
	if vfsEntry == nil {
		logger.Errorf("Could not get VFS Entry for %s", file.Path)
		return nil, syscall.EREMOTEIO
	}

	if vfsEntry.Type == VFSVirtualDirEntryType {
		// cannot open directory
		err := fmt.Errorf("Cannot open mapped directory entry - %s", vfsEntry.Path)
		logger.Error(err)
		return nil, syscall.EACCES
	} else if vfsEntry.Type == VFSIRODSEntryType {
		irodsPath, err := vfsEntry.GetIRODSPath(file.Path)
		if err != nil {
			logger.WithError(err).Errorf("GetIRODSPath error")
			return nil, syscall.EREMOTEIO
		}

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
			Entry:        file.Entry,
			IRODSFSEntry: file.Entry.IRODSEntry,
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
	} else {
		logger.Errorf("Unknown VFS Entry type : %s", vfsEntry.Type)
		return nil, syscall.EREMOTEIO
	}
}

// Read reads file content
func (handle *FileHandle) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "FileHandle.Read",
	})

	logger.Infof("Calling Read - %s, %d Offset, %d Bytes", handle.Path, req.Offset, req.Size)

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

	logger.Infof("Calling Write - %s, %d Bytes", handle.Path, len(req.Data))
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

	logger.Infof("Calling Flush - %s", handle.Path)

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

	logger.Infof("Calling Release - %s", handle.Path)
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
