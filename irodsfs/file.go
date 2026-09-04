package irodsfs

import (
	"context"
	"sync"
	"syscall"

	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	"github.com/cyverse/irodsfs-common/irods/vpath"
	irodsfs_common_util "github.com/cyverse/irodsfs-common/util"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
)

// File is a file node
type File struct {
	fusefs.Inode

	fs      *IRODSFS
	inodeID uint64
	path    string
	mutex   sync.RWMutex
}

// NewFile creates a new File
func NewFile(fs *IRODSFS, inodeID uint64, path string) *File {
	return &File{
		fs:      fs,
		inodeID: inodeID,
		path:    path,
	}
}

func (file *File) getStableAttr() fusefs.StableAttr {
	return fusefs.StableAttr{
		Mode: fuse.S_IFREG,
		Ino:  file.inodeID,
	}
}

func (file *File) ensureIRODSPath(vpathEntry *vpath.VPathEntry) error {
	return ensureVPathEntryIsIRODSEntry(file.fs.fsClient, vpathEntry)
}

// Getattr returns stat of file entry
func (file *File) Getattr(ctx context.Context, fh fusefs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if file.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(file.fs.logger)

	operID := file.fs.GetNextOperationID()
	file.fs.logger.Infof("Calling Getattr (%d) - %q", operID, file.path)
	defer file.fs.logger.Infof("Called Getattr (%d) - %q", operID, file.path)

	file.mutex.RLock()
	defer file.mutex.RUnlock()

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		file.fs.logger.Errorf("failed to get VPath Entry for %q", file.path)
		return syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		file.fs.logger.Errorf("failed to get file attribute from a virtual dir mapping")
		return syscall.EREMOTEIO
	}

	// IRODS File
	err := file.ensureIRODSPath(vpathEntry)
	if err != nil {
		file.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(file.path)
	if err != nil {
		file.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	return file.fs.IRODSGetattr(ctx, irodsPath, vpathEntry.ReadOnly, out)
}

// Setattr sets file attributes
func (file *File) Setattr(ctx context.Context, fh fusefs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if file.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(file.fs.logger)

	operID := file.fs.GetNextOperationID()
	file.fs.logger.Infof("Calling Setattr (%d) - %q", operID, file.path)
	defer file.fs.logger.Infof("Called Setattr (%d) - %q", operID, file.path)

	// do not return EOPNOTSUPP as it causes client errors, like git clone
	if size, ok := in.GetSize(); ok {
		// truncate file
		errno := file.Truncate(ctx, size)
		if errno != fusefs.OK {
			return errno
		}

		out.Size = size
		return fusefs.OK
	}

	return fusefs.OK
}

// Truncate truncates file entry
func (file *File) Truncate(ctx context.Context, size uint64) syscall.Errno {
	if file.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(file.fs.logger)

	operID := file.fs.GetNextOperationID()
	file.fs.logger.Infof("Calling Truncate (%d) - %q, %d", operID, file.path, size)
	defer file.fs.logger.Infof("Called Truncate (%d) - %q, %d", operID, file.path, size)

	file.mutex.Lock()
	defer file.mutex.Unlock()

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		file.fs.logger.Errorf("failed to get VPath Entry for %q", file.path)
		return syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		file.fs.logger.Error("failed to truncate a virtual dir")
		return syscall.EISDIR
	}

	// IRODS File
	err := ensureVPathEntryIsIRODSEntry(file.fs.fsClient, vpathEntry)
	if err != nil {
		file.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(file.path)
	if err != nil {
		file.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	irodsEntry, err := file.fs.IRODSStat(ctx, irodsPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			file.fs.logger.Debugf("failed to find a file - %q", file.path)
			return syscall.ENOENT
		}

		file.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	// check if there're opened file handles
	// handle ftruncate operation
	callFtruncate := false
	handlesOpened := file.fs.fileHandleMap.ListByPath(irodsEntry.Path)
	for _, handle := range handlesOpened {
		if handle.openMode.IsWrite() {
			// is writing
			file.fs.logger.Infof("Found opened file handle %q - %q", handle.file.path, handle.GetID())

			errno := handle.Truncate(ctx, size)
			if errno != 0 {
				file.fs.logger.Errorf("failed to truncate a file - %q, %d", irodsEntry.Path, size)
				return errno
			}

			callFtruncate = true

			// avoid truncating a file multiple times
			break
		}
	}

	if !callFtruncate {
		if irodsEntry.Size != int64(size) {
			err = file.fs.fsClient.TruncateFile(irodsEntry.Path, int64(size))
			if err != nil {
				if irodsclient_types.IsFileNotFoundError(err) {
					file.fs.logger.Debugf("failed to find a file - %q", irodsEntry.Path)
					return syscall.ENOENT
				}

				file.fs.logger.Error(err)
				return syscall.EREMOTEIO
			}
		}
	}

	return fusefs.OK
}

// Open opens file for the path and returns file handle
func (file *File) Open(ctx context.Context, flags uint32) (fusefs.FileHandle, uint32, syscall.Errno) {
	if file.fs.terminated.Load() {
		return nil, 0, syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(file.fs.logger)

	fuseFlag := uint32(0)
	// if we use Direct_IO, it will disable kernel cache, read-ahead, shared mmap
	//fuseFlag |= fuse.FOPEN_DIRECT_IO

	operID := file.fs.GetNextOperationID()
	file.fs.logger.Infof("Calling Open (%d) - %q, mode %d", operID, file.path, flags)
	defer file.fs.logger.Infof("Called Open (%d) - %q, mode %d", operID, file.path, flags)

	file.mutex.RLock()
	defer file.mutex.RUnlock()

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		file.fs.logger.Errorf("failed to get VPath Entry for %q", file.path)
		return nil, 0, syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		// failed to open directory
		file.fs.logger.Errorf("failed to open mapped directory entry - %q", vpathEntry.Path)
		return nil, 0, syscall.EISDIR
	}

	if vpathEntry.ReadOnly {
		openMode := file.fs.IRODSGetOpenFlags(flags)

		if openMode != irodsclient_types.FileOpenModeReadOnly {
			file.fs.logger.Error("failed to open a read-only file with non-read-only mode")
			return nil, 0, syscall.EROFS
		}
	}

	// IRODS File
	err := file.ensureIRODSPath(vpathEntry)
	if err != nil {
		file.fs.logger.Error(err)
		return nil, 0, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(file.path)
	if err != nil {
		file.fs.logger.Error(err)
		return nil, 0, syscall.EREMOTEIO
	}

	fileHandle, errno := file.fs.IRODSOpen(ctx, file, irodsPath, flags)
	if errno != fusefs.OK {
		return nil, 0, errno
	}

	fileHandle.SetFile(file)

	// add to file handle map
	file.fs.fileHandleMap.Add(fileHandle)

	return fileHandle, fuseFlag, fusefs.OK
}

// Getlk returns locks
func (file *File) Getlk(ctx context.Context, fh fusefs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	if file.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(file.fs.logger)

	operID := file.fs.GetNextOperationID()
	file.fs.logger.Infof("Calling Getlk (%d) - %q", operID, file.path)
	defer file.fs.logger.Infof("Called Getlk (%d) - %q", operID, file.path)

	fileHandle, ok := fh.(*FileHandle)
	if !ok {
		file.fs.logger.Errorf("failed to convert fh to a file handle - %q", file.path)
		return syscall.EINVAL
	}

	return fileHandle.GetLocalLock(ctx, owner, lk, flags, out)
}

// Setlk obtains a lock on a file, or fail if the lock could not obtained
func (file *File) Setlk(ctx context.Context, fh fusefs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if file.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(file.fs.logger)

	operID := file.fs.GetNextOperationID()
	file.fs.logger.Infof("Calling Setlk (%d) - %q", operID, file.path)
	defer file.fs.logger.Infof("Called Setlk (%d) - %q", operID, file.path)

	fileHandle, ok := fh.(*FileHandle)
	if !ok {
		file.fs.logger.Errorf("failed to convert fh to a file handle - %q", file.path)
		return syscall.EINVAL
	}

	return fileHandle.SetLocalLock(ctx, owner, lk, flags)
}

// Setlkw obtains a lock on a file, waiting if necessary
func (file *File) Setlkw(ctx context.Context, fh fusefs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if file.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(file.fs.logger)

	operID := file.fs.GetNextOperationID()
	file.fs.logger.Infof("Calling Setlkw (%d) - %q", operID, file.path)
	defer file.fs.logger.Infof("Called Setlkw (%d) - %q", operID, file.path)

	fileHandle, ok := fh.(*FileHandle)
	if !ok {
		file.fs.logger.Errorf("failed to convert fh to a file handle - %q", file.path)
		return syscall.EINVAL
	}

	return fileHandle.SetLocalLockW(ctx, owner, lk, flags)
}
