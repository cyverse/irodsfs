package irodsfs

import (
	"context"
	"io"
	"sync"
	"syscall"

	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	irodsfscommon_irods "github.com/cyverse/irodsfs-common/irods"
	irodsfs_common_util "github.com/cyverse/irodsfs-common/util"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
	"github.com/rs/xid"
)

// FileHandle is a file handle
type FileHandle struct {
	id       string
	fs       *IRODSFS
	file     *File
	path     string
	openMode irodsclient_types.FileOpenMode

	fileHandle           irodsfscommon_irods.IRODSFSFileHandle
	localFileLockManager *FileHandleLocalLockManager

	mutex sync.Mutex
}

func NewFileHandle(fs *IRODSFS, fileHandle irodsfscommon_irods.IRODSFSFileHandle) (*FileHandle, error) {
	openMode := fileHandle.GetOpenMode()

	handle := &FileHandle{
		id:                   xid.New().String(),
		fs:                   fs,
		path:                 fileHandle.GetEntry().Path,
		openMode:             openMode,
		fileHandle:           fileHandle,
		localFileLockManager: NewFileHandleLocalLockManager(),
	}

	return handle, nil
}

// GetID returns ID
func (handle *FileHandle) GetID() string {
	return handle.id
}

// GetPath returns path
func (handle *FileHandle) GetPath() string {
	return handle.path
}

// SetFile sets File
func (handle *FileHandle) SetFile(file *File) {
	handle.file = file
}

// Getattr returns stat of file entry
func (handle *FileHandle) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	if handle.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	operID := handle.fs.GetNextOperationID()
	handle.fs.logger.Infof("Calling Getattr (%d) - %q", operID, handle.file.path)
	defer handle.fs.logger.Infof("Called Getattr (%d) - %q", operID, handle.file.path)

	return handle.file.Getattr(ctx, handle, out)
}

// Setattr sets file attributes
func (handle *FileHandle) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if handle.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	operID := handle.fs.GetNextOperationID()
	handle.fs.logger.Infof("Calling Setattr (%d) - %q", operID, handle.file.path)
	defer handle.fs.logger.Infof("Called Setattr (%d) - %q", operID, handle.file.path)

	if size, ok := in.GetSize(); ok {
		errno := handle.Truncate(ctx, size)
		if errno != fusefs.OK {
			return errno
		}

		out.Size = size
		return fusefs.OK
	}

	return handle.file.Setattr(ctx, handle, in, out)
}

// Read reads file content
func (handle *FileHandle) Read(ctx context.Context, dest []byte, offset int64) (fuse.ReadResult, syscall.Errno) {
	if handle.fs.terminated.Load() {
		return nil, syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	size := len(dest)

	handle.fs.logger.Debugf("Calling Read - %q, %d Offset, %d Bytes", handle.file.path, offset, size)
	defer handle.fs.logger.Debugf("Called Read - %q, %d Offset, %d Bytes", handle.file.path, offset, size)

	if handle.fileHandle == nil {
		handle.fs.logger.Errorf("failed to get a file handle - %q", handle.file.path)
		return nil, syscall.EBADFD
	}

	if !handle.openMode.IsRead() {
		handle.fs.logger.Errorf("failed to read file opened with writeonly mode - %q", handle.file.path)
		return nil, syscall.EBADFD
	}

	if offset >= handle.fileHandle.GetEntry().Size {
		return fuse.ReadResultData(dest[:0]), fusefs.OK
	}

	readLen, err := handle.fileHandle.ReadAt(dest, offset)
	if err != nil && err != io.EOF {
		handle.fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}

	handle.fs.logger.Debugf("read %d bytes, eof? %t", readLen, err == io.EOF)

	return fuse.ReadResultData(dest[:readLen]), fusefs.OK
}

// Write writes file content
func (handle *FileHandle) Write(ctx context.Context, data []byte, offset int64) (uint32, syscall.Errno) {
	if handle.fs.terminated.Load() {
		return 0, syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	size := len(data)

	handle.fs.logger.Debugf("Calling Write - %q, %d Offset, %d Bytes", handle.file.path, offset, size)
	defer handle.fs.logger.Debugf("Called Write - %q, %d Offset, %d Bytes", handle.file.path, offset, size)

	if handle.fileHandle == nil {
		handle.fs.logger.Errorf("failed to get a file handle - %q", handle.file.path)
		return 0, syscall.EBADFD
	}

	if !handle.openMode.IsWrite() {
		handle.fs.logger.Errorf("failed to write file opened with readonly mode - %q", handle.file.path)
		return 0, syscall.EBADFD
	}

	if size == 0 {
		return 0, fusefs.OK
	}

	if offset < 0 {
		return 0, syscall.EBADFD
	}

	writeLen, err := handle.fileHandle.WriteAt(data, offset)
	if err != nil {
		handle.fs.logger.Error(err)
		return 0, syscall.EREMOTEIO
	}

	return uint32(writeLen), fusefs.OK
}

// Truncate truncates file content
func (handle *FileHandle) Truncate(ctx context.Context, size uint64) syscall.Errno {
	if handle.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	handle.fs.logger.Infof("Calling Truncate - %q, %d Bytes", handle.file.path, size)
	defer handle.fs.logger.Infof("Called Truncate - %q, %d Bytes", handle.file.path, size)

	if handle.fileHandle == nil {
		handle.fs.logger.Errorf("failed to get a file handle - %q", handle.file.path)
		return syscall.EBADFD
	}

	if !handle.openMode.IsWrite() {
		handle.fs.logger.Errorf("failed to truncate file opened with readonly mode - %q", handle.file.path)
		return syscall.EBADFD
	}

	err := handle.fileHandle.Truncate(int64(size))
	if err != nil {
		handle.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

func (handle *FileHandle) flush() syscall.Errno {
	handle.mutex.Lock()
	if handle.fileHandle == nil {
		handle.mutex.Unlock()
		return fusefs.OK
	}
	handle.mutex.Unlock()

	err := handle.fileHandle.Flush()
	if err != nil {
		handle.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}
	return fusefs.OK
}

// Flush flushes content changes
func (handle *FileHandle) Flush(ctx context.Context) syscall.Errno {
	if handle.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	operID := handle.fs.GetNextOperationID()
	handle.fs.logger.Debugf("Calling Flush (%d) - %q", operID, handle.file.path)
	defer handle.fs.logger.Debugf("Called Flush (%d) - %q", operID, handle.file.path)

	return handle.flush()
}

// Fsync flushes content changes
func (handle *FileHandle) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	if handle.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	operID := handle.fs.GetNextOperationID()
	handle.fs.logger.Debugf("Calling Fsync (%d) - %q", operID, handle.file.path)
	defer handle.fs.logger.Debugf("Called Fsync (%d) - %q", operID, handle.file.path)

	return handle.flush()
}

// Release closes file handle
func (handle *FileHandle) Release(ctx context.Context) syscall.Errno {
	if handle.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	handle.mutex.Lock()
	if handle.fileHandle == nil {
		handle.fs.fileHandleMap.Remove(handle.GetID())
		handle.mutex.Unlock()
		return fusefs.OK
	}
	handle.mutex.Unlock()

	handle.fs.logger.Infof("Calling Release - %q", handle.file.path)
	defer handle.fs.logger.Infof("Called Release - %q", handle.file.path)

	closeFunc := func() {
		handle.mutex.Lock()
		defer handle.mutex.Unlock()

		handle.fs.fileHandleMap.Remove(handle.GetID())

		err := handle.fileHandle.Close()
		if err != nil {
			handle.fs.logger.Error(err)
		}
	}

	if handle.openMode.IsReadOnly() {
		go closeFunc()
	} else {
		closeFunc()
	}

	return fusefs.OK
}

// Getlk returns lock
func (handle *FileHandle) Getlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	if handle.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	operID := handle.fs.GetNextOperationID()
	handle.fs.logger.Infof("Calling Getlk (%d) - %q", operID, handle.file.path)
	defer handle.fs.logger.Infof("Called Getlk (%d) - %q", operID, handle.file.path)

	return handle.GetLocalLock(ctx, owner, lk, flags, out)
}

// Setlk locks the file handle
func (handle *FileHandle) Setlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if handle.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	operID := handle.fs.GetNextOperationID()
	handle.fs.logger.Infof("Calling Setlk (%d) - %q", operID, handle.file.path)
	defer handle.fs.logger.Infof("Called Setlk (%d) - %q", operID, handle.file.path)

	return handle.SetLocalLock(ctx, owner, lk, flags)
}

// Setlkw locks the file handle and waits until it acquires the lock
func (handle *FileHandle) Setlkw(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if handle.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	operID := handle.fs.GetNextOperationID()
	handle.fs.logger.Infof("Calling Setlkw (%d) - %q", operID, handle.file.path)
	defer handle.fs.logger.Infof("Called Setlkw (%d) - %q", operID, handle.file.path)

	return handle.SetLocalLockW(ctx, owner, lk, flags)
}

// GetLocalLock returns local lock
func (handle *FileHandle) GetLocalLock(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	if handle.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	operID := handle.fs.GetNextOperationID()
	handle.fs.logger.Infof("Calling GetLocalLock (%d) - %q", operID, handle.file.path)
	defer handle.fs.logger.Infof("Called GetLocalLock (%d) - %q", operID, handle.file.path)

	handle.fs.logger.Debugf("owner %d, type %d, start %d, end %d, pid %d, flags %d", owner, lk.Typ, lk.Start, lk.End, lk.Pid, flags)

	lock := FileHandleLocalLock{
		LockType: lk.Typ,
		Pid:      lk.Pid,
		Start:    lk.Start,
		End:      lk.End,
	}

	lockFound := handle.localFileLockManager.Get(lock.Start, lock.End)
	if lockFound != nil {
		out.Start = lockFound.Start
		out.End = lockFound.End
		out.Pid = lockFound.Pid
		out.Typ = lockFound.LockType
		return fusefs.OK
	}

	out.Start = lk.Start
	out.End = lk.End
	out.Pid = lk.Pid
	out.Typ = syscall.F_UNLCK
	return fusefs.OK
}

// SetLocalLock sets local lock
func (handle *FileHandle) SetLocalLock(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if handle.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	operID := handle.fs.GetNextOperationID()
	handle.fs.logger.Infof("Calling SetLocalLock (%d) - %q", operID, handle.file.path)
	defer handle.fs.logger.Infof("Called SetLocalLock (%d) - %q", operID, handle.file.path)

	handle.fs.logger.Debugf("owner %d, type %d, start %d, end %d, pid %d, flags %d", owner, lk.Typ, lk.Start, lk.End, lk.Pid, flags)

	lock := FileHandleLocalLock{
		ID:       xid.New().String(),
		LockType: lk.Typ,
		Pid:      lk.Pid,
		Start:    lk.Start,
		End:      lk.End,
	}

	if lk.Typ == syscall.F_UNLCK {
		err := handle.localFileLockManager.Unlock(&lock)
		if err != nil {
			handle.fs.logger.Error(err)
			return syscall.ENOENT
		}
	} else {
		err := handle.localFileLockManager.Lock(&lock)
		if err != nil {
			handle.fs.logger.Error(err)
			return syscall.EAGAIN
		}
	}

	return fusefs.OK
}

// SetLocalLockW sets local lock and waits until it acquires the lock
func (handle *FileHandle) SetLocalLockW(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if handle.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(handle.fs.logger)

	handle.fs.logger.Debugf("Calling SetLocalLockW - %q", handle.file.path)
	defer handle.fs.logger.Debugf("Called SetLocalLockW - %q", handle.file.path)

	handle.fs.logger.Debugf("owner %d, type %d, start %d, end %d, pid %d, flags %d", owner, lk.Typ, lk.Start, lk.End, lk.Pid, flags)

	return syscall.ENOTSUP
}
