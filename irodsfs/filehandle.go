package irodsfs

import (
	"context"
	"io"
	"sync"
	"syscall"

	irodsfscommon_io "github.com/cyverse/irodsfs-common/io"
	irodsfscommon_irods "github.com/cyverse/irodsfs-common/irods"
	irodsfs_common_utils "github.com/cyverse/irodsfs-common/utils"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"

	log "github.com/sirupsen/logrus"
)

const (
	iRODSWriteBufferSize int = 16 * 1024 * 1024 // 16MB
	iRODSIOBlockSize     int = 16 * 1024 * 1024 // 16MB
	iRODSReadWriteSize   int = 128 * 1024       // 128KB
)

// FileHandle is a file handle
type FileHandle struct {
	fs   *IRODSFS
	file *File

	reader     irodsfscommon_io.Reader
	writer     irodsfscommon_io.Writer
	fileHandle irodsfscommon_irods.IRODSFSFileHandle

	mutex sync.Mutex
}

func NewFileHandle(file *File, fileHandle irodsfscommon_irods.IRODSFSFileHandle) *FileHandle {
	var writer irodsfscommon_io.Writer
	var reader irodsfscommon_io.Reader

	fsClient := file.fs.fsClient

	openMode := fileHandle.GetOpenMode()
	if openMode.IsReadOnly() {
		// writer
		writer = irodsfscommon_io.NewNilWriter(fsClient, fileHandle)

		// reader
		tempRootDirPath := file.fs.config.GetTempRootDirPath()
		if len(tempRootDirPath) > 0 {
			syncReader := irodsfscommon_io.NewSyncReader(fsClient, fileHandle, file.fs.instanceReportClient)
			reader = irodsfscommon_io.NewAsyncBlockReader(syncReader, iRODSIOBlockSize, iRODSReadWriteSize, tempRootDirPath)
		} else {
			reader = irodsfscommon_io.NewSyncReader(fsClient, fileHandle, file.fs.instanceReportClient)
		}
	} else if openMode.IsWriteOnly() {
		// writer
		if len(file.fs.config.PoolEndpoint) > 0 {
			writer = irodsfscommon_io.NewSyncWriter(fsClient, fileHandle, file.fs.instanceReportClient)
		} else {
			tempRootDirPath := file.fs.config.GetTempRootDirPath()
			if len(tempRootDirPath) > 0 {
				syncWriter := irodsfscommon_io.NewSyncWriter(fsClient, fileHandle, file.fs.instanceReportClient)
				asyncWriter := irodsfscommon_io.NewAsyncWriter(syncWriter, iRODSIOBlockSize, tempRootDirPath)
				writer = irodsfscommon_io.NewSyncBufferedWriter(asyncWriter, iRODSWriteBufferSize)
			} else {
				syncWriter := irodsfscommon_io.NewSyncWriter(fsClient, fileHandle, file.fs.instanceReportClient)
				writer = irodsfscommon_io.NewSyncBufferedWriter(syncWriter, iRODSIOBlockSize)
			}
		}

		// reader
		reader = irodsfscommon_io.NewNilReader(fsClient, fileHandle)
	} else {
		writer = irodsfscommon_io.NewSyncWriter(fsClient, fileHandle, file.fs.instanceReportClient)
		reader = irodsfscommon_io.NewSyncReader(fsClient, fileHandle, file.fs.instanceReportClient)
	}

	return &FileHandle{
		fs:   file.fs,
		file: file,

		reader:     reader,
		writer:     writer,
		fileHandle: fileHandle,

		mutex: sync.Mutex{},
	}
}

// Getattr returns stat of file entry
func (handle *FileHandle) Getattr(ctx context.Context, out *fuse.AttrOut) syscall.Errno {
	if handle.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Getattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := handle.fs.GetNextOperationID()
	logger.Infof("Calling Getattr (%d) - %s", operID, handle.file.path)
	defer logger.Infof("Called Getattr (%d) - %s", operID, handle.file.path)

	return handle.file.Getattr(ctx, handle, out)
}

// Setattr sets file attributes
func (handle *FileHandle) Setattr(ctx context.Context, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if handle.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Setattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := handle.fs.GetNextOperationID()
	logger.Infof("Calling Setattr (%d) - %s", operID, handle.file.path)
	defer logger.Infof("Called Setattr (%d) - %s", operID, handle.file.path)

	if size, ok := in.GetSize(); ok {
		// truncate file
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
	if handle.fs.terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Read",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	size := len(dest)

	logger.Debugf("Calling Read - %s, %d Offset, %d Bytes", handle.file.path, offset, size)
	defer logger.Debugf("Called Read - %s, %d Offset, %d Bytes", handle.file.path, offset, size)

	if handle.fileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.file.path)
		return nil, syscall.EBADFD
	}

	if !handle.fileHandle.IsReadMode() {
		logger.Errorf("failed to read file opened with writeonly mode - %s", handle.file.path)
		return nil, syscall.EBADFD
	}

	if handle.reader == nil {
		logger.Errorf("failed read file from nil reader - %s", handle.file.path)
		return nil, syscall.EBADFD
	}

	if offset > handle.fileHandle.GetEntry().Size {
		return fuse.ReadResultData(dest[:0]), fusefs.OK
	}

	readLen, err := handle.reader.ReadAt(dest, offset)
	if err != nil && err != io.EOF {
		logger.WithError(err).Errorf("failed to read data for file %s, offset %d, length %d", handle.file.path, offset, size)
		return nil, syscall.EREMOTEIO
	}

	return fuse.ReadResultData(dest[:readLen]), fusefs.OK
}

// Write writes file content
func (handle *FileHandle) Write(ctx context.Context, data []byte, offset int64) (written uint32, errno syscall.Errno) {
	if handle.fs.terminated {
		return 0, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Write",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	size := len(data)

	logger.Debugf("Calling Write - %s, %d Offset, %d Bytes", handle.file.path, offset, size)
	defer logger.Debugf("Called Write - %s, %d Offset, %d Bytes", handle.file.path, offset, size)

	if handle.fileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.file.path)
		return 0, syscall.EBADFD
	}

	if !handle.fileHandle.IsWriteMode() {
		logger.Errorf("failed to write file opened with readonly mode - %s", handle.file.path)
		return 0, syscall.EBADFD
	}

	if handle.writer == nil {
		logger.Errorf("failed to write file opened with readonly mode - %s", handle.file.path)
		return 0, syscall.EBADFD
	}

	if size == 0 {
		return 0, fusefs.OK
	}

	if offset < 0 {
		return 0, syscall.EBADFD
	}

	writeLen, err := handle.writer.WriteAt(data, offset)
	if err != nil {
		logger.WithError(err).Errorf("failed to write data for file %s, offset %d, length %d", handle.file.path, offset, size)
		return 0, syscall.EREMOTEIO
	}

	return uint32(writeLen), fusefs.OK
}

// Truncate truncates file content
func (handle *FileHandle) Truncate(ctx context.Context, size uint64) syscall.Errno {
	if handle.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Truncate",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	logger.Infof("Calling Truncate - %s, %d Bytes", handle.file.path, size)
	defer logger.Infof("Called Truncate - %s, %d Bytes", handle.file.path, size)

	if handle.fileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.file.path)
		return syscall.EBADFD
	}

	if !handle.fileHandle.IsWriteMode() {
		logger.Errorf("failed to truncate file opened with readonly mode - %s", handle.file.path)
		return syscall.EBADFD
	}

	err := handle.fileHandle.Truncate(int64(size))
	if err != nil {
		logger.WithError(err).Errorf("failed to truncate data for file %s, size %d", handle.file.path, size)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// Flush flushes content changes
func (handle *FileHandle) Flush(ctx context.Context) syscall.Errno {
	if handle.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Flush",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	logger.Debugf("Calling Flush - %s", handle.file.path)
	defer logger.Debugf("Called Flush - %s", handle.file.path)

	if handle.fileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.file.path)
		return syscall.EREMOTEIO
	}

	if handle.writer != nil {
		// Flush
		err := handle.writer.Flush()
		if err != nil {
			logger.WithError(err).Errorf("failed to flush - %s", handle.file.path)
			return syscall.EREMOTEIO
		}
	}

	return fusefs.OK
}

// Fsync flushes content changes
func (handle *FileHandle) Fsync(ctx context.Context, flags uint32) syscall.Errno {
	if handle.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Fsync",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	logger.Debugf("Calling Fsync - %s", handle.file.path)
	defer logger.Debugf("Called Fsync - %s", handle.file.path)

	return fusefs.OK
}

// Release closes file handle
func (handle *FileHandle) Release(ctx context.Context) syscall.Errno {
	if handle.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Release",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	logger.Debugf("Calling Release - %s", handle.file.path)
	defer logger.Debugf("Called Release - %s", handle.file.path)

	if handle.fileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.file.path)
		return syscall.EREMOTEIO
	}

	if handle.reader != nil {
		handle.reader.Release()
		err := handle.reader.GetPendingError()
		if err != nil {
			logger.WithError(err).Errorf("got a read failure - %s, %v", handle.file.path, err)
			return syscall.EREMOTEIO
		}
		handle.reader = nil
	}

	// Flush
	if handle.writer != nil {
		// wait until all queued tasks complete
		handle.writer.Release()

		err := handle.writer.GetPendingError()
		if err != nil {
			logger.WithError(err).Errorf("got a write failure - %s, %v", handle.file.path, err)
			return syscall.EREMOTEIO
		}
		handle.writer = nil
	}

	closeFunc := func() {
		//return
		// Lock
		handle.mutex.Lock()
		defer handle.mutex.Unlock()

		err := handle.fileHandle.Close()
		if err != nil {
			logger.Errorf("failed to close - %s", handle.file.path)
			//return syscall.EREMOTEIO
			return
		}

		// remove the handle from file handle map
		handle.fs.fileHandleMap.Remove(handle.fileHandle.GetID())

		// Report
		if handle.fs.instanceReportClient != nil {
			err = handle.fs.instanceReportClient.DoneFileAccess(handle.fileHandle)
			if err != nil {
				logger.WithError(err).Error("failed to report the file transfer to monitoring service")
				return
				//return err
			}
		}
	}

	openMode := handle.fileHandle.GetOpenMode()
	if openMode.IsReadOnly() {
		// close it asynchronously
		go closeFunc()
	} else {
		closeFunc()
	}

	return fusefs.OK
}

/*
func (handle *FileHandle) Getlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
}

func (handle *FileHandle) Setlk(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
}

func (handle *FileHandle) Setlkw(ctx context.Context, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
}

func (handle *FileHandle) Lseek(ctx context.Context, off uint64, whence uint32) (uint64, syscall.Errno) {
}

func (handle *FileHandle) Allocate(ctx context.Context, off uint64, size uint64, mode uint32) syscall.Errno {
}
*/
