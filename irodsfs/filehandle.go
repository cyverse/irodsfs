package irodsfs

import (
	"context"
	"sync"
	"syscall"

	fuse "bazil.org/fuse"
	irodsfscommon_io "github.com/cyverse/irodsfs-common/io"
	irodsfscommon_irods "github.com/cyverse/irodsfs-common/irods"
	irodsfscommon_utils "github.com/cyverse/irodsfs-common/utils"

	log "github.com/sirupsen/logrus"
)

const (
	writeBlockSize int = 1024 * 1024 * 8 // 8MB
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
	openMode := fileHandle.GetOpenMode()

	var writer irodsfscommon_io.Writer
	var reader irodsfscommon_io.Reader

	if openMode.IsReadOnly() {
		// writer
		writer = irodsfscommon_io.NewNilWriter(fileHandle)
		// reader
		reader = irodsfscommon_io.NewSyncReader(fileHandle, file.fs.instanceReportClient)
	} else if openMode.IsWriteOnly() {
		// write only
		reader = irodsfscommon_io.NewNilReader(fileHandle)

		if len(file.fs.config.PoolHost) == 0 {
			if file.fs.buffer != nil {
				// if there's no pool server configured, use async-buffered write
				asyncWriter := irodsfscommon_io.NewAsyncWriter(fileHandle, file.fs.buffer, file.fs.instanceReportClient)
				writer = irodsfscommon_io.NewBufferedWriter(asyncWriter)
			} else {
				syncWriter := irodsfscommon_io.NewSyncWriter(fileHandle, file.fs.instanceReportClient)
				writer = irodsfscommon_io.NewBufferedWriter(syncWriter)
			}
		} else {
			// if there's pool server configured, use sync-buffered write
			syncWriter := irodsfscommon_io.NewSyncWriter(fileHandle, file.fs.instanceReportClient)
			writer = irodsfscommon_io.NewBufferedWriter(syncWriter)
		}
	} else {
		writer = irodsfscommon_io.NewSyncWriter(fileHandle, file.fs.instanceReportClient)
		reader = irodsfscommon_io.NewSyncReader(fileHandle, file.fs.instanceReportClient)
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

// Read reads file content
func (handle *FileHandle) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	if handle.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Read",
	})

	defer irodsfscommon_utils.StackTraceFromPanic(logger)

	logger.Infof("Calling Read - %s, %d Offset, %d Bytes", handle.file.path, req.Offset, req.Size)
	defer logger.Infof("Called Read - %s, %d Offset, %d Bytes", handle.file.path, req.Offset, req.Size)

	if handle.fileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.file.path)
		return syscall.EBADFD
	}

	if !handle.fileHandle.IsReadMode() {
		logger.Errorf("failed to read file opened with writeonly mode - %s", handle.file.path)
		return syscall.EBADFD
	}

	if handle.reader == nil {
		logger.Errorf("failed read file from nil reader - %s", handle.file.path)
		return syscall.EBADFD
	}

	if req.Offset > handle.fileHandle.GetEntry().Size {
		resp.Data = resp.Data[:0]
		return nil
	}

	readLen, err := handle.reader.ReadAt(resp.Data[:req.Size], req.Offset)
	if err != nil {
		logger.WithError(err).Errorf("failed to read data for file %s, offset %d, length %d", handle.file.path, req.Offset, req.Size)
		return syscall.EREMOTEIO
	}

	resp.Data = resp.Data[:readLen]
	return nil
}

// Write writes file content
func (handle *FileHandle) Write(ctx context.Context, req *fuse.WriteRequest, resp *fuse.WriteResponse) error {
	if handle.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Write",
	})

	defer irodsfscommon_utils.StackTraceFromPanic(logger)

	logger.Infof("Calling Write - %s, %d Bytes", handle.file.path, len(req.Data))
	defer logger.Infof("Called Write - %s, %d Bytes", handle.file.path, len(req.Data))

	if handle.fileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.file.path)
		return syscall.EBADFD
	}

	if !handle.fileHandle.IsWriteMode() {
		logger.Errorf("failed to write file opened with readonly mode - %s", handle.file.path)
		return syscall.EBADFD
	}

	if handle.writer == nil {
		logger.Errorf("failed to write file opened with readonly mode - %s", handle.file.path)
		return syscall.EBADFD
	}

	if len(req.Data) == 0 || req.Offset < 0 {
		return nil
	}

	writeLen, err := handle.writer.WriteAt(req.Data, req.Offset)
	if err != nil {
		logger.WithError(err).Errorf("failed to write data for file %s, offset %d, length %d", handle.file.path, req.Offset, len(req.Data))
		return syscall.EREMOTEIO
	}

	resp.Size = writeLen
	return nil
}

// Flush flushes content changes
func (handle *FileHandle) Flush(ctx context.Context, req *fuse.FlushRequest) error {
	if handle.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Flush",
	})

	defer irodsfscommon_utils.StackTraceFromPanic(logger)

	logger.Infof("Calling Flush - %s", handle.file.path)
	defer logger.Infof("Called Flush - %s", handle.file.path)

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

	return nil
}

// Release closes file handle
func (handle *FileHandle) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	if handle.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandle",
		"function": "Release",
	})

	defer irodsfscommon_utils.StackTraceFromPanic(logger)

	logger.Infof("Calling Release - %s", handle.file.path)
	defer logger.Infof("Called Release - %s", handle.file.path)

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

	// Lock
	handle.mutex.Lock()
	defer handle.mutex.Unlock()

	err := handle.fileHandle.Close()
	if err != nil {
		logger.Errorf("failed to close - %s", handle.file.path)
		return syscall.EREMOTEIO
	}

	// remove the handle from file handle map
	handle.fs.fileHandleMap.Remove(handle.fileHandle.GetID())

	// Report
	err = handle.fs.instanceReportClient.DoneFileAccess(handle.fileHandle)
	if err != nil {
		logger.WithError(err).Error("failed to report the file transfer to monitoring service")
		return err
	}

	return nil
}
