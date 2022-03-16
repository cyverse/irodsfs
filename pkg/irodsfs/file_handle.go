package irodsfs

import (
	"context"
	"runtime/debug"
	"sync"
	"syscall"

	fuse "bazil.org/fuse"
	"github.com/cyverse/irodsfs/pkg/io"
	"github.com/cyverse/irodsfs/pkg/irodsapi"
	"github.com/cyverse/irodsfs/pkg/vfs"
	log "github.com/sirupsen/logrus"
)

const (
	WriteBlockSize int = 1024 * 1024 * 8 // 8MB
)

// FileHandle is a file handle
type FileHandle struct {
	fs          *IRODSFS
	path        string
	entry       *vfs.VFSEntry
	irodsEntry  *irodsapi.IRODSEntry
	irodsHandle irodsapi.IRODSFileHandle
	mutex       *sync.Mutex
	writer      io.Writer
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

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	logger.Infof("Calling Read - %s, %d Offset, %d Bytes", handle.path, req.Offset, req.Size)
	defer logger.Infof("Called Read - %s, %d Offset, %d Bytes", handle.path, req.Offset, req.Size)

	// Lock
	handle.mutex.Lock()
	defer handle.mutex.Unlock()

	if handle.irodsHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.path)
		return syscall.EBADFD
	}

	if !handle.irodsHandle.IsReadMode() {
		logger.Errorf("failed to read file opened with write mode - %s", handle.path)
		return syscall.EBADFD
	}

	if req.Offset > handle.irodsHandle.GetEntry().Size {
		resp.Data = resp.Data[:0]
		return nil
	}

	data, err := handle.irodsHandle.ReadAt(req.Offset, req.Size)
	if err != nil {
		logger.WithError(err).Errorf("failed to read - %s, %d", handle.path, req.Size)
		return syscall.EREMOTEIO
	}

	copiedLen := copy(resp.Data[:req.Size], data)
	resp.Data = resp.Data[:copiedLen]

	// Report
	if handle.fs.monitoringReporter != nil {
		handle.fs.monitoringReporter.ReportFileTransfer(handle.irodsEntry.Path, handle.irodsHandle, req.Offset, int64(copiedLen))
	}

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

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	logger.Infof("Calling Write - %s, %d Bytes", handle.path, len(req.Data))
	defer logger.Infof("Called Write - %s, %d Bytes", handle.path, len(req.Data))

	if handle.irodsHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.path)
		return syscall.EBADFD
	}

	if !handle.irodsHandle.IsWriteMode() {
		logger.Errorf("failed to write file opened with readonly mode - %s", handle.path)
		return syscall.EBADFD
	}

	if handle.writer == nil {
		logger.Errorf("failed to write file opened with readonly mode - %s", handle.path)
		return syscall.EBADFD
	}

	if len(req.Data) == 0 || req.Offset < 0 {
		return nil
	}

	err := handle.writer.WriteAt(req.Offset, req.Data)
	if err != nil {
		logger.WithError(err).Errorf("failed to write data for file %s, offset %d, length %d", handle.path, req.Offset, len(req.Data))
		return syscall.EREMOTEIO
	}

	resp.Size = len(req.Data)
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

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	logger.Infof("Calling Flush - %s", handle.path)
	defer logger.Infof("Called Flush - %s", handle.path)

	if handle.irodsHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.path)
		return syscall.EREMOTEIO
	}

	if handle.writer != nil {
		// Flush
		err := handle.writer.Flush()
		if err != nil {
			logger.WithError(err).Errorf("failed to flush - %s", handle.path)
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

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	logger.Infof("Calling Release - %s", handle.path)
	defer logger.Infof("Called Release - %s", handle.path)

	if handle.irodsHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.path)
		return syscall.EREMOTEIO
	}

	// Flush
	if handle.writer != nil {
		// wait until all queued tasks complete
		handle.writer.Release()

		err := handle.writer.GetPendingError()
		if err != nil {
			logger.WithError(err).Errorf("got a write failure - %s, %v", handle.path, err)
			return syscall.EREMOTEIO
		}
	}

	// Lock
	handle.mutex.Lock()
	defer handle.mutex.Unlock()

	err := handle.irodsHandle.Close()
	if err != nil {
		logger.Errorf("failed to close - %s", handle.path)
		return syscall.EREMOTEIO
	}

	// remove the handle from file handle map
	handle.fs.fileHandleMap.Remove(handle.irodsHandle.GetID())

	// Report
	err = handle.fs.monitoringReporter.ReportFileTransferDone(handle.irodsEntry.Path, handle.irodsHandle)
	if err != nil {
		logger.WithError(err).Error("failed to report the file transfer to monitoring service")
		return err
	}

	return nil
}
