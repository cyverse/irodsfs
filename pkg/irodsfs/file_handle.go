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
	FS             *IRODSFS
	Path           string
	Entry          *vfs.VFSEntry
	IRODSFSEntry   *irodsapi.IRODSEntry
	FileHandle     irodsapi.IRODSFileHandle
	FileHandleLock *sync.Mutex

	Writer io.Writer
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
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
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
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
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

	if handle.Writer == nil {
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
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	logger.Infof("Calling Flush - %s", handle.Path)
	defer logger.Infof("Called Flush - %s", handle.Path)

	if handle.FileHandle == nil {
		logger.Errorf("failed to get a file handle - %s", handle.Path)
		return syscall.EREMOTEIO
	}

	if handle.Writer != nil {
		// Flush
		err := handle.Writer.Flush()
		if err != nil {
			logger.WithError(err).Errorf("failed to flush - %s", handle.Path)
			return syscall.EREMOTEIO
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
		"struct":   "FileHandle",
		"function": "Release",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
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
