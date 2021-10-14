package io

import (
	"runtime/debug"
	"sync"

	"github.com/cyverse/irodsfs/pkg/irodsapi"
	"github.com/cyverse/irodsfs/pkg/report"
	log "github.com/sirupsen/logrus"
)

// SyncWriter helps sync write
type SyncWriter struct {
	Path            string
	IRODSFileHandle irodsapi.IRODSFileHandle
	FileHandleLock  *sync.Mutex

	MonitoringReporter *report.MonitoringReporter
}

// NewSyncWriter create a new SyncWriter
func NewSyncWriter(path string, fileHandle irodsapi.IRODSFileHandle, fileHandleLock *sync.Mutex, monitoringReporter *report.MonitoringReporter) *SyncWriter {
	syncWriter := &SyncWriter{
		Path:            path,
		IRODSFileHandle: fileHandle,
		FileHandleLock:  fileHandleLock,

		MonitoringReporter: monitoringReporter,
	}

	return syncWriter
}

// Release releases all resources
func (writer *SyncWriter) Release() {
	logger := log.WithFields(log.Fields{
		"package":  "io",
		"struct":   "SyncWriter",
		"function": "Release",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	writer.Flush()
}

// WriteAt writes data
func (writer *SyncWriter) WriteAt(offset int64, data []byte) error {
	logger := log.WithFields(log.Fields{
		"package":  "io",
		"struct":   "SyncWriter",
		"function": "WriteAt",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	if len(data) == 0 || offset < 0 {
		return nil
	}

	logger.Infof("Sync Writing - %s, offset %d, length %d", writer.Path, offset, len(data))

	writer.FileHandleLock.Lock()

	err := writer.IRODSFileHandle.WriteAt(offset, data)
	if err != nil {
		writer.FileHandleLock.Unlock()
		logger.WithError(err).Errorf("failed to write data - %s, offset %d, length %d", writer.Path, offset, len(data))
		return err
	}

	writer.FileHandleLock.Unlock()

	// Report
	if writer.MonitoringReporter != nil {
		writer.MonitoringReporter.ReportFileTransfer(writer.Path, writer.IRODSFileHandle, offset, int64(len(data)))
	}

	return nil
}

func (writer *SyncWriter) Flush() error {
	logger := log.WithFields(log.Fields{
		"package":  "io",
		"struct":   "SyncWriter",
		"function": "Flush",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	writer.FileHandleLock.Lock()
	defer writer.FileHandleLock.Unlock()

	return writer.IRODSFileHandle.Flush()
}

func (writer *SyncWriter) GetPendingError() error {
	return nil
}
