package io

import (
	"sync"

	"github.com/cyverse/irodsfs/pkg/irodsapi"
	"github.com/cyverse/irodsfs/pkg/report"
	log "github.com/sirupsen/logrus"
)

// SyncReader helps sync read
type SyncReader struct {
	path            string
	fileHandle      irodsapi.IRODSFileHandle
	fileHandleMutex *sync.Mutex

	monitoringReporter *report.MonitoringReporter
}

// NewSyncReader create a new SyncReader
func NewSyncReader(path string, fileHandle irodsapi.IRODSFileHandle, fileHandleMutex *sync.Mutex, monitoringReporter *report.MonitoringReporter) *SyncReader {
	syncReader := &SyncReader{
		path:            path,
		fileHandle:      fileHandle,
		fileHandleMutex: fileHandleMutex,

		monitoringReporter: monitoringReporter,
	}

	return syncReader
}

// Release releases all resources
func (reader *SyncReader) Release() {
}

// ReadAt reads data
func (reader *SyncReader) ReadAt(offset int64, length int) ([]byte, error) {
	logger := log.WithFields(log.Fields{
		"package":  "io",
		"struct":   "SyncReader",
		"function": "ReadAt",
	})

	if length <= 0 || offset < 0 {
		return []byte{}, nil
	}

	logger.Infof("Sync Reading - %s, offset %d, length %d", reader.path, offset, length)

	reader.fileHandleMutex.Lock()

	data, err := reader.fileHandle.ReadAt(offset, length)
	if err != nil {
		reader.fileHandleMutex.Unlock()
		logger.WithError(err).Errorf("failed to read data - %s, offset %d, length %d", reader.path, offset, length)
		return nil, err
	}

	reader.fileHandleMutex.Unlock()

	// Report
	if reader.monitoringReporter != nil {
		reader.monitoringReporter.ReportFileTransfer(reader.path, reader.fileHandle, offset, int64(length))
	}

	return data, nil
}

func (reader *SyncReader) GetPendingError() error {
	return nil
}
