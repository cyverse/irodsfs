package asyncwrite

import (
	"crypto/sha1"
	"encoding/hex"
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
	writer.Flush()
}

// Write writes data
func (writer *SyncWriter) WriteAt(offset int64, data []byte) error {
	logger := log.WithFields(log.Fields{
		"package":  "syncwrite",
		"struct":   "SyncWriter",
		"function": "WriteAt",
	})

	if len(data) == 0 || offset < 0 {
		return nil
	}

	hash := sha1.New()
	hash.Write(data)
	hashString := hex.EncodeToString(hash.Sum(nil))

	logger.Infof("Sync Writing - %s, Offset %d, length %d, hash %s", writer.Path, offset, len(data), hashString)

	writer.FileHandleLock.Lock()

	err := writer.IRODSFileHandle.WriteAt(offset, data)
	if err != nil {
		writer.FileHandleLock.Unlock()
		logger.WithError(err).Errorf("failed to write data - %s, %d, %d", writer.Path, offset, len(data))
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
	return nil
}

func (writer *SyncWriter) GetPendingError() error {
	return nil
}
