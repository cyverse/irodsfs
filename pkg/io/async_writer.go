package io

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/cyverse/irodsfs/pkg/irodsapi"
	"github.com/cyverse/irodsfs/pkg/report"
	"github.com/eapache/channels"
	log "github.com/sirupsen/logrus"
)

// AsyncWriter helps async write
type AsyncWriter struct {
	Path            string
	IRODSFileHandle irodsapi.IRODSFileHandle
	FileHandleLock  *sync.Mutex

	Buffer               Buffer
	BufferEntryGroupName string

	WriteWaitTasks sync.WaitGroup
	WriteQueue     channels.Channel

	PendingErrors []error
	Mutex         sync.Mutex // for WriteIOErrors

	MonitoringReporter *report.MonitoringReporter
}

// NewAsyncWriter create a new AsyncWriter
func NewAsyncWriter(path string, fileHandle irodsapi.IRODSFileHandle, fileHandleLock *sync.Mutex, writeBuffer Buffer, monitoringReporter *report.MonitoringReporter) *AsyncWriter {
	asyncWriter := &AsyncWriter{
		Path:            path,
		IRODSFileHandle: fileHandle,
		FileHandleLock:  fileHandleLock,

		Buffer:               writeBuffer,
		BufferEntryGroupName: fmt.Sprintf("write:%s", path),

		WriteWaitTasks: sync.WaitGroup{},
		WriteQueue:     channels.NewInfiniteChannel(),
		PendingErrors:  []error{},

		MonitoringReporter: monitoringReporter,
	}

	writeBuffer.CreateEntryGroup(asyncWriter.BufferEntryGroupName)

	go asyncWriter.backgroundWriteTask()

	return asyncWriter
}

// Release releases all resources
func (writer *AsyncWriter) Release() {
	logger := log.WithFields(log.Fields{
		"package":  "io",
		"struct":   "AsyncWriter",
		"function": "Release",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Panic(r)
		}
	}()

	writer.Flush()

	if writer.Buffer != nil {
		writer.Buffer.DeleteEntryGroup(writer.BufferEntryGroupName)
	}

	writer.WriteQueue.Close()
}

func (writer *AsyncWriter) getBufferEntryGroup() BufferEntryGroup {
	return writer.Buffer.GetEntryGroup(writer.BufferEntryGroupName)
}

func (writer *AsyncWriter) getBufferEntryKey(offset int64) string {
	return fmt.Sprintf("%d", offset)
}

func (writer *AsyncWriter) getBufferEntryOffset(key string) (int64, error) {
	return strconv.ParseInt(key, 10, 64)
}

// Write writes data
func (writer *AsyncWriter) WriteAt(offset int64, data []byte) error {
	logger := log.WithFields(log.Fields{
		"package":  "io",
		"struct":   "AsyncWriter",
		"function": "WriteAt",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Panic(r)
		}
	}()

	if len(data) == 0 || offset < 0 {
		return nil
	}

	entryKey := writer.getBufferEntryKey(offset)
	entryGroup := writer.getBufferEntryGroup()

	_, err := entryGroup.CreateEntry(entryKey, data)
	if err != nil {
		logger.WithError(err).Errorf("failed to put an entry to buffer - %s, %s", writer.BufferEntryGroupName, entryKey)
		return err
	}

	// schedule background write
	writer.WriteWaitTasks.Add(1)
	writer.WriteQueue.In() <- entryKey

	// any pending
	err = writer.GetPendingError()
	if err != nil {
		logger.WithError(err).Errorf("failed to write - %s, %v", writer.BufferEntryGroupName, err)
		return err
	}

	return nil
}

func (writer *AsyncWriter) Flush() error {
	logger := log.WithFields(log.Fields{
		"package":  "io",
		"struct":   "AsyncWriter",
		"function": "Flush",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Panic(r)
		}
	}()

	// wait until all queued tasks complete
	writer.waitForBackgroundWrites()

	// any pending
	err := writer.GetPendingError()
	if err != nil {
		logger.WithError(err).Errorf("failed to write - %s, %v", writer.BufferEntryGroupName, err)
		return err
	}

	writer.FileHandleLock.Lock()
	defer writer.FileHandleLock.Unlock()

	return writer.IRODSFileHandle.Flush()

}

func (writer *AsyncWriter) GetPendingError() error {
	writer.Mutex.Lock()
	defer writer.Mutex.Unlock()

	if len(writer.PendingErrors) > 0 {
		return writer.PendingErrors[0]
	}
	return nil
}

func (writer *AsyncWriter) addAsyncError(err error) {
	writer.Mutex.Lock()
	defer writer.Mutex.Unlock()

	writer.PendingErrors = append(writer.PendingErrors, err)
}

func (writer *AsyncWriter) waitForBackgroundWrites() {
	writer.WriteWaitTasks.Wait()
}

func (writer *AsyncWriter) backgroundWriteTask() {
	logger := log.WithFields(log.Fields{
		"package":  "io",
		"struct":   "AsyncWriter",
		"function": "backgroundWriteTask",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Panic(r)
		}
	}()

	entryGroup := writer.getBufferEntryGroup()

	for {
		outData, channelOpened := <-writer.WriteQueue.Out()
		if !channelOpened {
			// channel is closed
			return
		}

		if outData != nil {
			key := outData.(string)

			offset, err := writer.getBufferEntryOffset(key)
			if err != nil {
				logger.WithError(err).Errorf("failed to get entry offset - %s, %s", writer.BufferEntryGroupName, key)
				writer.addAsyncError(err)
				continue
			}

			entry := entryGroup.PopEntry(key)
			if entry == nil {
				err = fmt.Errorf("failed to get an entry - %s, %s", writer.BufferEntryGroupName, key)
				logger.Error(err)
				writer.addAsyncError(err)
				continue
			}

			data := entry.GetData()
			if len(data) != entry.GetSize() && len(data) <= 0 {
				err = fmt.Errorf("failed to get data - %s, %s", writer.BufferEntryGroupName, key)
				logger.Error(err)
				writer.addAsyncError(err)
				continue
			}

			logger.Infof("Async Writing - %s, Offset %d, length %d", writer.Path, offset, len(data))
			writer.FileHandleLock.Lock()

			err = writer.IRODSFileHandle.WriteAt(offset, data)
			if err != nil {
				writer.FileHandleLock.Unlock()
				logger.WithError(err).Errorf("failed to write data - %s, %d, %d", writer.Path, offset, len(data))
				writer.addAsyncError(err)
				continue
			}

			writer.FileHandleLock.Unlock()

			// Report
			if writer.MonitoringReporter != nil {
				writer.MonitoringReporter.ReportFileTransfer(writer.Path, writer.IRODSFileHandle, offset, int64(len(data)))
			}

			writer.WriteWaitTasks.Done()
		}
	}
}
