package io

import (
	"fmt"
	"runtime/debug"
	"strconv"
	"sync"

	"github.com/cyverse/irodsfs/pkg/irodsapi"
	"github.com/cyverse/irodsfs/pkg/report"
	"github.com/eapache/channels"
	log "github.com/sirupsen/logrus"
)

// AsyncWriter helps async write
type AsyncWriter struct {
	path            string
	fileHandle      irodsapi.IRODSFileHandle
	fileHandleMutex *sync.Mutex

	buffer               Buffer
	bufferEntryGroupName string

	writeWaitTasks sync.WaitGroup
	writeQueue     channels.Channel

	pendingErrors      []error
	pendingErrorsMutex sync.Mutex

	monitoringReporter *report.MonitoringReporter
}

// NewAsyncWriter create a new AsyncWriter
func NewAsyncWriter(path string, fileHandle irodsapi.IRODSFileHandle, fileHandleLock *sync.Mutex, writeBuffer Buffer, monitoringReporter *report.MonitoringReporter) *AsyncWriter {
	asyncWriter := &AsyncWriter{
		path:            path,
		fileHandle:      fileHandle,
		fileHandleMutex: fileHandleLock,

		buffer:               writeBuffer,
		bufferEntryGroupName: fmt.Sprintf("write:%s", path),

		writeWaitTasks: sync.WaitGroup{},
		writeQueue:     channels.NewInfiniteChannel(),
		pendingErrors:  []error{},

		monitoringReporter: monitoringReporter,
	}

	writeBuffer.CreateEntryGroup(asyncWriter.bufferEntryGroupName)

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
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	writer.Flush()

	if writer.buffer != nil {
		writer.buffer.DeleteEntryGroup(writer.bufferEntryGroupName)
	}

	writer.writeQueue.Close()
}

func (writer *AsyncWriter) getBufferEntryGroup() BufferEntryGroup {
	return writer.buffer.GetEntryGroup(writer.bufferEntryGroupName)
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
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
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
		logger.WithError(err).Errorf("failed to put an entry to buffer - %s, %s", writer.bufferEntryGroupName, entryKey)
		return err
	}

	// schedule background write
	writer.writeWaitTasks.Add(1)
	writer.writeQueue.In() <- entryKey

	// any pending
	err = writer.GetPendingError()
	if err != nil {
		logger.WithError(err).Errorf("failed to write - %s, %v", writer.bufferEntryGroupName, err)
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
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// wait until all queued tasks complete
	writer.waitForBackgroundWrites()

	// any pending
	err := writer.GetPendingError()
	if err != nil {
		logger.WithError(err).Errorf("failed to write - %s, %v", writer.bufferEntryGroupName, err)
		return err
	}

	writer.fileHandleMutex.Lock()
	defer writer.fileHandleMutex.Unlock()

	return writer.fileHandle.Flush()

}

func (writer *AsyncWriter) GetPendingError() error {
	writer.pendingErrorsMutex.Lock()
	defer writer.pendingErrorsMutex.Unlock()

	if len(writer.pendingErrors) > 0 {
		return writer.pendingErrors[0]
	}
	return nil
}

func (writer *AsyncWriter) addAsyncError(err error) {
	writer.pendingErrorsMutex.Lock()
	defer writer.pendingErrorsMutex.Unlock()

	writer.pendingErrors = append(writer.pendingErrors, err)
}

func (writer *AsyncWriter) waitForBackgroundWrites() {
	writer.writeWaitTasks.Wait()
}

func (writer *AsyncWriter) backgroundWriteTask() {
	logger := log.WithFields(log.Fields{
		"package":  "io",
		"struct":   "AsyncWriter",
		"function": "backgroundWriteTask",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	entryGroup := writer.getBufferEntryGroup()

	for {
		outData, channelOpened := <-writer.writeQueue.Out()
		if !channelOpened {
			// channel is closed
			return
		}

		if outData != nil {
			key := outData.(string)

			offset, err := writer.getBufferEntryOffset(key)
			if err != nil {
				logger.WithError(err).Errorf("failed to get entry offset - %s, %s", writer.bufferEntryGroupName, key)
				writer.addAsyncError(err)
				continue
			}

			entry := entryGroup.PopEntry(key)
			if entry == nil {
				err = fmt.Errorf("failed to get an entry - %s, %s", writer.bufferEntryGroupName, key)
				logger.Error(err)
				writer.addAsyncError(err)
				continue
			}

			data := entry.GetData()
			if len(data) != entry.GetSize() && len(data) <= 0 {
				err = fmt.Errorf("failed to get data - %s, %s", writer.bufferEntryGroupName, key)
				logger.Error(err)
				writer.addAsyncError(err)
				continue
			}

			logger.Infof("Async Writing - %s, Offset %d, length %d", writer.path, offset, len(data))
			writer.fileHandleMutex.Lock()

			err = writer.fileHandle.WriteAt(offset, data)
			if err != nil {
				writer.fileHandleMutex.Unlock()
				logger.WithError(err).Errorf("failed to write data - %s, %d, %d", writer.path, offset, len(data))
				writer.addAsyncError(err)
				continue
			}

			writer.fileHandleMutex.Unlock()

			// Report
			if writer.monitoringReporter != nil {
				writer.monitoringReporter.ReportFileTransfer(writer.path, writer.fileHandle, offset, int64(len(data)))
			}

			writer.writeWaitTasks.Done()
		}
	}
}
