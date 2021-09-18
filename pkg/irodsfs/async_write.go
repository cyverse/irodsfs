package irodsfs

import (
	"fmt"
	"strconv"
	"sync"

	"github.com/cyverse/irodsfs/pkg/buffer"
	"github.com/cyverse/irodsfs/pkg/irodsapi"
	"github.com/cyverse/irodsfs/pkg/report"
	"github.com/eapache/channels"
	log "github.com/sirupsen/logrus"
)

// AsyncWrite helps async write
type AsyncWrite struct {
	IRODSFileHandle irodsapi.IRODSFileHandle
	FileHandleLock  *sync.Mutex

	Buffer               buffer.Buffer
	BufferEntryGroupName string

	WriteWaitTasks sync.WaitGroup
	WriteQueue     channels.Channel

	PendingErrors []error
	Mutex         sync.Mutex // for WriteIOErrors

	MonitoringReporter *report.MonitoringReporter
}

// NewAsyncWrite create a new AsyncWrite
func NewAsyncWrite(fileHandle irodsapi.IRODSFileHandle, fileHandleLock *sync.Mutex, writeBuffer buffer.Buffer, monitoringReporter *report.MonitoringReporter) (*AsyncWrite, error) {
	asyncWrite := &AsyncWrite{
		IRODSFileHandle: fileHandle,
		FileHandleLock:  fileHandleLock,

		Buffer:               writeBuffer,
		BufferEntryGroupName: fmt.Sprintf("write:%s", fileHandle.GetEntry().Path),

		WriteWaitTasks: sync.WaitGroup{},
		WriteQueue:     channels.NewInfiniteChannel(),
		PendingErrors:  []error{},

		MonitoringReporter: monitoringReporter,
	}

	writeBuffer.CreateEntryGroup(asyncWrite.BufferEntryGroupName)

	go asyncWrite.backgroundWriteTask()

	return asyncWrite, nil
}

// Release releases all resources
func (asyncWrite *AsyncWrite) Release() {
	// wait until all queued tasks complete
	asyncWrite.WaitForBackgroundWrites()

	if asyncWrite.Buffer != nil {
		asyncWrite.Buffer.DeleteEntryGroup(asyncWrite.BufferEntryGroupName)
	}

	asyncWrite.WriteQueue.Close()
}

func (asyncWrite *AsyncWrite) getBufferEntryGroup() buffer.EntryGroup {
	return asyncWrite.Buffer.GetEntryGroup(asyncWrite.BufferEntryGroupName)
}

func (asyncWrite *AsyncWrite) getBufferEntryKey(offset int64) string {
	return fmt.Sprintf("%d", offset)
}

func (asyncWrite *AsyncWrite) getBufferEntryOffset(key string) (int64, error) {
	return strconv.ParseInt(key, 10, 64)
}

// Write writes data
func (asyncWrite *AsyncWrite) Write(offset int64, data []byte) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "AsyncWrite",
		"function": "Write",
	})

	if len(data) == 0 || offset < 0 {
		return nil
	}

	entryKey := asyncWrite.getBufferEntryKey(offset)
	entryGroup := asyncWrite.getBufferEntryGroup()

	_, err := entryGroup.CreateEntry(entryKey, data)
	if err != nil {
		logger.WithError(err).Errorf("failed to put an entry to buffer - %s, %s", asyncWrite.BufferEntryGroupName, entryKey)
		return err
	}

	// schedule background write
	asyncWrite.WriteWaitTasks.Add(1)
	asyncWrite.WriteQueue.In() <- entryKey

	// any pending
	err = asyncWrite.GetAsyncError()
	if err != nil {
		logger.WithError(err).Errorf("failed to write - %s, %v", asyncWrite.BufferEntryGroupName, err)
		return err
	}

	return nil
}

func (asyncWrite *AsyncWrite) GetAsyncError() error {
	asyncWrite.Mutex.Lock()
	defer asyncWrite.Mutex.Unlock()

	if len(asyncWrite.PendingErrors) > 0 {
		return asyncWrite.PendingErrors[0]
	}
	return nil
}

func (asyncWrite *AsyncWrite) addAsyncError(err error) {
	asyncWrite.Mutex.Lock()
	defer asyncWrite.Mutex.Unlock()

	asyncWrite.PendingErrors = append(asyncWrite.PendingErrors, err)
}

func (asyncWrite *AsyncWrite) WaitForBackgroundWrites() {
	asyncWrite.WriteWaitTasks.Wait()
}

func (asyncWrite *AsyncWrite) backgroundWriteTask() {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "AsyncWrite",
		"function": "backgroundWriteTask",
	})

	entryGroup := asyncWrite.getBufferEntryGroup()

	filePath := asyncWrite.IRODSFileHandle.GetEntry().Path

	for {
		outData, channelOpened := <-asyncWrite.WriteQueue.Out()
		if !channelOpened {
			// channel is closed
			return
		}

		if outData != nil {
			key := outData.(string)

			offset, err := asyncWrite.getBufferEntryOffset(key)
			if err != nil {
				logger.WithError(err).Errorf("failed to get entry offset - %s, %s", asyncWrite.BufferEntryGroupName, key)
				asyncWrite.addAsyncError(err)
				continue
			}

			entry := entryGroup.PopEntry(key)
			if entry == nil {
				err = fmt.Errorf("failed to get an entry - %s, %s", asyncWrite.BufferEntryGroupName, key)
				logger.Error(err)
				asyncWrite.addAsyncError(err)
				continue
			}

			data := entry.GetData()
			if len(data) != entry.GetSize() && len(data) <= 0 {
				err = fmt.Errorf("failed to get data - %s, %s", asyncWrite.BufferEntryGroupName, key)
				logger.Error(err)
				asyncWrite.addAsyncError(err)
				continue
			}

			logger.Infof("Async Writing - %s, Offset %d", filePath, offset)
			asyncWrite.FileHandleLock.Lock()

			err = asyncWrite.IRODSFileHandle.WriteAt(offset, data)
			if err != nil {
				logger.WithError(err).Errorf("failed to write data - %s, %d, %d", filePath, offset, len(data))
				asyncWrite.addAsyncError(err)
				continue
			}

			// Report
			if asyncWrite.MonitoringReporter != nil {
				asyncWrite.MonitoringReporter.ReportFileTransfer(asyncWrite.IRODSFileHandle.GetEntry().Path, asyncWrite.IRODSFileHandle, offset, int64(len(data)))
			}

			asyncWrite.FileHandleLock.Unlock()

			asyncWrite.WriteWaitTasks.Done()
		}
	}
}
