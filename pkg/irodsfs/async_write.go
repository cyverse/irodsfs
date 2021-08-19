package irodsfs

import (
	"fmt"
	"strconv"
	"sync"

	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	irodsfs_clienttype "github.com/cyverse/go-irodsclient/irods/types"
	channels "github.com/eapache/channels"
	log "github.com/sirupsen/logrus"
)

// AsyncWrite helps async write
type AsyncWrite struct {
	FS             *IRODSFS
	FileHandle     *irodsfs_client.FileHandle
	FileHandleLock *sync.Mutex

	FileBuffer     *FileBuffer
	WriteWaitTasks sync.WaitGroup
	WriteQueue     channels.Channel
	WriteIOErrors  []error
}

// NewAsyncWrite create a new AsyncWrite
func NewAsyncWrite(fs *IRODSFS, fileHandle *irodsfs_client.FileHandle, fileHandleLock *sync.Mutex) (*AsyncWrite, error) {
	asyncWrite := &AsyncWrite{
		FS:             fs,
		FileHandle:     fileHandle,
		FileHandleLock: fileHandleLock,

		FileBuffer:     fs.FileBuffer,
		WriteWaitTasks: sync.WaitGroup{},
		WriteQueue:     channels.NewInfiniteChannel(),
		WriteIOErrors:  []error{},
	}

	go asyncWrite.backgroundWriteTask()

	return asyncWrite, nil
}

// Release releases all resources
func (asyncWrite *AsyncWrite) Release() {
	// wait until all queued tasks complete
	asyncWrite.WaitBackgroundWrites()

	if asyncWrite.FileBuffer != nil {
		sectionName := asyncWrite.getFileBufferSectionName()
		asyncWrite.FileBuffer.ClearSection(sectionName)
	}

	asyncWrite.WriteQueue.Close()
}

// Write writes data
func (asyncWrite *AsyncWrite) Write(offset int64, data []byte) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Write",
	})

	if len(data) == 0 || offset < 0 {
		return nil
	}

	sectionName := asyncWrite.getFileBufferSectionName()
	bufferKey := asyncWrite.getFileBufferKey(offset)

	err := asyncWrite.FileBuffer.WaitForSpace(int64(len(data)))
	if err != nil {
		logger.WithError(err).Errorf("failed to wait space for cache write - %s, %s", sectionName, bufferKey)
		return err
	}

	err = asyncWrite.FileBuffer.Put(sectionName, bufferKey, data)
	if err != nil {
		logger.WithError(err).Errorf("failed to put cache - %s, %s", sectionName, bufferKey)
		return err
	}

	err = asyncWrite.queueBackgroundWrite(bufferKey)
	if err != nil {
		logger.WithError(err).Errorf("failed to queue background write - %s, %s", sectionName, bufferKey)
		return err
	}

	err = asyncWrite.GetAsyncError()
	if err != nil {
		logger.WithError(err).Errorf("got an async write failure - %s, %v", sectionName, err)
		return err
	}

	return nil
}

func (asyncWrite *AsyncWrite) GetAsyncError() error {
	if len(asyncWrite.WriteIOErrors) > 0 {
		return asyncWrite.WriteIOErrors[0]
	}
	return nil
}

func (asyncWrite *AsyncWrite) addAsyncError(err error) {
	asyncWrite.WriteIOErrors = append(asyncWrite.WriteIOErrors, err)
}

func (asyncWrite *AsyncWrite) queueBackgroundWrite(key string) error {
	// queue key
	asyncWrite.WriteWaitTasks.Add(1)
	asyncWrite.WriteQueue.In() <- key
	return nil
}

func (asyncWrite *AsyncWrite) WaitBackgroundWrites() {
	asyncWrite.WriteWaitTasks.Wait()
}

func (asyncWrite *AsyncWrite) backgroundWriteTask() {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "backgroundWriteTask",
	})

	sectionName := asyncWrite.getFileBufferSectionName()
	filePath := asyncWrite.FileHandle.Entry.Path

	for {
		outData, channelOpened := <-asyncWrite.WriteQueue.Out()
		if !channelOpened {
			// channel is closed
			return
		}

		if outData != nil {
			key := outData.(string)

			// buffer key is still in file buffer
			if bufferEntry, ok := asyncWrite.FileBuffer.GetBufferEntry(sectionName, key); ok {
				// write
				hasError := false

				if bufferEntry.Status == FileBufferEntryStatusReady {
					bufferData, err := asyncWrite.FileBuffer.Pop(sectionName, key)
					if err != nil {
						logger.WithError(err).Errorf("failed to get buffered data - %s, %s", sectionName, key)
						asyncWrite.addAsyncError(err)
						hasError = true
					}

					if !hasError {
						// upload buffer data
						offset, err := asyncWrite.getFileBufferOffsetFromKey(key)
						if err != nil {
							logger.WithError(err).Errorf("failed to get buffer offset - %s, %s", sectionName, key)
							asyncWrite.addAsyncError(err)
							hasError = true
						} else {
							logger.Infof("Async Writing - %s, Offset %d", filePath, offset)

							asyncWrite.FileHandleLock.Lock()

							if asyncWrite.FileHandle.GetOffset() != offset {
								_, err := asyncWrite.FileHandle.Seek(offset, irodsfs_clienttype.SeekSet)
								if err != nil {
									logger.WithError(err).Errorf("failed to seek - %s, %d", filePath, offset)
									asyncWrite.addAsyncError(err)
									hasError = true
								}
							}

							if !hasError {
								err := asyncWrite.FileHandle.Write(bufferData)
								if err != nil {
									logger.WithError(err).Errorf("failed to write data - %s, %d", filePath, len(bufferData))
									asyncWrite.addAsyncError(err)
									hasError = true
								}

								// Report
								asyncWrite.FS.MonitoringReporter.ReportFileTransfer(asyncWrite.FileHandle.IRODSHandle.Path, asyncWrite.FileHandle, offset, int64(len(bufferData)))
							}

							asyncWrite.FileHandleLock.Unlock()
						}
					}
				}
			}

			asyncWrite.WriteWaitTasks.Done()
		}
	}
}

func (asyncWrite *AsyncWrite) getFileBufferSectionName() string {
	return fmt.Sprintf("write:%s", asyncWrite.FileHandle.Entry.Path)
}

func (asyncWrite *AsyncWrite) getFileBufferKey(startOffset int64) string {
	return fmt.Sprintf("%d", startOffset)
}

func (asyncWrite *AsyncWrite) getFileBufferOffsetFromKey(key string) (int64, error) {
	return strconv.ParseInt(key, 10, 64)
}
