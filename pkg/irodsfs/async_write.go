package irodsfs

import (
	"fmt"
	"strconv"
	"sync"
	"syscall"

	irodsfs_clienttype "github.com/cyverse/go-irodsclient/irods/types"
	channels "github.com/eapache/channels"
	log "github.com/sirupsen/logrus"
)

const (
	WriteBlockSize int = 1024 * 1024 * 1 // 1MB
)

// AsyncWrite helps async write
type AsyncWrite struct {
	FS             *IRODSFS
	BlockIO        *BlockIO
	DiskBlockCache *FileCache
	WriteWaitTasks sync.WaitGroup
	WriteQueue     channels.Channel
	WriteIOErrors  []error
}

// NewAsyncWrite create a new AsyncWrite
func NewAsyncWrite(fs *IRODSFS, blockio *BlockIO) (*AsyncWrite, error) {
	asyncWrite := &AsyncWrite{
		FS:             fs,
		BlockIO:        blockio,
		DiskBlockCache: fs.FileCache,
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

	if asyncWrite.DiskBlockCache != nil {
		sectionName := asyncWrite.getFileCacheWriteSectionName()
		asyncWrite.DiskBlockCache.ClearSection(sectionName)
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

	sectionName := asyncWrite.getFileCacheWriteSectionName()
	cacheKey := asyncWrite.getFileCacheWriteKey(offset)

	err := asyncWrite.DiskBlockCache.WaitForSpace(int64(len(data)))
	if err != nil {
		logger.WithError(err).Errorf("Cache write wait error - %s, %s", sectionName, cacheKey)
		return syscall.EREMOTEIO
	}

	err = asyncWrite.DiskBlockCache.Put(sectionName, cacheKey, data)
	if err != nil {
		logger.WithError(err).Errorf("Cache write error - %s, %s", sectionName, cacheKey)
		return syscall.EREMOTEIO
	}

	err = asyncWrite.queueBackgroundWrite(cacheKey)
	if err != nil {
		logger.WithError(err).Errorf("Queue background write error - %s, %s", sectionName, cacheKey)
		return syscall.EREMOTEIO
	}

	err = asyncWrite.GetAsyncError()
	if err != nil {
		logger.WithError(err).Errorf("Async write error found - %s, %v", sectionName, err)
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

func (asyncWrite *AsyncWrite) popAsyncError() error {
	if len(asyncWrite.WriteIOErrors) > 0 {
		err := asyncWrite.WriteIOErrors[0]
		asyncWrite.WriteIOErrors = asyncWrite.WriteIOErrors[1:]
		return err
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

	sectionName := asyncWrite.getFileCacheWriteSectionName()
	filePath := asyncWrite.BlockIO.FileHandle.Entry.Path

	for {
		outData, channelOpened := <-asyncWrite.WriteQueue.Out()
		if !channelOpened {
			// channel is closed
			return
		}

		if outData != nil {
			key := outData.(string)

			// check key is still in file cache
			if cacheEntry, ok := asyncWrite.DiskBlockCache.GetCacheEntry(sectionName, key); ok {
				// write
				hasError := false

				if cacheEntry.Status == FileCacheEntryStatusReady {
					cacheData, err := asyncWrite.DiskBlockCache.Get(sectionName, key)
					if err != nil {
						logger.WithError(err).Errorf("Reading disk block cache error - %s, %s", sectionName, key)
						asyncWrite.addAsyncError(err)
						hasError = true
					}

					if !hasError {
						// upload cache data
						offset, err := asyncWrite.getFileCacheWriteOffsetFromKey(key)
						if err != nil {
							logger.WithError(err).Errorf("Reading cache offset error - %s, %s", sectionName, key)
							asyncWrite.addAsyncError(err)
							hasError = true
						} else {
							logger.Infof("Async Writing - %s, Offset %d", filePath, offset)

							asyncWrite.BlockIO.FileHandleLock.Lock()

							if asyncWrite.BlockIO.FileHandle.GetOffset() != offset {
								_, err := asyncWrite.BlockIO.FileHandle.Seek(offset, irodsfs_clienttype.SeekSet)
								if err != nil {
									logger.WithError(err).Errorf("Seek error - %s, %d", filePath, offset)
									asyncWrite.addAsyncError(err)
									hasError = true
								}
							}

							if !hasError {
								err := asyncWrite.BlockIO.FileHandle.Write(cacheData)
								if err != nil {
									logger.WithError(err).Errorf("Write error - %s, %d", filePath, len(cacheData))
									asyncWrite.addAsyncError(err)
									hasError = true
								}
							}

							asyncWrite.BlockIO.FileHandleLock.Unlock()

							asyncWrite.DiskBlockCache.Remove(sectionName, key)
						}
					}
				}
			}

			asyncWrite.WriteWaitTasks.Done()
		}
	}
}

func (asyncWrite *AsyncWrite) getFileCacheWriteSectionName() string {
	return fmt.Sprintf("write:%s", asyncWrite.BlockIO.FileHandle.Entry.Path)
}

func (asyncWrite *AsyncWrite) getFileCacheWriteKey(startOffset int64) string {
	return fmt.Sprintf("%d", startOffset)
}

func (asyncWrite *AsyncWrite) getFileCacheWriteOffsetFromKey(key string) (int64, error) {
	return strconv.ParseInt(key, 10, 64)
}
