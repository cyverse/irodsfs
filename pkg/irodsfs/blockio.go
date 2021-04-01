package irodsfs

import (
	"bytes"
	"fmt"
	"sync"
	"syscall"

	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	irodsfs_clienttype "github.com/cyverse/go-irodsclient/irods/types"
	lru "github.com/hashicorp/golang-lru"
	log "github.com/sirupsen/logrus"
)

// BlockIO helps reading/writing data in block level
type BlockIO struct {
	FS                     *IRODSFS
	FileHandle             *irodsfs_client.FileHandle
	FileHandleLock         sync.Mutex
	MemoryBlockCache       *lru.Cache
	DiskBlockCache         *FileCache
	FileBlockHelper        *FileBlockHelper
	WriteBuffer            bytes.Buffer
	WriteBufferStartOffset int64
	AsyncWrite             *AsyncWrite
}

// NewBlockIO create a new BlockIO
func NewBlockIO(fs *IRODSFS, handle *irodsfs_client.FileHandle) (*BlockIO, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "NewBlockIO",
	})

	cacheMax := fs.Config.PerFileBlockCacheMax
	if cacheMax <= 0 {
		cacheMax = 1
	}

	cache, err := lru.New(cacheMax)
	if err != nil {
		logger.WithError(err).Error("Could not create a new LRU Cache")
		return nil, err
	}

	fileBlockHelper := &FileBlockHelper{
		BlockSize: fs.Config.BlockSize,
		FileSize:  handle.Entry.Size,
	}

	blockio := &BlockIO{
		FS:                     fs,
		FileHandle:             handle,
		MemoryBlockCache:       cache,
		DiskBlockCache:         fs.FileCache,
		FileBlockHelper:        fileBlockHelper,
		WriteBuffer:            bytes.Buffer{},
		WriteBufferStartOffset: 0,
	}

	asyncWrite, err := NewAsyncWrite(fs, blockio)
	if err != nil {
		logger.WithError(err).Error("Could not create a new Async Write")
		return nil, err
	}

	blockio.AsyncWrite = asyncWrite

	return blockio, nil
}

// Release releases all resources
func (io *BlockIO) Release() {
	// wait until all queued tasks complete
	io.AsyncWrite.Release()

	if io.MemoryBlockCache != nil {
		io.MemoryBlockCache.Purge()
	}
}

// Read reads data
func (io *BlockIO) Read(offset int64, length int) ([]byte, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Read",
	})

	if offset > io.FileHandle.Entry.Size {
		return []byte{}, nil
	}

	startBlockID, endBlockID := io.FileBlockHelper.GetFirstAndLastBlockIDForRW(offset, length)
	curOffset := offset
	curLength := length

	if startBlockID == endBlockID {
		// single block
		inBlockOffset, inBlockLength := io.FileBlockHelper.GetInBlockOffsetAndLength(curOffset, curLength)
		dataBytes, err := io.readInBlock(startBlockID, inBlockOffset, inBlockLength)
		if err != nil {
			logger.WithError(err).Error("Could not read data for file %s, offset %d, length %d", io.FileHandle.IRODSHandle.Path, curOffset, inBlockLength)
			return nil, err
		}

		return dataBytes, nil
	}

	// long read
	dataBuffer := bytes.Buffer{}
	for blockID := startBlockID; blockID <= endBlockID; blockID++ {
		inBlockOffset, inBlockLength := io.FileBlockHelper.GetInBlockOffsetAndLength(curOffset, curLength)
		dataBytes, err := io.readInBlock(blockID, inBlockOffset, inBlockLength)
		if err != nil {
			logger.WithError(err).Error("Could not read data for file %s, offset %d, length %d", io.FileHandle.IRODSHandle.Path, curOffset, inBlockLength)
			return nil, err
		}

		_, err = dataBuffer.Write(dataBytes)
		if err != nil {
			logger.WithError(err).Error("Could not buffer data for file %s, offset %d, length %d", io.FileHandle.IRODSHandle.Path, curOffset, inBlockLength)
			return nil, err
		}

		curOffset += int64(len(dataBytes))
		curLength -= len(dataBytes)
	}
	return dataBuffer.Bytes(), nil
}

func (io *BlockIO) readInBlock(blockID BlockID, offset int, length int) ([]byte, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "ReadInBlock",
	})

	// in memory cache
	if memoryBlockData, inMemory := io.MemoryBlockCache.Get(blockID); inMemory {
		existingBlockData := memoryBlockData.([]byte)

		if len(existingBlockData) >= offset+length {
			return existingBlockData[offset : offset+length], nil
		}

		return existingBlockData[offset:], nil
	}

	// in disk cache
	diskCacheSectionName := io.getFileCacheReadSectionName()
	diskCacheKey := io.getFileCacheReadKey(blockID)
	if cacheEntry, ok := io.DiskBlockCache.GetCacheEntry(diskCacheSectionName, diskCacheKey); ok {
		if cacheEntry.Status == FileCacheEntryStatusReady {
			diskBlockData, err := io.DiskBlockCache.Get(diskCacheSectionName, diskCacheKey)
			if err != nil {
				logger.WithError(err).Errorf("Read disk cache error - %s, %s", io.FileHandle.Entry.Path, diskCacheKey)
				return nil, err
			}

			// move to in memory cache
			io.MemoryBlockCache.Add(blockID, diskBlockData)

			if len(diskBlockData) >= offset+length {
				return diskBlockData[offset : offset+length], nil
			}

			return diskBlockData[offset:], nil
		}
	}

	// no cache - get it from remote
	blockStartOffset := io.FileBlockHelper.GetBlockStartOffsetForBlockID(blockID)

	io.FileHandleLock.Lock()

	if io.FileHandle.GetOffset() != blockStartOffset {
		_, err := io.FileHandle.Seek(blockStartOffset, irodsfs_clienttype.SeekSet)
		if err != nil {
			io.FileHandleLock.Unlock()
			logger.WithError(err).Errorf("Seek error - %s, %d", io.FileHandle.Entry.Path, blockStartOffset)
			return nil, err
		}
	}

	blockSize := io.FileBlockHelper.GetBlockSizeForBlockID(blockID)
	blockData, err := io.FileHandle.Read(blockSize)
	if err != nil {
		io.FileHandleLock.Unlock()
		logger.WithError(err).Errorf("Read error - %s, %d", io.FileHandle.Entry.Path, blockSize)
		return nil, err
	}

	io.FileHandleLock.Unlock()

	// store in memory cache
	io.MemoryBlockCache.Add(blockID, blockData)

	go func() {
		availableSpace, err := io.DiskBlockCache.EvictBySize(int64(blockSize), 1)
		if err != nil {
			// ignore error
			logger.WithError(err).Errorf("Evict disk cache error - %d", blockSize)
		}

		if availableSpace < int64(blockSize) {
			// try again
			availableSpace, err = io.DiskBlockCache.EvictBySize(int64(blockSize), 0)
			if err != nil {
				// ignore error
				logger.WithError(err).Errorf("Evict disk cache error - %d", blockSize)
			}
		}

		if availableSpace >= int64(blockSize) {
			// store in disk cache
			err = io.DiskBlockCache.Put(diskCacheSectionName, diskCacheKey, blockData)
			if err != nil {
				// ignore error
				logger.WithError(err).Errorf("Write disk cache error - %s, %s", diskCacheSectionName, diskCacheKey)
			}
		}
	}()

	if len(blockData) >= offset+length {
		return blockData[offset : offset+length], nil
	}

	return blockData[offset:], nil
}

// Write writes data
func (io *BlockIO) Write(offset int64, data []byte) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Write",
	})

	if len(data) == 0 || offset < 0 {
		return nil
	}

	// check if data is continuous from prior write
	if io.WriteBuffer.Len() > 0 {
		// has data
		if io.WriteBufferStartOffset+int64(io.WriteBuffer.Len()) != offset {
			// not continuous
			// Spill to disk cache
			err := io.AsyncWrite.Write(io.WriteBufferStartOffset, io.WriteBuffer.Bytes())
			if err != nil {
				logger.WithError(err).Errorf("Spill error - %s, %d", io.FileHandle.Entry.Path, io.WriteBufferStartOffset)
				return syscall.EREMOTEIO
			}

			io.WriteBufferStartOffset = 0
			io.WriteBuffer.Reset()

			// write to buffer
			_, err = io.WriteBuffer.Write(data)
			if err != nil {
				logger.WithError(err).Errorf("Could not buffer data for file %s, offset %d, length %d", io.FileHandle.IRODSHandle.Path, offset, len(data))
				return syscall.EREMOTEIO
			}
			io.WriteBufferStartOffset = offset
		} else {
			// continuous
			// write to buffer
			_, err := io.WriteBuffer.Write(data)
			if err != nil {
				logger.WithError(err).Errorf("Could not buffer data for file %s, offset %d, length %d", io.FileHandle.IRODSHandle.Path, offset, len(data))
				return syscall.EREMOTEIO
			}
		}
	} else {
		// write to buffer
		_, err := io.WriteBuffer.Write(data)
		if err != nil {
			logger.WithError(err).Errorf("Could not buffer data for file %s, offset %d, length %d", io.FileHandle.IRODSHandle.Path, offset, len(data))
			return syscall.EREMOTEIO
		}
		io.WriteBufferStartOffset = offset
	}

	if io.WriteBuffer.Len() >= WriteBlockSize {
		// Spill to disk cache
		err := io.AsyncWrite.Write(io.WriteBufferStartOffset, io.WriteBuffer.Bytes())
		if err != nil {
			logger.WithError(err).Errorf("Spill error - %s, %d", io.FileHandle.Entry.Path, io.WriteBufferStartOffset)
			return syscall.EREMOTEIO
		}

		io.WriteBufferStartOffset = 0
		io.WriteBuffer.Reset()
	}
	return nil
}

// Flush flushes write buffer
func (io *BlockIO) Flush() error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Flush",
	})

	// spill
	if io.WriteBuffer.Len() > 0 {
		err := io.AsyncWrite.Write(io.WriteBufferStartOffset, io.WriteBuffer.Bytes())
		if err != nil {
			logger.WithError(err).Errorf("Spill error - %s, %d", io.FileHandle.Entry.Path, io.WriteBufferStartOffset)
			return syscall.EREMOTEIO
		}

		io.WriteBufferStartOffset = 0
		io.WriteBuffer.Reset()
	}

	// wait until all queued tasks complete
	io.AsyncWrite.WaitBackgroundWrites()

	err := io.AsyncWrite.GetAsyncError()
	if err != nil {
		logger.WithError(err).Errorf("Async write error - %s, %v", io.FileHandle.Entry.Path, err)
		return syscall.EREMOTEIO
	}

	return nil
}

func (io *BlockIO) getFileCacheReadSectionName() string {
	return fmt.Sprintf("read:%s", io.FileHandle.Entry.Path)
}

func (io *BlockIO) getFileCacheReadKey(blockID BlockID) string {
	return fmt.Sprintf("%d", int64(blockID))
}
