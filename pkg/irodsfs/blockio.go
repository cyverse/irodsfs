package irodsfs

import (
	"bytes"
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
	BlockCache             *lru.Cache
	FileBlockHelper        *FileBlockHelper
	WriteBuffer            bytes.Buffer
	WriteBufferStartOffset int64
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

	return &BlockIO{
		FS:                     fs,
		FileHandle:             handle,
		BlockCache:             cache,
		FileBlockHelper:        fileBlockHelper,
		WriteBuffer:            bytes.Buffer{},
		WriteBufferStartOffset: 0,
	}, nil
}

// Release releases all resources
func (io *BlockIO) Release() {
	if io.BlockCache != nil {
		io.BlockCache.Purge()
		io.BlockCache = nil
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

	var existingBlockData []byte

	if blockData, ok := io.BlockCache.Get(blockID); ok {
		existingBlockData = blockData.([]byte)
	} else {
		// no cache
		blockStartOffset := io.FileBlockHelper.GetBlockStartOffsetForBlockID(blockID)

		io.FileHandleLock.Lock()
		defer io.FileHandleLock.Unlock()

		if io.FileHandle.GetOffset() != blockStartOffset {
			_, err := io.FileHandle.Seek(blockStartOffset, irodsfs_clienttype.SeekSet)
			if err != nil {
				logger.WithError(err).Errorf("Seek error - %s, %d", io.FileHandle.Entry.Path, blockStartOffset)
				return nil, err
			}
		}

		blockSize := io.FileBlockHelper.GetBlockSizeForBlockID(blockID)
		blockData, err := io.FileHandle.Read(blockSize)
		if err != nil {
			logger.WithError(err).Errorf("Read error - %s, %d", io.FileHandle.Entry.Path, blockSize)
			return nil, err
		}

		io.BlockCache.Add(blockID, blockData)
		existingBlockData = blockData
	}

	if len(existingBlockData) >= offset+length {
		return existingBlockData[offset : offset+length], nil
	}

	return existingBlockData[offset:], nil
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

	io.FileHandleLock.Lock()
	defer io.FileHandleLock.Unlock()

	// check if data is continuous from prior write
	if io.WriteBuffer.Len() > 0 {
		// has data
		if io.WriteBufferStartOffset+int64(io.WriteBuffer.Len()) != offset {
			// not continuous
			// flush
			if io.FileHandle.GetOffset() != io.WriteBufferStartOffset {
				_, err := io.FileHandle.Seek(io.WriteBufferStartOffset, irodsfs_clienttype.SeekSet)
				if err != nil {
					logger.WithError(err).Errorf("Seek error - %s, %d", io.FileHandle.Entry.Path, io.WriteBufferStartOffset)
					return syscall.EREMOTEIO
				}
			}

			err := io.FileHandle.Write(io.WriteBuffer.Bytes())
			if err != nil {
				logger.WithError(err).Errorf("Write error - %s, %d", io.FileHandle.Entry.Path, io.WriteBuffer.Len())
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

	if io.WriteBuffer.Len() >= io.FS.Config.BlockSize {
		// Flush
		if io.FileHandle.GetOffset() != io.WriteBufferStartOffset {
			_, err := io.FileHandle.Seek(io.WriteBufferStartOffset, irodsfs_clienttype.SeekSet)
			if err != nil {
				logger.WithError(err).Errorf("Seek error - %s, %d", io.FileHandle.Entry.Path, io.WriteBufferStartOffset)
				return syscall.EREMOTEIO
			}
		}

		err := io.FileHandle.Write(io.WriteBuffer.Bytes())
		if err != nil {
			logger.WithError(err).Errorf("Write error - %s, %d", io.FileHandle.Entry.Path, io.WriteBuffer.Len())
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

	if io.WriteBuffer.Len() == 0 {
		return nil
	}

	// has data
	io.FileHandleLock.Lock()
	defer io.FileHandleLock.Unlock()

	// flush
	if io.FileHandle.GetOffset() != io.WriteBufferStartOffset {
		_, err := io.FileHandle.Seek(io.WriteBufferStartOffset, irodsfs_clienttype.SeekSet)
		if err != nil {
			logger.WithError(err).Errorf("Seek error - %s, %d", io.FileHandle.Entry.Path, io.WriteBufferStartOffset)
			return syscall.EREMOTEIO
		}
	}

	err := io.FileHandle.Write(io.WriteBuffer.Bytes())
	if err != nil {
		logger.WithError(err).Errorf("Write error - %s, %d", io.FileHandle.Entry.Path, io.WriteBuffer.Len())
		return syscall.EREMOTEIO
	}

	io.WriteBufferStartOffset = 0
	io.WriteBuffer.Reset()
	return nil
}
