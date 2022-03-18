package io

import (
	"fmt"

	"github.com/cyverse/irodsfs/pkg/irodsapi"
)

// NilReader does nothing for read
type NilReader struct {
	path       string
	fileHandle irodsapi.IRODSFileHandle
}

// NewNilReader create a new NilReader
func NewNilReader(path string, fileHandle irodsapi.IRODSFileHandle) *NilReader {
	nilReader := &NilReader{
		path:       path,
		fileHandle: fileHandle,
	}

	return nilReader
}

// Release releases all resources
func (reader *NilReader) Release() {
}

// ReadAt reads data
func (reader *NilReader) ReadAt(offset int64, length int) ([]byte, error) {
	return nil, fmt.Errorf("failed to read data using NilReader - %s, offset %d, length %d", reader.path, offset, length)
}

func (reader *NilReader) GetPendingError() error {
	return nil
}
