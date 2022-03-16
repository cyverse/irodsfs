package io

import (
	"bytes"
	"fmt"
	"runtime/debug"
	"sync"

	log "github.com/sirupsen/logrus"
)

const (
	BufferSizeMax int = 1024 * 1024 * 8 // 8MB
)

type BufferedWriter struct {
	path string

	buffer            bytes.Buffer
	bufferStartOffset int64
	bufferMutex       sync.Mutex

	writer Writer
}

func NewBufferedWriter(path string, writer Writer) *BufferedWriter {
	return &BufferedWriter{
		path: path,

		buffer:            bytes.Buffer{},
		bufferStartOffset: 0,

		writer: writer,
	}
}

// Release releases all resources
func (writer *BufferedWriter) Release() {
	logger := log.WithFields(log.Fields{
		"package":  "io",
		"struct":   "BufferedWriter",
		"function": "Release",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	writer.Flush()

	if writer.writer != nil {
		writer.writer.Release()
		writer.writer = nil
	}
}

func (writer *BufferedWriter) Flush() error {
	logger := log.WithFields(log.Fields{
		"package":  "io",
		"struct":   "BufferedWriter",
		"function": "Flush",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// empty buffer
	if writer.buffer.Len() > 0 {
		err := writer.writer.WriteAt(writer.bufferStartOffset, writer.buffer.Bytes())
		if err != nil {
			logger.Error(err)
			return err
		}
	}

	writer.bufferStartOffset = 0
	writer.buffer.Reset()

	return writer.writer.Flush()
}

func (writer *BufferedWriter) WriteAt(offset int64, data []byte) error {
	logger := log.WithFields(log.Fields{
		"package":  "io",
		"struct":   "BufferedWriter",
		"function": "WriteAt",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	if writer.writer == nil {
		return fmt.Errorf("failed to write data to nil writer")
	}

	if len(data) == 0 || offset < 0 {
		return nil
	}

	writer.bufferMutex.Lock()
	defer writer.bufferMutex.Unlock()

	// check if data is continuous from prior write
	if writer.buffer.Len() > 0 {
		// has data
		if writer.bufferStartOffset+int64(writer.buffer.Len()) != offset {
			// not continuous
			// send out
			err := writer.writer.WriteAt(writer.bufferStartOffset, writer.buffer.Bytes())
			if err != nil {
				logger.Error(err)
				return err
			}

			writer.bufferStartOffset = 0
			writer.buffer.Reset()

			// write to buffer
			_, err = writer.buffer.Write(data)
			if err != nil {
				logger.WithError(err).Errorf("failed to buffer data for file %s, offset %d, length %d", writer.path, offset, len(data))
				return err
			}

			writer.bufferStartOffset = offset
		} else {
			// continuous
			// write to buffer
			_, err := writer.buffer.Write(data)
			if err != nil {
				logger.WithError(err).Errorf("failed to buffer data for file %s, offset %d, length %d", writer.path, offset, len(data))
				return err
			}
		}
	} else {
		// write to buffer
		_, err := writer.buffer.Write(data)
		if err != nil {
			logger.WithError(err).Errorf("failed to buffer data for file %s, offset %d, length %d", writer.path, offset, len(data))
			return err
		}

		writer.bufferStartOffset = offset
	}

	if writer.buffer.Len() >= BufferSizeMax {
		// Spill to disk cache
		err := writer.writer.WriteAt(writer.bufferStartOffset, writer.buffer.Bytes())
		if err != nil {
			logger.Error(err)
			return err
		}

		writer.bufferStartOffset = 0
		writer.buffer.Reset()
	}

	return nil
}

func (writer *BufferedWriter) GetPendingError() error {
	if writer.writer != nil {
		return writer.writer.GetPendingError()
	}
	return nil
}
