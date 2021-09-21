package asyncwrite

import (
	"bytes"
	"fmt"
	"sync"

	log "github.com/sirupsen/logrus"
)

type BufferedWriter struct {
	Path string

	Buffer            bytes.Buffer
	BufferStartOffset int64
	Mutex             sync.Mutex // lock for WriteBuffer

	Writer Writer
}

const (
	BufferSizeMax int = 1024 * 1024 * 8 // 8MB
)

func NewBufferedWriter(path string, writer Writer) *BufferedWriter {
	return &BufferedWriter{
		Path: path,

		Buffer:            bytes.Buffer{},
		BufferStartOffset: 0,

		Writer: writer,
	}
}

// Release releases all resources
func (writer *BufferedWriter) Release() {
	writer.Flush()

	if writer.Writer != nil {
		writer.Writer.Release()
		writer.Writer = nil
	}
}

func (writer *BufferedWriter) Flush() error {
	logger := log.WithFields(log.Fields{
		"package":  "asyncwrite",
		"struct":   "BufferedWriter",
		"function": "Flush",
	})

	// empty buffer
	if writer.Buffer.Len() > 0 {
		err := writer.Writer.WriteAt(writer.BufferStartOffset, writer.Buffer.Bytes())
		if err != nil {
			logger.Error(err)
			return err
		}
	}

	writer.BufferStartOffset = 0
	writer.Buffer.Reset()

	return writer.Writer.Flush()
}

func (writer *BufferedWriter) WriteAt(offset int64, data []byte) error {
	logger := log.WithFields(log.Fields{
		"package":  "asyncwrite",
		"struct":   "BufferedWriter",
		"function": "WriteAt",
	})

	if writer.Writer == nil {
		return fmt.Errorf("failed to write data to nil writer")
	}

	if len(data) == 0 || offset < 0 {
		return nil
	}

	writer.Mutex.Lock()
	defer writer.Mutex.Unlock()

	// check if data is continuous from prior write
	if writer.Buffer.Len() > 0 {
		// has data
		if writer.BufferStartOffset+int64(writer.Buffer.Len()) != offset {
			// not continuous
			// send out
			err := writer.Writer.WriteAt(writer.BufferStartOffset, writer.Buffer.Bytes())
			if err != nil {
				logger.Error(err)
				return err
			}

			writer.BufferStartOffset = 0
			writer.Buffer.Reset()

			// write to buffer
			_, err = writer.Buffer.Write(data)
			if err != nil {
				logger.WithError(err).Errorf("failed to buffer data for file %s, offset %d, length %d", writer.Path, offset, len(data))
				return err
			}

			writer.BufferStartOffset = offset
		} else {
			// continuous
			// write to buffer
			_, err := writer.Buffer.Write(data)
			if err != nil {
				logger.WithError(err).Errorf("failed to buffer data for file %s, offset %d, length %d", writer.Path, offset, len(data))
				return err
			}
		}
	} else {
		// write to buffer
		_, err := writer.Buffer.Write(data)
		if err != nil {
			logger.WithError(err).Errorf("failed to buffer data for file %s, offset %d, length %d", writer.Path, offset, len(data))
			return err
		}

		writer.BufferStartOffset = offset
	}

	if writer.Buffer.Len() >= BufferSizeMax {
		// Spill to disk cache
		err := writer.Writer.WriteAt(writer.BufferStartOffset, writer.Buffer.Bytes())
		if err != nil {
			logger.Error(err)
			return err
		}

		writer.BufferStartOffset = 0
		writer.Buffer.Reset()
	}

	return nil
}

func (writer *BufferedWriter) GetPendingError() error {
	if writer.Writer != nil {
		return writer.Writer.GetPendingError()
	}
	return nil
}
