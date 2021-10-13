package io

// Writer helps data write
type Writer interface {
	WriteAt(offset int64, data []byte) error
	Flush() error
	GetPendingError() error
	Release()
}
