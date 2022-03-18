package io

// Reader helps data read
type Reader interface {
	ReadAt(offset int64, length int) ([]byte, error)
	GetPendingError() error
	Release()
}
