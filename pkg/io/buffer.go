package io

import (
	"time"
)

// BufferEntry is a buffer entry (e.g., a file chunk)
type BufferEntry interface {
	GetKey() string
	GetSize() int
	GetAccessCount() int
	GetCreationTime() time.Time

	GetData() []byte
}

// BufferEntryGroup defines an entry group (e.g., a file)
type BufferEntryGroup interface {
	GetBuffer() Buffer

	GetName() string
	GetEntryCount() int
	GetSize() int64

	GetEntryKeys() []string
	DeleteAllEntries()

	CreateEntry(key string, data []byte) (BufferEntry, error)
	GetEntry(key string) BufferEntry
	DeleteEntry(key string)
	PopEntry(key string) BufferEntry
}

// Buffer is a buffer management object
type Buffer interface {
	Release()

	GetSizeCap() int64

	GetTotalEntries() int
	GetTotalEntrySize() int64
	GetAvailableSize() int64

	WaitForSpace(spaceRequired int64) bool

	CreateEntryGroup(name string) BufferEntryGroup
	GetEntryGroup(name string) BufferEntryGroup
	GetEntryGroups() []BufferEntryGroup
	DeleteEntryGroup(name string)

	DeleteAllEntryGroups()
}
