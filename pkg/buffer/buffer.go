package buffer

import (
	"time"
)

// BufferEntry is an entry
type Entry interface {
	GetKey() string
	GetSize() int
	GetAccessCount() int
	GetCreationTime() time.Time

	GetData() []byte
}

// EntryGroup defines a group
type EntryGroup interface {
	GetBuffer() Buffer

	GetName() string
	GetEntryCount() int
	GetSize() int64

	GetEntryKeys() []string
	DeleteAllEntries()

	CreateEntry(key string, data []byte) (Entry, error)
	GetEntry(key string) Entry
	DeleteEntry(key string)
	PopEntry(key string) Entry
}

type Buffer interface {
	GetSizeCap() int64

	GetTotalEntries() int
	GetTotalEntrySize() int64
	GetAvailableSize() int64

	WaitForSpace(spaceRequired int64) bool

	CreateEntryGroup(name string) EntryGroup
	GetEntryGroup(name string) EntryGroup
	GetEntryGroups() []EntryGroup
	DeleteEntryGroup(name string)

	DeleteAllEntryGroups()
}
