package io

import (
	"fmt"
	"sync"
	"time"
)

type RAMBufferEntry struct {
	Key          string
	Size         int
	AccessCount  int
	CreationTime time.Time
	Data         []byte
	Mutex        sync.Mutex
}

func NewRAMBufferEntry(key string, data []byte) *RAMBufferEntry {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	return &RAMBufferEntry{
		Key:          key,
		Size:         len(data),
		AccessCount:  0,
		CreationTime: time.Now(),
		Data:         dataCopy,
	}
}

func (entry *RAMBufferEntry) GetKey() string {
	return entry.Key
}

func (entry *RAMBufferEntry) GetSize() int {
	return entry.Size
}

func (entry *RAMBufferEntry) GetAccessCount() int {
	entry.Mutex.Lock()
	defer entry.Mutex.Unlock()

	return entry.AccessCount
}

func (entry *RAMBufferEntry) GetCreationTime() time.Time {
	return entry.CreationTime
}

func (entry *RAMBufferEntry) GetData() []byte {
	entry.Mutex.Lock()
	defer entry.Mutex.Unlock()

	entry.AccessCount++
	return entry.Data
}

// RAMBufferEntryGroup defines a group
type RAMBufferEntryGroup struct {
	Buffer *RAMBuffer

	Name     string
	Size     int64
	EntryMap map[string]*RAMBufferEntry

	Mutex sync.Mutex
}

func NewRAMBufferEntryGroup(buffer *RAMBuffer, name string) *RAMBufferEntryGroup {
	return &RAMBufferEntryGroup{
		Buffer: buffer,

		Name:     name,
		Size:     0,
		EntryMap: map[string]*RAMBufferEntry{},
	}
}

func (group *RAMBufferEntryGroup) GetBuffer() Buffer {
	return group.Buffer
}

func (group *RAMBufferEntryGroup) GetName() string {
	return group.Name
}

func (group *RAMBufferEntryGroup) GetEntryCount() int {
	group.Buffer.Mutex.Lock()
	defer group.Buffer.Mutex.Unlock()

	group.Mutex.Lock()
	defer group.Mutex.Unlock()

	return len(group.EntryMap)
}

func (group *RAMBufferEntryGroup) getEntryCountWithoutBufferLock() int {
	group.Mutex.Lock()
	defer group.Mutex.Unlock()

	return len(group.EntryMap)
}

func (group *RAMBufferEntryGroup) GetSize() int64 {
	group.Buffer.Mutex.Lock()
	defer group.Buffer.Mutex.Unlock()

	group.Mutex.Lock()
	defer group.Mutex.Unlock()

	return group.Size
}

func (group *RAMBufferEntryGroup) getSizeWithoutBufferLock() int64 {
	group.Mutex.Lock()
	defer group.Mutex.Unlock()

	return group.Size
}

func (group *RAMBufferEntryGroup) GetEntryKeys() []string {
	group.Buffer.Mutex.Lock()
	defer group.Buffer.Mutex.Unlock()

	group.Mutex.Lock()
	defer group.Mutex.Unlock()

	keys := []string{}

	for key := range group.EntryMap {
		keys = append(keys, key)
	}
	return keys
}

func (group *RAMBufferEntryGroup) DeleteAllEntries() {
	group.Buffer.Mutex.Lock()
	group.Mutex.Lock()

	for _, entry := range group.EntryMap {
		group.Size -= int64(entry.GetSize())
	}

	group.EntryMap = map[string]*RAMBufferEntry{}

	group.Mutex.Unlock()
	group.Buffer.Condition.Broadcast()
	group.Buffer.Mutex.Unlock()
}

func (group *RAMBufferEntryGroup) deleteAllEntriesWithoutBufferLock() {
	group.Mutex.Lock()
	defer group.Mutex.Unlock()

	for _, entry := range group.EntryMap {
		group.Size -= int64(entry.GetSize())
	}

	group.EntryMap = map[string]*RAMBufferEntry{}
}

func (group *RAMBufferEntryGroup) CreateEntry(key string, data []byte) (BufferEntry, error) {
	group.Buffer.Mutex.Lock()
	if group.Buffer.SizeCap < int64(len(data)) {
		group.Buffer.Mutex.Unlock()
		return nil, fmt.Errorf("requested data %d is larger than size cap %d", len(data), group.Buffer.SizeCap)
	}
	group.Buffer.Mutex.Unlock()

	for {
		group.Buffer.Mutex.Lock()

		var size int64 = 0
		for _, group := range group.Buffer.EntryGroupMap {
			size += group.getSizeWithoutBufferLock()
		}
		avail := group.Buffer.SizeCap - size

		if avail >= int64(len(data)) {
			group.Mutex.Lock()

			entry := NewRAMBufferEntry(key, data)
			group.EntryMap[key] = entry
			group.Size += int64(len(data))

			group.Mutex.Unlock()
			group.Buffer.Mutex.Unlock()
			return entry, nil
		}

		// wait for availability
		group.Buffer.Condition.Wait()
		group.Buffer.Mutex.Unlock()
	}
}

func (group *RAMBufferEntryGroup) GetEntry(key string) BufferEntry {
	group.Buffer.Mutex.Lock()
	defer group.Buffer.Mutex.Unlock()

	group.Mutex.Lock()
	defer group.Mutex.Unlock()

	if entry, ok := group.EntryMap[key]; ok {
		return entry
	}

	return nil
}

func (group *RAMBufferEntryGroup) DeleteEntry(key string) {
	group.Buffer.Mutex.Lock()
	group.Mutex.Lock()

	if entry, ok := group.EntryMap[key]; ok {
		group.Size -= int64(entry.GetSize())
	}

	delete(group.EntryMap, key)

	group.Mutex.Unlock()
	group.Buffer.Condition.Broadcast()
	group.Buffer.Mutex.Unlock()
}

func (group *RAMBufferEntryGroup) PopEntry(key string) BufferEntry {
	group.Buffer.Mutex.Lock()
	group.Mutex.Lock()

	var returnEntry BufferEntry = nil
	if entry, ok := group.EntryMap[key]; ok {
		group.Size -= int64(entry.GetSize())
		returnEntry = entry
	}

	delete(group.EntryMap, key)

	group.Mutex.Unlock()
	group.Buffer.Condition.Broadcast()
	group.Buffer.Mutex.Unlock()

	return returnEntry
}

// RAMBuffer
type RAMBuffer struct {
	SizeCap       int64
	EntryGroupMap map[string]*RAMBufferEntryGroup

	Mutex     *sync.Mutex
	Condition *sync.Cond
}

func NewRAMBuffer(sizeCap int64) *RAMBuffer {
	mutex := sync.Mutex{}
	return &RAMBuffer{
		SizeCap:       sizeCap,
		EntryGroupMap: map[string]*RAMBufferEntryGroup{},
		Mutex:         &mutex,
		Condition:     sync.NewCond(&mutex),
	}
}

func (buffer *RAMBuffer) Release() {
	buffer.DeleteAllEntryGroups()
}

func (buffer *RAMBuffer) GetSizeCap() int64 {
	return buffer.SizeCap
}

func (buffer *RAMBuffer) GetTotalEntries() int {
	buffer.Mutex.Lock()
	defer buffer.Mutex.Unlock()

	entries := 0

	for _, group := range buffer.EntryGroupMap {
		entries += group.getEntryCountWithoutBufferLock()
	}

	return entries
}

func (buffer *RAMBuffer) GetTotalEntrySize() int64 {
	buffer.Mutex.Lock()
	defer buffer.Mutex.Unlock()

	var size int64 = 0
	for _, group := range buffer.EntryGroupMap {
		size += group.getSizeWithoutBufferLock()
	}

	return size
}

func (buffer *RAMBuffer) GetAvailableSize() int64 {
	buffer.Mutex.Lock()
	defer buffer.Mutex.Unlock()

	var size int64 = 0
	for _, group := range buffer.EntryGroupMap {
		size += group.getSizeWithoutBufferLock()
	}

	return buffer.SizeCap - size
}

func (buffer *RAMBuffer) WaitForSpace(spaceRequired int64) bool {
	buffer.Mutex.Lock()
	if buffer.SizeCap < spaceRequired {
		buffer.Mutex.Unlock()
		return false
	}
	buffer.Mutex.Unlock()

	for {
		buffer.Mutex.Lock()

		var size int64 = 0
		for _, group := range buffer.EntryGroupMap {
			size += group.getSizeWithoutBufferLock()
		}
		avail := buffer.SizeCap - size

		if avail >= spaceRequired {
			buffer.Mutex.Unlock()
			return true
		}

		// wait for availability
		buffer.Condition.Wait()
		buffer.Mutex.Unlock()
	}
}

func (buffer *RAMBuffer) CreateEntryGroup(name string) BufferEntryGroup {
	buffer.Mutex.Lock()
	defer buffer.Mutex.Unlock()

	group := NewRAMBufferEntryGroup(buffer, name)
	buffer.EntryGroupMap[name] = group

	return group
}

func (buffer *RAMBuffer) GetEntryGroup(name string) BufferEntryGroup {
	buffer.Mutex.Lock()
	defer buffer.Mutex.Unlock()

	if group, ok := buffer.EntryGroupMap[name]; ok {
		return group
	}

	return nil
}

func (buffer *RAMBuffer) GetEntryGroups() []BufferEntryGroup {
	buffer.Mutex.Lock()
	defer buffer.Mutex.Unlock()

	groups := []BufferEntryGroup{}

	for _, group := range buffer.EntryGroupMap {
		groups = append(groups, group)
	}

	return groups
}

func (buffer *RAMBuffer) DeleteEntryGroup(name string) {
	buffer.Mutex.Lock()

	if group, ok := buffer.EntryGroupMap[name]; ok {
		group.deleteAllEntriesWithoutBufferLock()
	}

	delete(buffer.EntryGroupMap, name)

	buffer.Condition.Broadcast()
	buffer.Mutex.Unlock()
}

func (buffer *RAMBuffer) DeleteAllEntryGroups() {
	buffer.Mutex.Lock()

	for _, group := range buffer.EntryGroupMap {
		group.deleteAllEntriesWithoutBufferLock()
	}

	buffer.EntryGroupMap = map[string]*RAMBufferEntryGroup{}

	buffer.Condition.Broadcast()
	buffer.Mutex.Unlock()
}
