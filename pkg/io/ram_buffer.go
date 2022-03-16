package io

import (
	"fmt"
	"sync"
	"time"
)

type RAMBufferEntry struct {
	key          string
	size         int
	accessCount  int
	creationTime time.Time
	data         []byte
	mutex        sync.Mutex
}

func NewRAMBufferEntry(key string, data []byte) *RAMBufferEntry {
	dataCopy := make([]byte, len(data))
	copy(dataCopy, data)

	return &RAMBufferEntry{
		key:          key,
		size:         len(data),
		accessCount:  0,
		creationTime: time.Now(),
		data:         dataCopy,
	}
}

func (entry *RAMBufferEntry) GetKey() string {
	return entry.key
}

func (entry *RAMBufferEntry) GetSize() int {
	return entry.size
}

func (entry *RAMBufferEntry) GetAccessCount() int {
	entry.mutex.Lock()
	defer entry.mutex.Unlock()

	return entry.accessCount
}

func (entry *RAMBufferEntry) GetCreationTime() time.Time {
	return entry.creationTime
}

func (entry *RAMBufferEntry) GetData() []byte {
	entry.mutex.Lock()
	defer entry.mutex.Unlock()

	entry.accessCount++
	return entry.data
}

// RAMBufferEntryGroup defines a group
type RAMBufferEntryGroup struct {
	buffer *RAMBuffer

	name     string
	size     int64
	entryMap map[string]*RAMBufferEntry

	mutex sync.Mutex
}

func NewRAMBufferEntryGroup(buffer *RAMBuffer, name string) *RAMBufferEntryGroup {
	return &RAMBufferEntryGroup{
		buffer: buffer,

		name:     name,
		size:     0,
		entryMap: map[string]*RAMBufferEntry{},
	}
}

func (group *RAMBufferEntryGroup) GetBuffer() Buffer {
	return group.buffer
}

func (group *RAMBufferEntryGroup) GetName() string {
	return group.name
}

func (group *RAMBufferEntryGroup) GetEntryCount() int {
	group.buffer.mutex.Lock()
	defer group.buffer.mutex.Unlock()

	group.mutex.Lock()
	defer group.mutex.Unlock()

	return len(group.entryMap)
}

func (group *RAMBufferEntryGroup) getEntryCountWithoutBufferLock() int {
	group.mutex.Lock()
	defer group.mutex.Unlock()

	return len(group.entryMap)
}

func (group *RAMBufferEntryGroup) GetSize() int64 {
	group.buffer.mutex.Lock()
	defer group.buffer.mutex.Unlock()

	group.mutex.Lock()
	defer group.mutex.Unlock()

	return group.size
}

func (group *RAMBufferEntryGroup) getSizeWithoutBufferLock() int64 {
	group.mutex.Lock()
	defer group.mutex.Unlock()

	return group.size
}

func (group *RAMBufferEntryGroup) GetEntryKeys() []string {
	group.buffer.mutex.Lock()
	defer group.buffer.mutex.Unlock()

	group.mutex.Lock()
	defer group.mutex.Unlock()

	keys := []string{}

	for key := range group.entryMap {
		keys = append(keys, key)
	}
	return keys
}

func (group *RAMBufferEntryGroup) DeleteAllEntries() {
	group.buffer.mutex.Lock()
	group.mutex.Lock()

	for _, entry := range group.entryMap {
		group.size -= int64(entry.GetSize())
	}

	group.entryMap = map[string]*RAMBufferEntry{}

	group.mutex.Unlock()
	group.buffer.condition.Broadcast()
	group.buffer.mutex.Unlock()
}

func (group *RAMBufferEntryGroup) deleteAllEntriesWithoutBufferLock() {
	group.mutex.Lock()
	defer group.mutex.Unlock()

	for _, entry := range group.entryMap {
		group.size -= int64(entry.GetSize())
	}

	group.entryMap = map[string]*RAMBufferEntry{}
}

func (group *RAMBufferEntryGroup) CreateEntry(key string, data []byte) (BufferEntry, error) {
	group.buffer.mutex.Lock()
	if group.buffer.sizeCap < int64(len(data)) {
		group.buffer.mutex.Unlock()
		return nil, fmt.Errorf("requested data %d is larger than size cap %d", len(data), group.buffer.sizeCap)
	}
	group.buffer.mutex.Unlock()

	for {
		group.buffer.mutex.Lock()

		var size int64 = 0
		for _, group := range group.buffer.entryGroupMap {
			size += group.getSizeWithoutBufferLock()
		}
		avail := group.buffer.sizeCap - size

		if avail >= int64(len(data)) {
			group.mutex.Lock()

			entry := NewRAMBufferEntry(key, data)
			group.entryMap[key] = entry
			group.size += int64(len(data))

			group.mutex.Unlock()
			group.buffer.mutex.Unlock()
			return entry, nil
		}

		// wait for availability
		group.buffer.condition.Wait()
		group.buffer.mutex.Unlock()
	}
}

func (group *RAMBufferEntryGroup) GetEntry(key string) BufferEntry {
	group.buffer.mutex.Lock()
	defer group.buffer.mutex.Unlock()

	group.mutex.Lock()
	defer group.mutex.Unlock()

	if entry, ok := group.entryMap[key]; ok {
		return entry
	}

	return nil
}

func (group *RAMBufferEntryGroup) DeleteEntry(key string) {
	group.buffer.mutex.Lock()
	group.mutex.Lock()

	if entry, ok := group.entryMap[key]; ok {
		group.size -= int64(entry.GetSize())
	}

	delete(group.entryMap, key)

	group.mutex.Unlock()
	group.buffer.condition.Broadcast()
	group.buffer.mutex.Unlock()
}

func (group *RAMBufferEntryGroup) PopEntry(key string) BufferEntry {
	group.buffer.mutex.Lock()
	group.mutex.Lock()

	var returnEntry BufferEntry = nil
	if entry, ok := group.entryMap[key]; ok {
		group.size -= int64(entry.GetSize())
		returnEntry = entry
	}

	delete(group.entryMap, key)

	group.mutex.Unlock()
	group.buffer.condition.Broadcast()
	group.buffer.mutex.Unlock()

	return returnEntry
}

// RAMBuffer
type RAMBuffer struct {
	sizeCap       int64
	entryGroupMap map[string]*RAMBufferEntryGroup

	mutex     *sync.Mutex
	condition *sync.Cond
}

func NewRAMBuffer(sizeCap int64) *RAMBuffer {
	mutex := sync.Mutex{}
	return &RAMBuffer{
		sizeCap:       sizeCap,
		entryGroupMap: map[string]*RAMBufferEntryGroup{},
		mutex:         &mutex,
		condition:     sync.NewCond(&mutex),
	}
}

func (buffer *RAMBuffer) Release() {
	buffer.DeleteAllEntryGroups()
}

func (buffer *RAMBuffer) GetSizeCap() int64 {
	return buffer.sizeCap
}

func (buffer *RAMBuffer) GetTotalEntries() int {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()

	entries := 0

	for _, group := range buffer.entryGroupMap {
		entries += group.getEntryCountWithoutBufferLock()
	}

	return entries
}

func (buffer *RAMBuffer) GetTotalEntrySize() int64 {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()

	var size int64 = 0
	for _, group := range buffer.entryGroupMap {
		size += group.getSizeWithoutBufferLock()
	}

	return size
}

func (buffer *RAMBuffer) GetAvailableSize() int64 {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()

	var size int64 = 0
	for _, group := range buffer.entryGroupMap {
		size += group.getSizeWithoutBufferLock()
	}

	return buffer.sizeCap - size
}

func (buffer *RAMBuffer) WaitForSpace(spaceRequired int64) bool {
	buffer.mutex.Lock()
	if buffer.sizeCap < spaceRequired {
		buffer.mutex.Unlock()
		return false
	}
	buffer.mutex.Unlock()

	for {
		buffer.mutex.Lock()

		var size int64 = 0
		for _, group := range buffer.entryGroupMap {
			size += group.getSizeWithoutBufferLock()
		}
		avail := buffer.sizeCap - size

		if avail >= spaceRequired {
			buffer.mutex.Unlock()
			return true
		}

		// wait for availability
		buffer.condition.Wait()
		buffer.mutex.Unlock()
	}
}

func (buffer *RAMBuffer) CreateEntryGroup(name string) BufferEntryGroup {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()

	group := NewRAMBufferEntryGroup(buffer, name)
	buffer.entryGroupMap[name] = group

	return group
}

func (buffer *RAMBuffer) GetEntryGroup(name string) BufferEntryGroup {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()

	if group, ok := buffer.entryGroupMap[name]; ok {
		return group
	}

	return nil
}

func (buffer *RAMBuffer) GetEntryGroups() []BufferEntryGroup {
	buffer.mutex.Lock()
	defer buffer.mutex.Unlock()

	groups := []BufferEntryGroup{}

	for _, group := range buffer.entryGroupMap {
		groups = append(groups, group)
	}

	return groups
}

func (buffer *RAMBuffer) DeleteEntryGroup(name string) {
	buffer.mutex.Lock()

	if group, ok := buffer.entryGroupMap[name]; ok {
		group.deleteAllEntriesWithoutBufferLock()
	}

	delete(buffer.entryGroupMap, name)

	buffer.condition.Broadcast()
	buffer.mutex.Unlock()
}

func (buffer *RAMBuffer) DeleteAllEntryGroups() {
	buffer.mutex.Lock()

	for _, group := range buffer.entryGroupMap {
		group.deleteAllEntriesWithoutBufferLock()
	}

	buffer.entryGroupMap = map[string]*RAMBufferEntryGroup{}

	buffer.condition.Broadcast()
	buffer.mutex.Unlock()
}
