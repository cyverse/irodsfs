package buffer

import (
	"fmt"
	"sync"
	"time"
)

type RAMEntry struct {
	Key          string
	Size         int
	AccessCount  int
	CreationTime time.Time
	Data         []byte
	Mutex        sync.Mutex
}

func NewRAMEntry(buffer *RAMBuffer, group *RAMEntryGroup, key string, data []byte) *RAMEntry {
	return &RAMEntry{
		Key:          key,
		Size:         len(data),
		AccessCount:  0,
		CreationTime: time.Now(),
		Data:         data,
	}
}

func (entry *RAMEntry) GetKey() string {
	return entry.Key
}

func (entry *RAMEntry) GetSize() int {
	return entry.Size
}

func (entry *RAMEntry) GetAccessCount() int {
	entry.Mutex.Lock()
	defer entry.Mutex.Unlock()

	return entry.AccessCount
}

func (entry *RAMEntry) GetCreationTime() time.Time {
	return entry.CreationTime
}

func (entry *RAMEntry) GetData() []byte {
	entry.Mutex.Lock()
	defer entry.Mutex.Unlock()

	entry.AccessCount++
	return entry.Data
}

// RAMEntryGroup defines a group
type RAMEntryGroup struct {
	Buffer *RAMBuffer

	Name     string
	Size     int64
	EntryMap map[string]*RAMEntry

	Mutex sync.Mutex
}

func NewRAMEntryGroup(buffer *RAMBuffer, name string) *RAMEntryGroup {
	return &RAMEntryGroup{
		Buffer: buffer,

		Name:     name,
		Size:     0,
		EntryMap: map[string]*RAMEntry{},
	}
}

func (group *RAMEntryGroup) GetBuffer() Buffer {
	return group.Buffer
}

func (group *RAMEntryGroup) GetName() string {
	return group.Name
}

func (group *RAMEntryGroup) GetEntryCount() int {
	group.Buffer.Mutex.Lock()
	defer group.Buffer.Mutex.Unlock()

	group.Mutex.Lock()
	defer group.Mutex.Unlock()

	return len(group.EntryMap)
}

func (group *RAMEntryGroup) getEntryCountWithoutBufferLock() int {
	group.Mutex.Lock()
	defer group.Mutex.Unlock()

	return len(group.EntryMap)
}

func (group *RAMEntryGroup) GetSize() int64 {
	group.Buffer.Mutex.Lock()
	defer group.Buffer.Mutex.Unlock()

	group.Mutex.Lock()
	defer group.Mutex.Unlock()

	return group.Size
}

func (group *RAMEntryGroup) getSizeWithoutBufferLock() int64 {
	group.Mutex.Lock()
	defer group.Mutex.Unlock()

	return group.Size
}

func (group *RAMEntryGroup) GetEntryKeys() []string {
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

func (group *RAMEntryGroup) DeleteAllEntries() {
	group.Buffer.Mutex.Lock()
	group.Mutex.Lock()

	for _, entry := range group.EntryMap {
		group.Size -= int64(entry.GetSize())
	}

	group.EntryMap = map[string]*RAMEntry{}

	group.Mutex.Unlock()
	group.Buffer.Condition.Broadcast()
	group.Buffer.Mutex.Unlock()
}

func (group *RAMEntryGroup) deleteAllEntriesWithoutBufferLock() {
	group.Mutex.Lock()
	defer group.Mutex.Unlock()

	for _, entry := range group.EntryMap {
		group.Size -= int64(entry.GetSize())
	}

	group.EntryMap = map[string]*RAMEntry{}
}

func (group *RAMEntryGroup) CreateEntry(key string, data []byte) (Entry, error) {
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

			entry := NewRAMEntry(group.Buffer, group, key, data)
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

func (group *RAMEntryGroup) GetEntry(key string) Entry {
	group.Buffer.Mutex.Lock()
	defer group.Buffer.Mutex.Unlock()

	group.Mutex.Lock()
	defer group.Mutex.Unlock()

	if entry, ok := group.EntryMap[key]; ok {
		return entry
	}

	return nil
}

func (group *RAMEntryGroup) DeleteEntry(key string) {
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

func (group *RAMEntryGroup) PopEntry(key string) Entry {
	group.Buffer.Mutex.Lock()
	group.Mutex.Lock()

	var returnEntry Entry = nil
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
	EntryGroupMap map[string]*RAMEntryGroup

	Mutex     *sync.Mutex
	Condition *sync.Cond
}

func NewRAMBuffer(sizeCap int64) *RAMBuffer {
	mutex := sync.Mutex{}
	return &RAMBuffer{
		SizeCap:       sizeCap,
		EntryGroupMap: map[string]*RAMEntryGroup{},
		Mutex:         &mutex,
		Condition:     sync.NewCond(&mutex),
	}
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

func (buffer *RAMBuffer) CreateEntryGroup(name string) EntryGroup {
	buffer.Mutex.Lock()
	defer buffer.Mutex.Unlock()

	group := NewRAMEntryGroup(buffer, name)
	buffer.EntryGroupMap[name] = group

	return group
}

func (buffer *RAMBuffer) GetEntryGroup(name string) EntryGroup {
	buffer.Mutex.Lock()
	defer buffer.Mutex.Unlock()

	if group, ok := buffer.EntryGroupMap[name]; ok {
		return group
	}

	return nil
}

func (buffer *RAMBuffer) GetEntryGroups() []EntryGroup {
	buffer.Mutex.Lock()
	defer buffer.Mutex.Unlock()

	groups := []EntryGroup{}

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

	buffer.EntryGroupMap = map[string]*RAMEntryGroup{}

	buffer.Condition.Broadcast()
	buffer.Mutex.Unlock()
}
