package irodsfs

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sync"
	"time"
)

type FileBufferEntryStatus string

const (
	FileBufferEntryStatusInvalid FileBufferEntryStatus = "invalid"
	FileBufferEntryStatusWriting FileBufferEntryStatus = "writing"
	FileBufferEntryStatusReady   FileBufferEntryStatus = "ready"
)

const (
	FileBufferEntryMax int = 1000
)

// FileBufferEntry is an entry in FileBuffer
type FileBufferEntry struct {
	Key          string
	Section      string
	Size         int64
	Status       FileBufferEntryStatus
	AccessCount  int
	CreationTime time.Time
}

// FileBufferSection defines a section in FileBuffer
type FileBufferSection struct {
	Name   string
	KeyMap map[string]string
	Mutex  *sync.RWMutex
}

func (section *FileBufferSection) Lock() {
	section.Mutex.Lock()
}

func (section *FileBufferSection) RLock() {
	section.Mutex.RLock()
}

func (section *FileBufferSection) Unlock() {
	section.Mutex.Unlock()
}

func (section *FileBufferSection) RUnlock() {
	section.Mutex.RUnlock()
}

type FileBuffer struct {
	StoragePath string
	SizeCap     int64

	// internal
	SizeUsed   int64
	EntryMap   map[string]*FileBufferEntry
	SectionMap map[string]*FileBufferSection

	Mutex     *sync.RWMutex
	Condition *sync.Cond
}

// NewFileBuffer create a new FileBuffer
func NewFileBuffer(storagePath string, sizeCap int64) (*FileBuffer, error) {
	fileBuffer := &FileBuffer{
		StoragePath: storagePath,
		SizeCap:     sizeCap,
		SizeUsed:    0,
		EntryMap:    map[string]*FileBufferEntry{},
		SectionMap:  map[string]*FileBufferSection{},
		Mutex:       &sync.RWMutex{},
		Condition:   sync.NewCond(&sync.RWMutex{}),
	}

	err := fileBuffer.createStorage()
	if err != nil {
		return nil, err
	}

	return fileBuffer, nil
}

func (buffer *FileBuffer) Destroy() {
	buffer.Clear()
}

func (buffer *FileBuffer) Lock() {
	buffer.Mutex.Lock()
}

func (buffer *FileBuffer) RLock() {
	buffer.Mutex.RLock()
}

func (buffer *FileBuffer) Unlock() {
	buffer.Mutex.Unlock()
}

func (buffer *FileBuffer) RUnlock() {
	buffer.Mutex.RUnlock()
}

// Clear clears all bufferred data
func (buffer *FileBuffer) Clear() {
	buffer.Lock()
	defer buffer.Unlock()

	for key := range buffer.EntryMap {
		delete(buffer.EntryMap, key)
	}

	buffer.clearStorage()

	for key := range buffer.SectionMap {
		delete(buffer.SectionMap, key)
	}

	buffer.SizeUsed = 0

	buffer.Condition.Broadcast()
}

// Clear clears all buffers in a section
func (buffer *FileBuffer) ClearSection(section string) {
	buffer.Lock()
	defer buffer.Unlock()

	if bufferSection, ok := buffer.SectionMap[section]; ok {
		// has it
		bufferSection.Lock()
		for key, bufferKey := range bufferSection.KeyMap {
			if bufferEntry, ok := buffer.EntryMap[bufferKey]; ok {
				delete(buffer.EntryMap, bufferKey)
				buffer.SizeUsed -= bufferEntry.Size

				buffer.Condition.Broadcast()

				// delete file
				buffer.deleteFile(bufferKey)
			}

			delete(bufferSection.KeyMap, key)
		}
		bufferSection.Unlock()
	}
}

// Remove removes data buffer
func (buffer *FileBuffer) Remove(section string, key string) {
	buffer.Lock()
	defer buffer.Unlock()

	if bufferSection, ok := buffer.SectionMap[section]; ok {
		// has it
		bufferSection.Lock()
		if bufferKey, ok := bufferSection.KeyMap[key]; ok {
			if bufferEntry, ok2 := buffer.EntryMap[bufferKey]; ok2 {
				delete(buffer.EntryMap, bufferKey)
				buffer.SizeUsed -= bufferEntry.Size

				buffer.Condition.Broadcast()

				// delete file
				buffer.deleteFile(bufferKey)

			}

			delete(bufferSection.KeyMap, key)
		}
		bufferSection.Unlock()
	}
}

func (buffer *FileBuffer) WaitForSpace(size int64) error {
	availableSpace := buffer.GetAvailableSpace()

	if availableSpace < size {
		// not available
		avail, err := buffer.EvictUsed(1)
		if err != nil {
			return err
		}

		if avail < size {
			for {
				// wait
				buffer.Condition.L.Lock()
				buffer.Condition.Wait()
				buffer.Condition.L.Unlock()

				availableSpace := buffer.GetAvailableSpace()
				if availableSpace >= size {
					break
				}
			}
		}
	}
	return nil
}

// Put puts data into file buffer
func (buffer *FileBuffer) Put(section string, key string, val []byte) error {
	return buffer.PutReader(section, key, bytes.NewReader(val))
}

// PutReader puts data into file buffer
func (buffer *FileBuffer) PutReader(section string, key string, reader io.Reader) error {
	buffer.Lock()
	defer buffer.Unlock()

	bufferEntry := &FileBufferEntry{
		Key:          key,
		Section:      section,
		Size:         0,
		Status:       FileBufferEntryStatusWriting,
		AccessCount:  0,
		CreationTime: time.Now(),
	}

	bufferKey := buffer.makeBufferKey(section, key)

	buffer.EntryMap[bufferKey] = bufferEntry

	if bufferSection, ok := buffer.SectionMap[section]; ok {
		// section exists
		bufferSection.Lock()
		bufferSection.KeyMap[key] = bufferKey
		bufferSection.Unlock()
	} else {
		bufferSection := &FileBufferSection{
			Name:   section,
			KeyMap: map[string]string{},
			Mutex:  &sync.RWMutex{},
		}

		bufferSection.KeyMap[key] = bufferKey

		buffer.SectionMap[section] = bufferSection
	}

	filesize, err := buffer.writeFile(bufferKey, reader)
	if err != nil {
		delete(buffer.EntryMap, bufferKey)
		return err
	}

	buffer.SizeUsed += filesize

	bufferEntry.Size = filesize
	bufferEntry.Status = FileBufferEntryStatusReady
	return nil
}

// GetBufferEntry returns buffer entry
func (buffer *FileBuffer) GetBufferEntry(section string, key string) (*FileBufferEntry, bool) {
	buffer.RLock()
	defer buffer.RUnlock()

	bufferKey := buffer.makeBufferKey(section, key)

	if bufferEntry, ok := buffer.EntryMap[bufferKey]; ok {
		return bufferEntry, true
	}

	return nil, false
}

// GetBufferSection returns buffer section
func (buffer *FileBuffer) GetBufferSection(section string) (*FileBufferSection, bool) {
	buffer.RLock()
	defer buffer.RUnlock()

	if bufferSection, ok := buffer.SectionMap[section]; ok {
		return bufferSection, true
	}

	return nil, false
}

// Get gets data in file buffer
func (buffer *FileBuffer) Get(section string, key string) ([]byte, error) {
	reader, _, err := buffer.GetReader(section, key)
	if err != nil {
		return nil, err
	}

	dataBytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	err = reader.Close()
	if err != nil {
		return nil, err
	}

	return dataBytes, nil
}

// GetReader gets data in file buffer
func (buffer *FileBuffer) GetReader(section string, key string) (io.ReadCloser, int64, error) {
	buffer.RLock()
	defer buffer.RUnlock()

	bufferKey := buffer.makeBufferKey(section, key)

	bufferEntry, ok := buffer.EntryMap[bufferKey]
	if !ok {
		// no buffer
		return nil, 0, fmt.Errorf("failed to find a buffer for key %s", bufferKey)
	}

	if bufferEntry.Status != FileBufferEntryStatusReady {
		return nil, 0, fmt.Errorf("buffer status is not ready - %s", bufferEntry.Status)
	}

	bufferEntry.AccessCount++

	reader, size, err := buffer.readFile(bufferKey)
	return reader, size, err
}

// Pop gets data in file buffer and deletes
func (buffer *FileBuffer) Pop(section string, key string) ([]byte, error) {
	reader, _, err := buffer.PopReader(section, key)
	if err != nil {
		return nil, err
	}

	dataBytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	err = reader.Close()
	if err != nil {
		return nil, err
	}

	return dataBytes, nil
}

// PopReader gets data in file buffer and deletes
func (buffer *FileBuffer) PopReader(section string, key string) (io.ReadCloser, int64, error) {
	buffer.RLock()
	defer buffer.RUnlock()

	bufferKey := buffer.makeBufferKey(section, key)

	bufferEntry, ok := buffer.EntryMap[bufferKey]
	if !ok {
		// no buffer
		return nil, 0, fmt.Errorf("failed to find a buffer for key %s", bufferKey)
	}

	if bufferEntry.Status != FileBufferEntryStatusReady {
		return nil, 0, fmt.Errorf("buffer status is not ready - %s", bufferEntry.Status)
	}

	bufferEntry.AccessCount++

	reader, size, err := buffer.readFile(bufferKey)
	if err == nil {
		// delete
		delete(buffer.EntryMap, bufferKey)
		if bufferSection, ok := buffer.SectionMap[bufferEntry.Section]; ok {
			delete(bufferSection.KeyMap, bufferEntry.Key)
		}

		buffer.SizeUsed -= bufferEntry.Size

		// delete file
		buffer.deleteFile(bufferKey)
	}

	return reader, size, err
}

func (buffer *FileBuffer) GetSizeUsed() int64 {
	buffer.RLock()
	defer buffer.RUnlock()

	return buffer.SizeUsed
}

func (buffer *FileBuffer) GetAvailableSpace() int64 {
	buffer.RLock()
	defer buffer.RUnlock()

	return buffer.SizeCap - buffer.SizeUsed
}

func (buffer *FileBuffer) GetSpaceUsedPercent() float64 {
	buffer.RLock()
	defer buffer.RUnlock()

	return float64(buffer.SizeUsed) / float64(buffer.SizeCap)
}

func (buffer *FileBuffer) EvictUsed(minAccessCount int) (int64, error) {
	buffer.Lock()
	defer buffer.Unlock()

	for _, bufferEntry := range buffer.EntryMap {
		if minAccessCount <= bufferEntry.AccessCount {
			bufferKey := buffer.makeBufferKey(bufferEntry.Section, bufferEntry.Key)

			delete(buffer.EntryMap, bufferKey)
			if bufferSection, ok := buffer.SectionMap[bufferEntry.Section]; ok {
				delete(bufferSection.KeyMap, bufferEntry.Key)
			}
			buffer.SizeUsed -= bufferEntry.Size

			buffer.Condition.Broadcast()

			// delete file
			err := buffer.deleteFile(bufferKey)
			if err != nil {
				return buffer.SizeCap - buffer.SizeUsed, err
			}
		}
	}

	return buffer.SizeCap - buffer.SizeUsed, nil
}

func (buffer *FileBuffer) writeFile(key string, reader io.Reader) (int64, error) {
	filepath := path.Join(buffer.StoragePath, key)

	file, err := os.Create(filepath)
	if err != nil {
		return 0, err
	}

	writtenSize, err := io.Copy(file, reader)
	if err != nil {
		return 0, err
	}

	err = file.Close()
	if err != nil {
		return 0, err
	}

	return writtenSize, nil
}

func (buffer *FileBuffer) readFile(key string) (io.ReadCloser, int64, error) {
	filepath := path.Join(buffer.StoragePath, key)

	fileinfo, err := os.Stat(filepath)
	if err != nil {
		return nil, 0, err
	}
	if fileinfo.IsDir() {
		return nil, 0, fmt.Errorf("buffer file %s is not a file", filepath)
	}

	file, err := os.Open(filepath)
	if err != nil {
		return nil, 0, err
	}

	return file, fileinfo.Size(), nil
}

func (buffer *FileBuffer) deleteFile(key string) error {
	filepath := path.Join(buffer.StoragePath, key)

	_, err := os.Stat(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return os.Remove(filepath)
}

func (buffer *FileBuffer) makeBufferKey(section string, key string) string {
	bufferKey := fmt.Sprintf("%s|%s", section, key)
	hashcode := sha256.Sum256([]byte(bufferKey))
	return fmt.Sprintf("%x", hashcode)
}

func (buffer *FileBuffer) createStorage() error {
	fileinfo, err := os.Stat(buffer.StoragePath)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(buffer.StoragePath, 0766)
			return nil
		} else {
			return err
		}
	}

	if !fileinfo.IsDir() {
		return fmt.Errorf("buffer storage %s is not a directory", buffer.StoragePath)
	}

	// clear existing buffers
	err = buffer.clearStorage()
	if err != nil {
		return err
	}

	return nil
}

func (buffer *FileBuffer) clearStorage() error {
	dirEntries, err := ioutil.ReadDir(buffer.StoragePath)
	if err != nil {
		return err
	}

	var lasterr error
	for _, entry := range dirEntries {
		path := path.Join(buffer.StoragePath, entry.Name())
		err := os.RemoveAll(path)
		if err != nil {
			lasterr = err
		}
	}

	return lasterr
}
