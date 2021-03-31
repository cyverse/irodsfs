package irodsfs

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"sync"
	"time"
)

type FileCacheEntryStatus string

const (
	FileCacheEntryStatusInvalid FileCacheEntryStatus = "invalid"
	FileCacheEntryStatusWriting FileCacheEntryStatus = "writing"
	FileCacheEntryStatusReady   FileCacheEntryStatus = "ready"
)

const (
	FileCacheEntryMax int = 1000
)

type FileCacheEntry struct {
	Key          string
	Section      string
	Size         int64
	Status       FileCacheEntryStatus
	AccessCount  int
	CreationTime time.Time
}

type FileCacheSection struct {
	Name        string
	CacheKeyMap map[string]string
	Mutex       *sync.RWMutex
}

func (section *FileCacheSection) Lock() {
	section.Mutex.Lock()
}

func (section *FileCacheSection) RLock() {
	section.Mutex.RLock()
}

func (section *FileCacheSection) Unlock() {
	section.Mutex.Unlock()
}

func (section *FileCacheSection) RUnlock() {
	section.Mutex.RUnlock()
}

type FileCache struct {
	StoragePath string
	SizeCap     int64

	// internal
	SizeUsed   int64
	CacheMap   map[string]*FileCacheEntry
	SectionMap map[string]*FileCacheSection

	Mutex     *sync.RWMutex
	Condition *sync.Cond
}

// NewFileCache create a new FileCache
func NewFileCache(storagePath string, sizeCap int64) (*FileCache, error) {
	fileCache := &FileCache{
		StoragePath: storagePath,
		SizeCap:     sizeCap,
		SizeUsed:    0,
		CacheMap:    map[string]*FileCacheEntry{},
		SectionMap:  map[string]*FileCacheSection{},
		Mutex:       &sync.RWMutex{},
		Condition:   sync.NewCond(&sync.RWMutex{}),
	}

	err := fileCache.createStorage()
	if err != nil {
		return nil, err
	}

	return fileCache, nil
}

func (cache *FileCache) Destroy() {
	cache.Clear()
}

func (cache *FileCache) Lock() {
	cache.Mutex.Lock()
}

func (cache *FileCache) RLock() {
	cache.Mutex.RLock()
}

func (cache *FileCache) Unlock() {
	cache.Mutex.Unlock()
}

func (cache *FileCache) RUnlock() {
	cache.Mutex.RUnlock()
}

// Clear clears all caches
func (cache *FileCache) Clear() {
	cache.Lock()
	defer cache.Unlock()

	for key, _ := range cache.CacheMap {
		delete(cache.CacheMap, key)
	}

	cache.clearStorage()

	for key, _ := range cache.SectionMap {
		delete(cache.SectionMap, key)
	}

	cache.SizeUsed = 0

	cache.Condition.Broadcast()
}

// Clear clears all caches in a section
func (cache *FileCache) ClearSection(section string) {
	cache.Lock()
	defer cache.Unlock()

	if cacheSection, ok := cache.SectionMap[section]; ok {
		// has it
		cacheSection.Lock()
		for key, cacheKey := range cacheSection.CacheKeyMap {
			if cacheEntry, ok := cache.CacheMap[cacheKey]; ok {
				delete(cache.CacheMap, cacheKey)
				cache.SizeUsed -= cacheEntry.Size

				cache.Condition.Broadcast()

				// delete file
				cache.deleteFile(cacheKey)
			}

			delete(cacheSection.CacheKeyMap, key)
		}
		cacheSection.Unlock()
	}
}

// Remove removes data cache
func (cache *FileCache) Remove(section string, key string) {
	cache.Lock()
	defer cache.Unlock()

	if cacheSection, ok := cache.SectionMap[section]; ok {
		// has it
		cacheSection.Lock()
		if cacheKey, ok := cacheSection.CacheKeyMap[key]; ok {
			if cacheEntry, ok2 := cache.CacheMap[cacheKey]; ok2 {
				delete(cache.CacheMap, cacheKey)
				cache.SizeUsed -= cacheEntry.Size

				cache.Condition.Broadcast()

				// delete file
				cache.deleteFile(cacheKey)

			}

			delete(cacheSection.CacheKeyMap, key)
		}
		cacheSection.Unlock()
	}
}

func (cache *FileCache) WaitForSpace(size int64) error {
	availableSpace := cache.GetAvailableSpace()

	if availableSpace < size {
		// not available
		avail, err := cache.EvictBySize(size, 1)
		if err != nil {
			return err
		}

		if avail < size {
			for {
				// wait
				cache.Condition.L.Lock()
				cache.Condition.Wait()
				cache.Condition.L.Unlock()

				availableSpace := cache.GetAvailableSpace()
				if availableSpace >= size {
					break
				}
			}
		}
	}
	return nil
}

// Put puts data into file cache
func (cache *FileCache) Put(section string, key string, val []byte) error {
	return cache.PutReader(section, key, bytes.NewReader(val))
}

// PutReader puts data into file cache
func (cache *FileCache) PutReader(section string, key string, reader io.Reader) error {
	cache.Lock()
	defer cache.Unlock()

	cacheEntry := &FileCacheEntry{
		Key:          key,
		Section:      section,
		Size:         0,
		Status:       FileCacheEntryStatusWriting,
		AccessCount:  0,
		CreationTime: time.Now(),
	}

	cacheKey := cache.makeCacheKey(section, key)

	cache.CacheMap[cacheKey] = cacheEntry

	if cacheSection, ok := cache.SectionMap[section]; ok {
		// section exists
		cacheSection.Lock()
		cacheSection.CacheKeyMap[key] = cacheKey
		cacheSection.Unlock()
	} else {
		cacheSection := &FileCacheSection{
			Name:        section,
			CacheKeyMap: map[string]string{},
			Mutex:       &sync.RWMutex{},
		}

		cacheSection.CacheKeyMap[key] = cacheKey

		cache.SectionMap[section] = cacheSection
	}

	filesize, err := cache.writeFile(cacheKey, reader)
	if err != nil {
		delete(cache.CacheMap, cacheKey)
		return err
	}

	cache.SizeUsed += filesize

	cacheEntry.Size = filesize
	cacheEntry.Status = FileCacheEntryStatusReady
	return nil
}

// GetCacheEntry returns cache entry
func (cache *FileCache) GetCacheEntry(section string, key string) (*FileCacheEntry, bool) {
	cache.RLock()
	defer cache.RUnlock()

	cacheKey := cache.makeCacheKey(section, key)

	if cacheEntry, ok := cache.CacheMap[cacheKey]; ok {
		return cacheEntry, true
	}

	return nil, false
}

// GetCacheSection returns cache section
func (cache *FileCache) GetCacheSection(section string) (*FileCacheSection, bool) {
	cache.RLock()
	defer cache.RUnlock()

	if cacheSection, ok := cache.SectionMap[section]; ok {
		return cacheSection, true
	}

	return nil, false
}

// Get gets data in file cache
func (cache *FileCache) Get(section string, key string) ([]byte, error) {
	reader, _, err := cache.GetReader(section, key)
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

// Get gets data in file cache
func (cache *FileCache) GetReader(section string, key string) (io.ReadCloser, int64, error) {
	cache.RLock()
	defer cache.RUnlock()

	cacheKey := cache.makeCacheKey(section, key)

	cacheEntry, ok := cache.CacheMap[cacheKey]
	if !ok {
		// no cache
		return nil, 0, fmt.Errorf("no cache found")
	}

	if cacheEntry.Status != FileCacheEntryStatusReady {
		return nil, 0, fmt.Errorf("cache status is not ready - %s", cacheEntry.Status)
	}

	cacheEntry.AccessCount++

	reader, size, err := cache.readFile(cacheKey)
	return reader, size, err
}

func (cache *FileCache) GetSizeUsed() int64 {
	cache.RLock()
	defer cache.RUnlock()

	return cache.SizeUsed
}

func (cache *FileCache) GetAvailableSpace() int64 {
	cache.RLock()
	defer cache.RUnlock()

	return cache.SizeCap - cache.SizeUsed
}

func (cache *FileCache) GetSpaceUsedPercent() float64 {
	cache.RLock()
	defer cache.RUnlock()

	return float64(cache.SizeUsed) / float64(cache.SizeCap)
}

func (cache *FileCache) EvictBySize(sizeRequired int64, minAccessCount int) (int64, error) {
	cache.Lock()
	defer cache.Unlock()

	if cache.SizeCap-cache.SizeUsed < sizeRequired {
		// need space
		cacheEntryArray := []*FileCacheEntry{}
		for _, cacheEntry := range cache.CacheMap {
			if minAccessCount <= cacheEntry.AccessCount {
				cacheEntryArray = append(cacheEntryArray, cacheEntry)
			}
		}

		sortFunc := func(i int, j int) bool {
			e1 := cacheEntryArray[i]
			e2 := cacheEntryArray[j]

			return e1.CreationTime.Before(e2.CreationTime)
		}

		// sort by oldest
		sort.Slice(cacheEntryArray, sortFunc)

		for _, cacheEntry := range cacheEntryArray {
			cacheKey := cache.makeCacheKey(cacheEntry.Section, cacheEntry.Key)

			delete(cache.CacheMap, cacheKey)
			if cacheSection, ok := cache.SectionMap[cacheEntry.Section]; ok {
				delete(cacheSection.CacheKeyMap, cacheEntry.Key)
			}

			cache.SizeUsed -= cacheEntry.Size

			cache.Condition.Broadcast()

			// delete file
			err := cache.deleteFile(cacheKey)
			if err != nil {
				return cache.SizeCap - cache.SizeUsed, err
			}

			if cache.SizeCap-cache.SizeUsed >= sizeRequired {
				return cache.SizeCap - cache.SizeUsed, nil
			}
		}
	}

	return cache.SizeCap - cache.SizeUsed, nil
}

func (cache *FileCache) EvictByAccessCount(minAccessCount int) (int64, error) {
	cache.Lock()
	defer cache.Unlock()

	for _, cacheEntry := range cache.CacheMap {
		if minAccessCount <= cacheEntry.AccessCount {
			cacheKey := cache.makeCacheKey(cacheEntry.Section, cacheEntry.Key)

			delete(cache.CacheMap, cacheKey)
			if cacheSection, ok := cache.SectionMap[cacheEntry.Section]; ok {
				delete(cacheSection.CacheKeyMap, cacheEntry.Key)
			}
			cache.SizeUsed -= cacheEntry.Size

			cache.Condition.Broadcast()

			// delete file
			err := cache.deleteFile(cacheKey)
			if err != nil {
				return cache.SizeCap - cache.SizeUsed, err
			}
		}
	}

	return cache.SizeCap - cache.SizeUsed, nil
}

func (cache *FileCache) writeFile(key string, reader io.Reader) (int64, error) {
	filepath := path.Join(cache.StoragePath, key)

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

func (cache *FileCache) readFile(key string) (io.ReadCloser, int64, error) {
	filepath := path.Join(cache.StoragePath, key)

	fileinfo, err := os.Stat(filepath)
	if err != nil {
		return nil, 0, err
	}
	if fileinfo.IsDir() {
		return nil, 0, fmt.Errorf("cache file %s is not a file", filepath)
	}

	file, err := os.Open(filepath)
	if err != nil {
		return nil, 0, err
	}

	return file, fileinfo.Size(), nil
}

func (cache *FileCache) deleteFile(key string) error {
	filepath := path.Join(cache.StoragePath, key)

	_, err := os.Stat(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	return os.Remove(filepath)
}

func (cache *FileCache) makeCacheKey(section string, key string) string {
	cacheKey := fmt.Sprintf("%s|%s", section, key)
	hashcode := sha256.Sum256([]byte(cacheKey))
	return fmt.Sprintf("%x", hashcode)
}

func (cache *FileCache) createStorage() error {
	fileinfo, err := os.Stat(cache.StoragePath)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(cache.StoragePath, 0766)
			return nil
		} else {
			return err
		}
	}

	if !fileinfo.IsDir() {
		return fmt.Errorf("cache storage %s is not a directory", cache.StoragePath)
	}

	// clear existing caches
	err = cache.clearStorage()
	if err != nil {
		return err
	}

	return nil
}

func (cache *FileCache) clearStorage() error {
	dirEntries, err := ioutil.ReadDir(cache.StoragePath)
	if err != nil {
		return err
	}

	var lasterr error
	for _, entry := range dirEntries {
		path := path.Join(cache.StoragePath, entry.Name())
		err := os.RemoveAll(path)
		if err != nil {
			lasterr = err
		}
	}

	return lasterr
}
