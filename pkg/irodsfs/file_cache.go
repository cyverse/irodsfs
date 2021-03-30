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

	lru "github.com/hashicorp/golang-lru"
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
	Key    string
	Size   int64
	Path   string
	Status FileCacheEntryStatus
}

type FileCache struct {
	StoragePath string
	SizeCap     int64

	// internal
	SizeUsed int64
	LRUCahce *lru.Cache
	Lock     *sync.RWMutex
}

// NewFileCache create a new FileCache
func NewFileCache(storagePath string, sizeCap int64) (*FileCache, error) {
	fileCache := &FileCache{
		StoragePath: storagePath,
		SizeCap:     sizeCap,
		SizeUsed:    0,
		LRUCahce:    nil,
		Lock:        &sync.RWMutex{},
	}

	lruCache, err := lru.NewWithEvict(FileCacheEntryMax, fileCache.onEvicted)
	if err != nil {
		return nil, err
	}
	fileCache.LRUCahce = lruCache

	err = fileCache.createStorage()
	if err != nil {
		return nil, err
	}

	return fileCache, nil
}

func (cache *FileCache) Destroy() {
	cache.LRUCahce.Purge()
}

func (cache *FileCache) onEvicted(key interface{}, value interface{}) {
	// call back
	if value != nil {
		fileCacheEntry := value.(*FileCacheEntry)
		cache.SizeUsed -= fileCacheEntry.Size

		if len(fileCacheEntry.Path) > 0 && fileCacheEntry.Status == FileCacheEntryStatusReady {
			os.Remove(fileCacheEntry.Path)
		}
	}
}

// Put puts data into file cache
func (cache *FileCache) Put(key string, val []byte) error {
	return cache.PutReader(key, bytes.NewReader(val))
}

// PutReader puts data into file cache
func (cache *FileCache) PutReader(key string, reader io.Reader) error {
	cache.Lock.Lock()
	defer cache.Lock.Unlock()

	fileCacheEntry := &FileCacheEntry{
		Key:    key,
		Size:   0,
		Path:   "",
		Status: FileCacheEntryStatusWriting,
	}

	cache.LRUCahce.Add(key, fileCacheEntry)

	filepath, filesize, err := cache.writeFile(key, reader)
	if err != nil {
		return err
	}

	cache.SizeUsed += filesize

	err = cache.evict()
	if err != nil {
		return err
	}

	fileCacheEntry.Size = filesize
	fileCacheEntry.Path = filepath
	fileCacheEntry.Status = FileCacheEntryStatusReady

	cache.LRUCahce.Add(key, fileCacheEntry)
	return nil
}

// HasCache checks existance of cache
func (cache *FileCache) HasCache(key string) (bool, FileCacheEntryStatus) {
	cache.Lock.RLock()
	defer cache.Lock.RUnlock()

	if cacheEntry, ok := cache.LRUCahce.Get(key); ok {
		return true, cacheEntry.(*FileCacheEntry).Status
	}

	return false, FileCacheEntryStatusInvalid
}

// Get gets data in file cache
func (cache *FileCache) Get(key string) ([]byte, error) {
	reader, err := cache.GetReader(key)
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
func (cache *FileCache) GetReader(key string) (io.ReadCloser, error) {
	cache.Lock.RLock()
	defer cache.Lock.RUnlock()

	cacheEntry, ok := cache.LRUCahce.Get(key)
	if !ok {
		// no cache
		return nil, fmt.Errorf("no cache found")
	}

	fileCacheEntry := cacheEntry.(*FileCacheEntry)

	if fileCacheEntry.Status != FileCacheEntryStatusReady {
		return nil, fmt.Errorf("cache status is not ready - %s", fileCacheEntry.Status)
	}

	_, _, reader, err := cache.readFile(key)
	return reader, err
}

// Purge clears all cache
func (cache *FileCache) Purge() {
	cache.LRUCahce.Purge()
}

func (cache *FileCache) writeFile(key string, reader io.Reader) (string, int64, error) {
	filename := cache.hashValue(key)
	filepath := path.Join(cache.StoragePath, filename)

	file, err := os.Create(filepath)
	if err != nil {
		return "", 0, err
	}

	writtenSize, err := io.Copy(file, reader)
	if err != nil {
		return "", 0, err
	}

	err = file.Close()
	if err != nil {
		return "", 0, err
	}

	return filepath, writtenSize, nil
}

func (cache *FileCache) readFile(key string) (string, int64, io.ReadCloser, error) {
	filename := cache.hashValue(key)
	filepath := path.Join(cache.StoragePath, filename)

	fileinfo, err := os.Stat(filepath)
	if err != nil {
		return "", 0, nil, err
	}
	if fileinfo.IsDir() {
		return "", 0, nil, fmt.Errorf("cache file %s is not a file", filepath)
	}

	file, err := os.Open(filepath)
	if err != nil {
		return "", 0, nil, err
	}

	return filepath, fileinfo.Size(), file, nil
}

func (cache *FileCache) evict() error {
	for cache.SizeUsed > cache.SizeCap {
		_, cacheEntry, ok := cache.LRUCahce.RemoveOldest()
		if ok {
			cache.SizeUsed -= cacheEntry.(*FileCacheEntry).Size
		}
	}

	return nil
}

func (cache *FileCache) hashValue(text string) string {
	hashcode := sha256.Sum256([]byte(text))
	return fmt.Sprintf("%x", hashcode)
}

func (cache *FileCache) createStorage() error {
	fileinfo, err := os.Stat(cache.StoragePath)
	if err != nil {
		if os.IsNotExist(err) {
			os.MkdirAll(cache.StoragePath, 0766)
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

	if lasterr != nil {
		return lasterr
	}

	return nil
}
