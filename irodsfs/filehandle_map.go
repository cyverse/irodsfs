package irodsfs

import (
	"fmt"
	"strings"
	"sync"
)

type FileHandleMap struct {
	mutex       sync.Mutex
	fileHandles map[string]*FileHandle // ID-handle mapping
	filePathID  map[string][]string    // path-IDs mappings
}

// NewFileHandleMap creates a new FileHandleMap
func NewFileHandleMap() *FileHandleMap {
	return &FileHandleMap{
		mutex:       sync.Mutex{},
		fileHandles: map[string]*FileHandle{},
		filePathID:  map[string][]string{},
	}
}

// Add registers a file handle
func (fileHandleMap *FileHandleMap) Add(handle *FileHandle) {
	fileHandleMap.mutex.Lock()
	defer fileHandleMap.mutex.Unlock()

	handleID := handle.fileHandle.GetID()
	handlePath := handle.fileHandle.GetEntry().Path

	fileHandleMap.fileHandles[handleID] = handle
	if ids, ok := fileHandleMap.filePathID[handlePath]; ok {
		fileHandleMap.filePathID[handlePath] = append(ids, handleID)
	} else {
		fileHandleMap.filePathID[handlePath] = []string{handleID}
	}
}

// Remove deletes a file handle registered using ID
func (fileHandleMap *FileHandleMap) Remove(id string) {
	fileHandleMap.mutex.Lock()
	defer fileHandleMap.mutex.Unlock()

	handle := fileHandleMap.fileHandles[id]
	if handle != nil {
		delete(fileHandleMap.fileHandles, id)

		handlePath := handle.fileHandle.GetEntry().Path
		if ids, ok := fileHandleMap.filePathID[handlePath]; ok {
			newIDs := []string{}
			for _, handleID := range ids {
				if handleID != id {
					newIDs = append(newIDs, handleID)
				}
			}

			if len(newIDs) > 0 {
				fileHandleMap.filePathID[handlePath] = newIDs
			} else {
				delete(fileHandleMap.filePathID, handlePath)
			}
		}
	}
}

// PopAll pops all file handles registered (clear) and returns
func (fileHandleMap *FileHandleMap) PopAll() []*FileHandle {
	fileHandleMap.mutex.Lock()
	defer fileHandleMap.mutex.Unlock()

	handles := []*FileHandle{}
	for _, handle := range fileHandleMap.fileHandles {
		handles = append(handles, handle)
	}

	// clear
	fileHandleMap.fileHandles = map[string]*FileHandle{}
	fileHandleMap.filePathID = map[string][]string{}

	return handles
}

// Clear clears all file handles registered
func (fileHandleMap *FileHandleMap) Clear() {
	fileHandleMap.mutex.Lock()
	defer fileHandleMap.mutex.Unlock()

	fileHandleMap.fileHandles = map[string]*FileHandle{}
	fileHandleMap.filePathID = map[string][]string{}
}

// List lists all file handles registered
func (fileHandleMap *FileHandleMap) List() []*FileHandle {
	fileHandleMap.mutex.Lock()
	defer fileHandleMap.mutex.Unlock()

	handles := []*FileHandle{}
	for _, handle := range fileHandleMap.fileHandles {
		handles = append(handles, handle)
	}

	return handles
}

// Get returns a file handle registered using ID
func (fileHandleMap *FileHandleMap) Get(id string) *FileHandle {
	fileHandleMap.mutex.Lock()
	defer fileHandleMap.mutex.Unlock()

	return fileHandleMap.fileHandles[id]
}

// Pop pops a file handle registered using ID and returns the handle
func (fileHandleMap *FileHandleMap) Pop(id string) *FileHandle {
	fileHandleMap.mutex.Lock()
	defer fileHandleMap.mutex.Unlock()

	handle := fileHandleMap.fileHandles[id]
	if handle != nil {
		delete(fileHandleMap.fileHandles, id)

		handlePath := handle.fileHandle.GetEntry().Path
		if ids, ok := fileHandleMap.filePathID[handlePath]; ok {
			newIDs := []string{}
			for _, handleID := range ids {
				if handleID != id {
					newIDs = append(newIDs, handleID)
				}
			}

			if len(newIDs) > 0 {
				fileHandleMap.filePathID[handlePath] = newIDs
			} else {
				delete(fileHandleMap.filePathID, handlePath)
			}
		}
	}

	return handle
}

// ListByPath returns file handles registered using path
func (fileHandleMap *FileHandleMap) ListByPath(path string) []*FileHandle {
	fileHandleMap.mutex.Lock()
	defer fileHandleMap.mutex.Unlock()

	handles := []*FileHandle{}
	if ids, ok := fileHandleMap.filePathID[path]; ok {
		for _, handleID := range ids {
			if handle, ok2 := fileHandleMap.fileHandles[handleID]; ok2 {
				handles = append(handles, handle)
			}
		}
	}
	return handles
}

// ListPathsUnderDir returns paths of file handles under given parent path
func (fileHandleMap *FileHandleMap) ListPathsInDir(parentPath string) []string {
	fileHandleMap.mutex.Lock()
	defer fileHandleMap.mutex.Unlock()

	prefix := parentPath
	if len(prefix) > 1 && !strings.HasSuffix(prefix, "/") {
		prefix = fmt.Sprintf("%s/", prefix)
	}

	paths := []string{}
	// loop over all file handles opened
	for path := range fileHandleMap.filePathID {
		// check if it's sub dirs or files in the dir
		if strings.HasPrefix(path, prefix) {
			paths = append(paths, path)
		}
	}

	return paths
}

// PopByPath pops file handles registered using path and returns the handles
func (fileHandleMap *FileHandleMap) PopByPath(path string) []*FileHandle {
	fileHandleMap.mutex.Lock()
	defer fileHandleMap.mutex.Unlock()

	handles := []*FileHandle{}
	if ids, ok := fileHandleMap.filePathID[path]; ok {
		for _, handleID := range ids {
			if handle, ok2 := fileHandleMap.fileHandles[handleID]; ok2 {
				handles = append(handles, handle)
				delete(fileHandleMap.fileHandles, handleID)
			}
		}

		delete(fileHandleMap.filePathID, path)
	}

	return handles
}
