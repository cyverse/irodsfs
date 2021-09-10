package irodsfs

import "sync"

// FileMetaUpdater holds updates on file metadata temporarily.
// So subsequent fs operations find them to refresh metadata.
type FileMetaUpdater struct {
	UpdatedFiles map[int64]*FileMetaUpdated
	Mutex        sync.Mutex
}

// FileMetaUpdated holds information that is updated
type FileMetaUpdated struct {
	Path string
}

// NewFileMetaUpdater create a new FileMetaUpdater
func NewFileMetaUpdater() *FileMetaUpdater {
	return &FileMetaUpdater{
		UpdatedFiles: map[int64]*FileMetaUpdated{},
	}
}

// Add adds a new update on a file/directory with the inode and path
func (updater *FileMetaUpdater) Add(inode int64, path string) {
	u := &FileMetaUpdated{
		Path: path,
	}

	updater.Mutex.Lock()
	defer updater.Mutex.Unlock()

	updater.UpdatedFiles[inode] = u
}

// Get returns the update on a file/directory with the inode
func (updater *FileMetaUpdater) Get(inode int64) (*FileMetaUpdated, bool) {
	updater.Mutex.Lock()
	defer updater.Mutex.Unlock()

	u, ok := updater.UpdatedFiles[inode]
	return u, ok
}

// Delete returns the update on a file/directory with the inode
func (updater *FileMetaUpdater) Delete(inode int64) {
	updater.Mutex.Lock()
	defer updater.Mutex.Unlock()

	delete(updater.UpdatedFiles, inode)
}

// Pop pops the update on a file/directory with the inode
func (updater *FileMetaUpdater) Pop(inode int64) (*FileMetaUpdated, bool) {
	updater.Mutex.Lock()
	defer updater.Mutex.Unlock()

	if u, ok := updater.UpdatedFiles[inode]; ok {
		delete(updater.UpdatedFiles, inode)
		return u, ok
	}
	return nil, false
}
