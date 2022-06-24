package irodsfs

import (
	"sync"

	fusefs "github.com/seaweedfs/fuse/fs"
)

// FileMetaUpdater holds updates on file metadata temporarily.
// So subsequent fs operations find them to refresh metadata.
type FileMetaUpdater struct {
	updatedFiles map[int64]*FileMetaUpdated
	mutex        sync.Mutex
}

// FileMetaUpdated holds information that is updated
type FileMetaUpdated struct {
	Path string
}

// NewFileMetaUpdater create a new FileMetaUpdater
func NewFileMetaUpdater() *FileMetaUpdater {
	return &FileMetaUpdater{
		updatedFiles: map[int64]*FileMetaUpdated{},
	}
}

// Add adds a new update on a file/directory with the inode and path
func (updater *FileMetaUpdater) Add(inode int64, path string) {
	u := &FileMetaUpdated{
		Path: path,
	}

	updater.mutex.Lock()
	defer updater.mutex.Unlock()

	updater.updatedFiles[inode] = u
}

// Get returns the update on a file/directory with the inode
func (updater *FileMetaUpdater) Get(inode int64) (*FileMetaUpdated, bool) {
	updater.mutex.Lock()
	defer updater.mutex.Unlock()

	u, ok := updater.updatedFiles[inode]
	return u, ok
}

// Delete returns the update on a file/directory with the inode
func (updater *FileMetaUpdater) Delete(inode int64) {
	updater.mutex.Lock()
	defer updater.mutex.Unlock()

	delete(updater.updatedFiles, inode)
}

// Pop pops the update on a file/directory with the inode
func (updater *FileMetaUpdater) Pop(inode int64) (*FileMetaUpdated, bool) {
	updater.mutex.Lock()
	defer updater.mutex.Unlock()

	if u, ok := updater.updatedFiles[inode]; ok {
		delete(updater.updatedFiles, inode)
		return u, ok
	}
	return nil, false
}

// Pop pops the update on a file/directory with the inode
func (updater *FileMetaUpdater) Apply(node fusefs.Node) {
	updater.mutex.Lock()
	defer updater.mutex.Unlock()

	switch fnode := node.(type) {
	case *Dir:
		if u, ok := updater.updatedFiles[fnode.inodeID]; ok {
			delete(updater.updatedFiles, fnode.inodeID)

			// update path
			fnode.mutex.Lock()
			fnode.path = u.Path
			fnode.mutex.Unlock()
		}
	case *File:
		if u, ok := updater.updatedFiles[fnode.inodeID]; ok {
			delete(updater.updatedFiles, fnode.inodeID)

			// update path
			fnode.mutex.Lock()
			fnode.path = u.Path
			fnode.mutex.Unlock()
		}
	}
}
