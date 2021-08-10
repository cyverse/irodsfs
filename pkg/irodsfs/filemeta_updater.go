package irodsfs

// FileMetaUpdater holds updates on file metadata temporarily.
// So subsequent fs operations find them to refresh metadata.
type FileMetaUpdater struct {
	UpdatedFiles map[int64]*FileMetaUpdated
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

	updater.UpdatedFiles[inode] = u
}

// Get returns the update on a file/directory with the inode
func (updater *FileMetaUpdater) Get(inode int64) (*FileMetaUpdated, bool) {
	u, ok := updater.UpdatedFiles[inode]
	return u, ok
}

// Delete returns the update on a file/directory with the inode
func (updater *FileMetaUpdater) Delete(inode int64) {
	delete(updater.UpdatedFiles, inode)
}

// Pop pops the update on a file/directory with the inode
func (updater *FileMetaUpdater) Pop(inode int64) (*FileMetaUpdated, bool) {
	if u, ok := updater.UpdatedFiles[inode]; ok {
		delete(updater.UpdatedFiles, inode)
		return u, ok
	}
	return nil, false
}
