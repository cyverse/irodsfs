package irodsfs

// FileMetaUpdater records updates on file metadata temporarily.
// So subsequent fs operations find them to renew info.
type FileMetaUpdater struct {
	UpdatedFiles map[int64]*FileMetaUpdated
}

type FileMetaUpdated struct {
	Path string
}

// NewFileMetaUpdater create a new FileMetaUpdater
func NewFileMetaUpdater() *FileMetaUpdater {
	return &FileMetaUpdater{
		UpdatedFiles: map[int64]*FileMetaUpdated{},
	}
}

func (updater *FileMetaUpdater) Add(inode int64, path string) {
	u := &FileMetaUpdated{
		Path: path,
	}

	updater.UpdatedFiles[inode] = u
}

func (updater *FileMetaUpdater) Get(inode int64) (*FileMetaUpdated, bool) {
	u, ok := updater.UpdatedFiles[inode]
	return u, ok
}

func (updater *FileMetaUpdater) Delete(inode int64) {
	delete(updater.UpdatedFiles, inode)
}
