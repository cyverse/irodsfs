package irodsfs

type FileUpdater struct {
	UpdatedFiles map[int64]*FileUpdated
}

type FileUpdated struct {
	Path string
}

// NewFileUpdater create a new FileUpdater
func NewFileUpdater() *FileUpdater {
	return &FileUpdater{
		UpdatedFiles: map[int64]*FileUpdated{},
	}
}

func (updater *FileUpdater) Add(inode int64, path string) {
	u := &FileUpdated{
		Path: path,
	}

	updater.UpdatedFiles[inode] = u
}

func (updater *FileUpdater) Get(inode int64) (*FileUpdated, bool) {
	u, ok := updater.UpdatedFiles[inode]
	return u, ok
}

func (updater *FileUpdater) Delete(inode int64) {
	delete(updater.UpdatedFiles, inode)
}
