package irodsfs

import (
	"context"
	"path"
	"sync"
	"syscall"

	"github.com/cockroachdb/errors"

	irodsclient_util "github.com/cyverse/go-irodsclient/irods/util"
	"github.com/cyverse/irodsfs-common/irods/vpath"
	irodsfs_common_util "github.com/cyverse/irodsfs-common/util"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
)

// Dir is a directory node
type Dir struct {
	fusefs.Inode

	fs      *IRODSFS
	inodeID uint64
	path    string
	mutex   sync.RWMutex
}

// NewDir creates a new Dir
func NewDir(fs *IRODSFS, inodeID uint64, path string) *Dir {
	return &Dir{
		fs:      fs,
		inodeID: inodeID,
		path:    path,
	}
}

func (dir *Dir) getStableAttr() fusefs.StableAttr {
	return fusefs.StableAttr{
		Mode: uint32(fuse.S_IFDIR),
		Ino:  dir.inodeID,
		Gen:  0,
	}
}

func (dir *Dir) ensureDirIRODSPath(vpathEntry *vpath.VPathEntry) error {
	return ensureVPathEntryIsIRODSDir(dir.fs.fsClient, vpathEntry)
}

func (dir *Dir) ensureIRODSPath(vpathEntry *vpath.VPathEntry) error {
	return ensureVPathEntryIsIRODSEntry(dir.fs.fsClient, vpathEntry)
}

func (dir *Dir) NewSubDirInode(ctx context.Context, inodeID uint64, path string) (*Dir, *fusefs.Inode) {
	subDir := NewDir(dir.fs, inodeID, path)
	subDirInode := dir.NewInode(ctx, subDir, subDir.getStableAttr())

	return subDir, subDirInode
}

func (dir *Dir) NewSubFileInode(ctx context.Context, inodeID uint64, path string) (*File, *fusefs.Inode) {
	subFile := NewFile(dir.fs, inodeID, path)
	subFileInode := dir.NewInode(ctx, subFile, subFile.getStableAttr())

	return subFile, subFileInode
}

// Getattr returns stat of file entry
func (dir *Dir) Getattr(ctx context.Context, fh fusefs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if dir.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(dir.fs.logger)

	operID := dir.fs.GetNextOperationID()
	dir.fs.logger.Infof("Calling Getattr (%d) - %q", operID, dir.path)
	defer dir.fs.logger.Infof("Called Getattr (%d) - %q", operID, dir.path)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		dir.fs.logger.Errorf("failed to get VPath Entry for %q", dir.path)
		return syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		if vpathEntry.Path == dir.path {
			err := dir.fs.setAttrOutForVirtualDirEntry(vpathEntry.VirtualDirEntry, &out.Attr)
			if err != nil {
				dir.fs.logger.Error(err)
				return syscall.EREMOTEIO
			}
			return fusefs.OK
		}
		return syscall.ENOENT
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	return dir.fs.IRODSGetattr(ctx, irodsPath, vpathEntry.ReadOnly, out)
}

// Setattr sets dir attributes
func (dir *Dir) Setattr(ctx context.Context, fh fusefs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if dir.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(dir.fs.logger)

	// intentionally no-op: returning EOPNOTSUPP breaks clients like git clone
	return fusefs.OK
}

// Lookup returns a node for the path
func (dir *Dir) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fusefs.Inode, syscall.Errno) {
	if dir.fs.terminated.Load() {
		return nil, syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(dir.fs.logger)

	targetPath := path.Join(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	dir.fs.logger.Infof("Calling Lookup (%d) - %q", operID, targetPath)
	defer dir.fs.logger.Infof("Called Lookup (%d) - %q", operID, targetPath)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		dir.fs.logger.Errorf("failed to get VPath Entry for %q", targetPath)
		return nil, syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		if vpathEntry.Path == targetPath {
			_, subDirInode := dir.NewSubDirInode(ctx, vpathEntry.VirtualDirEntry.ID, targetPath)
			err := dir.fs.setAttrOutForVirtualDirEntry(vpathEntry.VirtualDirEntry, &out.Attr)
			if err != nil {
				dir.fs.logger.Error(err)
				return nil, syscall.EREMOTEIO
			}

			return subDirInode, fusefs.OK
		}
		return nil, syscall.ENOENT
	}

	// IRODS Dir
	err := dir.ensureIRODSPath(vpathEntry)
	if err != nil {
		dir.fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		dir.fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}

	entryID, entryDir, errno := dir.fs.IRODSLookup(ctx, dir, irodsPath, vpathEntry.ReadOnly, out)
	if errno != fusefs.OK {
		return nil, errno
	}

	inodeID, err := dir.fs.getInodeIDForIRODSEntryID(uint64(entryID))
	if err != nil {
		dir.fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}

	if entryDir {
		_, subDirInode := dir.NewSubDirInode(ctx, inodeID, targetPath)
		return subDirInode, fusefs.OK
	}

	_, subFileInode := dir.NewSubFileInode(ctx, inodeID, targetPath)
	return subFileInode, fusefs.OK
}

// Opendir validates the existance of a dir
func (dir *Dir) Opendir(ctx context.Context) syscall.Errno {
	if dir.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(dir.fs.logger)

	operID := dir.fs.GetNextOperationID()
	dir.fs.logger.Infof("Calling Opendir (%d) - %q", operID, dir.path)
	defer dir.fs.logger.Infof("Called Opendir (%d) - %q", operID, dir.path)

	// intentionally no lock: Rename holds the mutex and calls Opendir, which would deadlock
	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		dir.fs.logger.Errorf("failed to get VPath Entry for %q", dir.path)
		return syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		if vpathEntry.Path == dir.path {
			return fusefs.OK
		}
		return syscall.ENOENT
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	return dir.fs.IRODSOpendir(ctx, irodsPath)
}

// Readdir returns directory entries
func (dir *Dir) Readdir(ctx context.Context) (fusefs.DirStream, syscall.Errno) {
	if dir.fs.terminated.Load() {
		return nil, syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(dir.fs.logger)

	operID := dir.fs.GetNextOperationID()
	dir.fs.logger.Infof("Calling Readdir (%d) - %q", operID, dir.path)
	defer dir.fs.logger.Infof("Called Readdir (%d) - %q", operID, dir.path)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		dir.fs.logger.Errorf("failed to get VPath Entry for %q", dir.path)
		return nil, syscall.EREMOTEIO
	}

	dirEntries := getDefaultDirEntries()

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		if vpathEntry.Path == dir.path {
			for _, entry := range vpathEntry.VirtualDirEntry.DirEntries {
				if entry.IsVirtualDirEntry() {
					// Virtual Dir entry
					dirEntry := fuse.DirEntry{
						Ino:  entry.VirtualDirEntry.ID,
						Mode: uint32(fuse.S_IFDIR),
						Name: entry.VirtualDirEntry.Name,
					}

					dirEntries = append(dirEntries, dirEntry)
				} else {
					// iRODS entry
					entryType := uint32(fuse.S_IFREG)

					if entry.IRODSEntry.IsDir() {
						entryType = uint32(fuse.S_IFDIR)
					}

					inodeID, err := dir.fs.getInodeIDForIRODSEntry(entry.IRODSEntry)
					if err != nil {
						dir.fs.logger.Error(err)
					} else {
						dirEntry := fuse.DirEntry{
							Ino:  inodeID,
							Mode: entryType,
							Name: path.Base(entry.Path),
						}

						dirEntries = append(dirEntries, dirEntry)
					}
				}
			}

			return fusefs.NewListDirStream(dirEntries), fusefs.OK
		}
		return nil, syscall.ENOENT
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		dir.fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		dir.fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}

	irodsDirEntries, errno := dir.fs.IRODSReaddir(ctx, irodsPath)
	dirEntries = append(dirEntries, irodsDirEntries...)

	return fusefs.NewListDirStream(dirEntries), errno
}

// Rmdir removes a dir
func (dir *Dir) Rmdir(ctx context.Context, name string) syscall.Errno {
	if dir.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(dir.fs.logger)

	targetPath := path.Join(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	dir.fs.logger.Infof("Calling Rmdir (%d) - %q", operID, targetPath)
	defer dir.fs.logger.Infof("Called Rmdir (%d) - %q", operID, targetPath)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		dir.fs.logger.Errorf("failed to get VPath Entry for %q", targetPath)
		return syscall.EREMOTEIO
	}

	if isVPathEntryUnmodifiable(vpathEntry, targetPath) {
		// failed to remove. read only
		dir.fs.logger.Errorf("failed to remove readonly vpath mapping entry %q", vpathEntry.Path)
		return syscall.EROFS
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	return dir.fs.IRODSRmdir(ctx, irodsPath)
}

// Unlink removes a file for the path
func (dir *Dir) Unlink(ctx context.Context, name string) syscall.Errno {
	if dir.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(dir.fs.logger)

	targetPath := path.Join(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	dir.fs.logger.Infof("Calling Unlink (%d) - %q", operID, targetPath)
	defer dir.fs.logger.Infof("Called Unlink (%d) - %q", operID, targetPath)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		dir.fs.logger.Errorf("failed to get VPath Entry for %q", targetPath)
		return syscall.EREMOTEIO
	}

	if isVPathEntryUnmodifiable(vpathEntry, targetPath) {
		// failed to remove. read only
		dir.fs.logger.Errorf("failed to remove readonly vpath mapping entry %q", vpathEntry.Path)
		return syscall.EROFS
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	return dir.fs.IRODSUnlink(ctx, irodsPath)
}

// Mkdir makes a dir for the path
func (dir *Dir) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fusefs.Inode, syscall.Errno) {
	if dir.fs.terminated.Load() {
		return nil, syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(dir.fs.logger)

	targetPath := path.Join(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	dir.fs.logger.Infof("Calling Mkdir (%d) - %q", operID, targetPath)
	defer dir.fs.logger.Infof("Called Mkdir (%d) - %q", operID, targetPath)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		dir.fs.logger.Errorf("failed to get VPath Entry for %q", targetPath)
		return nil, syscall.EREMOTEIO
	}

	if isVPathEntryUnmodifiable(vpathEntry, targetPath) {
		dir.fs.logger.Errorf("failed to mkdir in readonly vpath mapping entry %q", vpathEntry.Path)
		return nil, syscall.EROFS
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		dir.fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		dir.fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}

	entryID, errno := dir.fs.IRODSMkdir(ctx, dir, irodsPath, out)
	if errno != fusefs.OK {
		return nil, errno
	}

	inodeID, err := dir.fs.getInodeIDForIRODSEntryID(uint64(entryID))
	if err != nil {
		dir.fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}
	_, subDirInode := dir.NewSubDirInode(ctx, inodeID, targetPath)
	return subDirInode, fusefs.OK
}

func (dir *Dir) renameNode(srcPath string, destPath string, node *fusefs.Inode) error {
	switch fsnode := node.Operations().(type) {
	case *Dir:
		relPath, err := irodsclient_util.GetIRODSRelativePath(srcPath, fsnode.path)
		if err != nil {
			return err
		}

		newPath := path.Join(destPath, relPath)
		dir.fs.logger.Debugf("renaming a dir node %q to %q", fsnode.path, newPath)

		fsnode.path = newPath

		// recurse
		for _, childNode := range fsnode.Children() {
			err := dir.renameNode(srcPath, destPath, childNode)
			if err != nil {
				return err
			}
		}
	case *File:
		relPath, err := irodsclient_util.GetIRODSRelativePath(srcPath, fsnode.path)
		if err != nil {
			return err
		}

		newPath := path.Join(destPath, relPath)
		dir.fs.logger.Debugf("renaming a file node %q to %q", fsnode.path, newPath)

		fsnode.path = newPath
	default:
		return errors.New("unknown node type")
	}

	return nil
}

// Rename renames a node for the path
func (dir *Dir) Rename(ctx context.Context, name string, newParent fusefs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if dir.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(dir.fs.logger)

	targetSrcPath := path.Join(dir.path, name)

	newdir, ok := newParent.(*Dir)
	if !ok || newdir == nil {
		dir.fs.logger.Error("failed to convert newParent to Dir type")
		return syscall.EINVAL
	}

	targetDestPath := path.Join(newdir.path, newName)

	operID := dir.fs.GetNextOperationID()
	dir.fs.logger.Infof("Calling Rename (%d) - %q to %q", operID, targetSrcPath, targetDestPath)
	defer dir.fs.logger.Infof("Called Rename (%d) - %q to %q", operID, targetSrcPath, targetDestPath)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	if newdir != dir {
		newdir.mutex.Lock()
		defer newdir.mutex.Unlock()
	}

	vpathSrcEntry := dir.fs.vpathManager.GetClosestEntry(targetSrcPath)
	if vpathSrcEntry == nil {
		dir.fs.logger.Errorf("failed to get VPath Entry for %q", targetSrcPath)
		return syscall.EREMOTEIO
	}

	vpathDestEntry := dir.fs.vpathManager.GetClosestEntry(targetDestPath)
	if vpathDestEntry == nil {
		dir.fs.logger.Errorf("failed to get VPath Entry for path %q", targetDestPath)
		return syscall.EREMOTEIO
	}

	if isVPathEntryUnmodifiable(vpathSrcEntry, targetSrcPath) {
		// failed to remove. read only
		dir.fs.logger.Errorf("failed to rename readonly vpath mapping entry %q", vpathSrcEntry.Path)
		return syscall.EROFS
	}

	if isVPathEntryUnmodifiable(vpathDestEntry, targetDestPath) {
		// failed to remove. read only
		dir.fs.logger.Errorf("failed to rename to readonly vpath mapping entry %q", vpathDestEntry.Path)
		return syscall.EROFS
	}

	// IRODS Dir
	err := dir.ensureIRODSPath(vpathSrcEntry)
	if err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	err = dir.ensureIRODSPath(vpathDestEntry)
	if err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	irodsSrcPath, err := vpathSrcEntry.GetIRODSPath(targetSrcPath)
	if err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	irodsDestPath, err := vpathDestEntry.GetIRODSPath(targetDestPath)
	if err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	// lock first
	// dir?
	openFilePaths := dir.fs.fileHandleMap.ListPathsInDir(irodsSrcPath)
	for _, openFilePath := range openFilePaths {
		handlesOpened := dir.fs.fileHandleMap.ListByPath(openFilePath)
		for _, handle := range handlesOpened {
			handle.mutex.Lock()
			defer handle.mutex.Unlock()
		}
	}

	// file?
	handlesOpened := dir.fs.fileHandleMap.ListByPath(irodsSrcPath)
	for _, handle := range handlesOpened {
		handle.mutex.Lock()
		defer handle.mutex.Unlock()
	}

	errno := dir.fs.IRODSRename(ctx, dir, irodsSrcPath, irodsDestPath)
	if errno != fusefs.OK {
		return errno
	}

	// update in-memory path; if the node isn't cached yet, skip — the rename on iRODS already succeeded
	childNode := dir.GetChild(name)
	if childNode == nil {
		dir.fs.logger.Warnf("node %q not in kernel cache after rename, skipping in-memory path update", irodsSrcPath)
		dir.fs.fileHandleMap.Rename(irodsSrcPath, irodsDestPath)
		return fusefs.OK
	}

	if err := dir.renameNode(targetSrcPath, targetDestPath, childNode); err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	// report update to fileHandleMap
	dir.fs.fileHandleMap.Rename(irodsSrcPath, irodsDestPath)

	return fusefs.OK
}

// Create creates a file for the path and returns file handle
func (dir *Dir) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fusefs.Inode, fusefs.FileHandle, uint32, syscall.Errno) {
	if dir.fs.terminated.Load() {
		return nil, nil, 0, syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(dir.fs.logger)

	fuseFlag := uint32(0)
	targetPath := path.Join(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	dir.fs.logger.Infof("Calling Create (%d) - %q, mode %d", operID, targetPath, flags)
	defer dir.fs.logger.Infof("Called Create (%d) - %q, mode %d", operID, targetPath, flags)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		dir.fs.logger.Errorf("failed to get VPath Entry for %q", targetPath)
		return nil, nil, 0, syscall.EREMOTEIO
	}

	if isVPathEntryUnmodifiable(vpathEntry, targetPath) {
		dir.fs.logger.Errorf("failed to create file in readonly vpath mapping entry %q", vpathEntry.Path)
		return nil, nil, 0, syscall.EROFS
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		dir.fs.logger.Error(err)
		return nil, nil, 0, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		dir.fs.logger.Error(err)
		return nil, nil, 0, syscall.EREMOTEIO
	}

	entryID, fileHandle, errno := dir.fs.IRODSCreate(ctx, dir, irodsPath, flags, out)
	if errno != fusefs.OK {
		return nil, nil, 0, errno
	}

	inodeID, err := dir.fs.getInodeIDForIRODSEntryID(uint64(entryID))
	if err != nil {
		dir.fs.logger.Error(err)
		return nil, nil, 0, syscall.EREMOTEIO
	}

	subFile, subFileInode := dir.NewSubFileInode(ctx, inodeID, targetPath)
	fileHandle.SetFile(subFile)

	// add to file handle map
	dir.fs.fileHandleMap.Add(fileHandle)

	return subFileInode, fileHandle, fuseFlag, fusefs.OK
}

// Statfs returns filesystem statistics.
// iRODS does not expose total/free disk usage, so large placeholder values are
// returned to prevent clients from treating the filesystem as full.
func (dir *Dir) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
	if dir.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(dir.fs.logger)

	const blockSize = 4096
	const totalBlocks = 1 << 38 // ~1 PiB

	out.Bsize = blockSize
	out.Frsize = blockSize
	out.Blocks = totalBlocks
	out.Bfree = totalBlocks
	out.Bavail = totalBlocks
	out.Files = 1 << 20
	out.Ffree = 1 << 20
	out.NameLen = 255

	return fusefs.OK
}

// Fsync flushes content changes
func (dir *Dir) Fsync(ctx context.Context, fh fusefs.FileHandle, flags uint32) syscall.Errno {
	if dir.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	return fusefs.OK
}
