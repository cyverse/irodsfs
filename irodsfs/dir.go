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

func (dir *Dir) NewSubSymlinkInode(ctx context.Context, inodeID uint64, path string, target string) (*Symlink, *fusefs.Inode) {
	subSymlink := NewSymlink(dir.fs, inodeID, path, target)
	subSymlinkInode := dir.NewInode(ctx, subSymlink, subSymlink.getStableAttr())

	return subSymlink, subSymlinkInode
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
	if errno == syscall.ENOENT {
		// the name may belong to a symbolic link, which is stored under a suffixed
		// name. It is probed second so that a real entry always wins.
		return dir.lookupSymlink(ctx, irodsPath, targetPath, out)
	}

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

// lookupSymlink returns the inode of the symbolic link stored under the suffixed
// name of the given irods path
func (dir *Dir) lookupSymlink(ctx context.Context, irodsPath string, targetPath string, out *fuse.EntryOut) (*fusefs.Inode, syscall.Errno) {
	entryID, errno := dir.fs.IRODSLookupSymlink(ctx, SymlinkStoredName(irodsPath), out)
	if errno != fusefs.OK {
		return nil, errno
	}

	inodeID, err := dir.fs.getInodeIDForIRODSEntryID(uint64(entryID))
	if err != nil {
		dir.fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}

	_, subSymlinkInode := dir.NewSubSymlinkInode(ctx, inodeID, targetPath, "")
	return subSymlinkInode, fusefs.OK
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

// resolveStoredIRODSPath maps the visible irods path of an existing entry to the path
// it is stored under, and reports whether that entry is a symbolic link. A symbolic
// link lives under a suffixed name, so the name the kernel hands us is not always the
// name to act on.
//
// The node is usually already in the kernel cache, which answers this for free. When
// it is not, the names are probed in the order Lookup uses, so that a real entry keeps
// winning. When neither name exists the plain path is returned, leaving the caller to
// report the same error it reports today.
func (dir *Dir) resolveStoredIRODSPath(ctx context.Context, name string, irodsPath string) (string, bool, syscall.Errno) {
	if childNode := dir.GetChild(name); childNode != nil {
		if _, ok := childNode.Operations().(*Symlink); ok {
			return SymlinkStoredName(irodsPath), true, fusefs.OK
		}

		return irodsPath, false, fusefs.OK
	}

	exists, errno := dir.fs.IRODSExists(ctx, irodsPath)
	if errno != fusefs.OK {
		return "", false, errno
	}

	if exists {
		return irodsPath, false, fusefs.OK
	}

	storedPath := SymlinkStoredName(irodsPath)

	exists, errno = dir.fs.IRODSExists(ctx, storedPath)
	if errno != fusefs.OK {
		return "", false, errno
	}

	if exists {
		return storedPath, true, fusefs.OK
	}

	return irodsPath, false, fusefs.OK
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

	storedPath, isSymlink, errno := dir.resolveStoredIRODSPath(ctx, name, irodsPath)
	if errno != fusefs.OK {
		return errno
	}

	errno = dir.fs.IRODSUnlink(ctx, storedPath)
	if errno != fusefs.OK {
		return errno
	}

	if isSymlink {
		// the node can outlive the removal, so drop the cached target rather than
		// keep answering Readlink for a link that is gone
		if childNode := dir.GetChild(name); childNode != nil {
			if symlinkNode, ok := childNode.Operations().(*Symlink); ok {
				symlinkNode.invalidateTarget()
			}
		}
	}

	return fusefs.OK
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

	if IsSymlinkStoredName(name) {
		dir.fs.logger.Errorf("failed to create %q, names ending with %q are reserved for symbolic links", targetPath, SymlinkSuffix)
		return nil, syscall.EPERM
	}

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

// Symlink creates a symbolic link
func (dir *Dir) Symlink(ctx context.Context, target string, name string, out *fuse.EntryOut) (*fusefs.Inode, syscall.Errno) {
	if dir.fs.terminated.Load() {
		return nil, syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(dir.fs.logger)

	targetPath := path.Join(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	dir.fs.logger.Infof("Calling Symlink (%d) - %q -> %q", operID, targetPath, target)
	defer dir.fs.logger.Infof("Called Symlink (%d) - %q -> %q", operID, targetPath, target)

	if IsSymlinkStoredName(name) {
		dir.fs.logger.Errorf("failed to create %q, names ending with %q are reserved for symbolic links", targetPath, SymlinkSuffix)
		return nil, syscall.EPERM
	}

	if len(target) == 0 {
		dir.fs.logger.Errorf("failed to create symbolic link %q, its target is empty", targetPath)
		return nil, syscall.EINVAL
	}

	if int64(len(target)) > SymlinkTargetMax {
		dir.fs.logger.Errorf("failed to create symbolic link %q, its target is %d bytes, larger than %d", targetPath, len(target), SymlinkTargetMax)
		return nil, syscall.ENAMETOOLONG
	}

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		dir.fs.logger.Errorf("failed to get VPath Entry for %q", targetPath)
		return nil, syscall.EREMOTEIO
	}

	if isVPathEntryUnmodifiable(vpathEntry, targetPath) {
		dir.fs.logger.Errorf("failed to create a symbolic link in readonly vpath mapping entry %q", vpathEntry.Path)
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

	// a real entry always wins over a symbolic link of the same visible name, so a
	// link that would be hidden the moment it is created is refused instead
	exists, errno := dir.fs.IRODSExists(ctx, irodsPath)
	if errno != fusefs.OK {
		return nil, errno
	}

	if exists {
		dir.fs.logger.Errorf("failed to create symbolic link %q, an entry of the same name exists", targetPath)
		return nil, syscall.EEXIST
	}

	storedPath := SymlinkStoredName(irodsPath)

	exists, errno = dir.fs.IRODSExists(ctx, storedPath)
	if errno != fusefs.OK {
		return nil, errno
	}

	if exists {
		dir.fs.logger.Errorf("failed to create symbolic link %q, it already exists", targetPath)
		return nil, syscall.EEXIST
	}

	entryID, errno := dir.fs.IRODSSymlink(ctx, storedPath, target, out)
	if errno != fusefs.OK {
		return nil, errno
	}

	inodeID, err := dir.fs.getInodeIDForIRODSEntryID(uint64(entryID))
	if err != nil {
		dir.fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}

	_, subSymlinkInode := dir.NewSubSymlinkInode(ctx, inodeID, targetPath, target)
	return subSymlinkInode, fusefs.OK
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
	case *Symlink:
		relPath, err := irodsclient_util.GetIRODSRelativePath(srcPath, fsnode.path)
		if err != nil {
			return err
		}

		newPath := path.Join(destPath, relPath)
		dir.fs.logger.Debugf("renaming a symbolic link node %q to %q", fsnode.path, newPath)

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

	if IsSymlinkStoredName(newName) {
		dir.fs.logger.Errorf("failed to rename to %q, names ending with %q are reserved for symbolic links", targetDestPath, SymlinkSuffix)
		return syscall.EPERM
	}

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

	// a symbolic link is stored under a suffixed name, so both ends of the rename
	// carry the suffix. For every other entry the stored path is the visible one.
	storedSrcPath, srcIsSymlink, errno := dir.resolveStoredIRODSPath(ctx, name, irodsSrcPath)
	if errno != fusefs.OK {
		return errno
	}

	storedDestPath := irodsDestPath
	if srcIsSymlink {
		storedDestPath = SymlinkStoredName(irodsDestPath)

		// a real entry always wins over a symbolic link of the same visible name, so
		// moving a link onto one would only hide the link the moment it lands
		exists, errno := dir.fs.IRODSExists(ctx, irodsDestPath)
		if errno != fusefs.OK {
			return errno
		}

		if exists {
			dir.fs.logger.Errorf("failed to rename symbolic link %q to %q, an entry of the same name exists", targetSrcPath, targetDestPath)
			return syscall.EEXIST
		}
	}

	// lock first
	// dir?
	openFilePaths := dir.fs.fileHandleMap.ListPathsInDir(storedSrcPath)
	for _, openFilePath := range openFilePaths {
		handlesOpened := dir.fs.fileHandleMap.ListByPath(openFilePath)
		for _, handle := range handlesOpened {
			handle.mutex.Lock()
			defer handle.mutex.Unlock()
		}
	}

	// file?
	handlesOpened := dir.fs.fileHandleMap.ListByPath(storedSrcPath)
	for _, handle := range handlesOpened {
		handle.mutex.Lock()
		defer handle.mutex.Unlock()
	}

	errno = dir.fs.IRODSRename(ctx, dir, storedSrcPath, storedDestPath)
	if errno != fusefs.OK {
		return errno
	}

	// update in-memory path; if the node isn't cached yet, skip — the rename on iRODS already succeeded
	childNode := dir.GetChild(name)
	if childNode == nil {
		dir.fs.logger.Warnf("node %q not in kernel cache after rename, skipping in-memory path update", storedSrcPath)
		dir.fs.fileHandleMap.Rename(storedSrcPath, storedDestPath)
		return fusefs.OK
	}

	if err := dir.renameNode(targetSrcPath, targetDestPath, childNode); err != nil {
		dir.fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	// report update to fileHandleMap
	dir.fs.fileHandleMap.Rename(storedSrcPath, storedDestPath)

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

	if IsSymlinkStoredName(name) {
		dir.fs.logger.Errorf("failed to create %q, names ending with %q are reserved for symbolic links", targetPath, SymlinkSuffix)
		return nil, nil, 0, syscall.EPERM
	}

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
