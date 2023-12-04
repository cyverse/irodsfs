package irodsfs

import (
	"context"
	"sync"
	"syscall"

	irodsfs_common_utils "github.com/cyverse/irodsfs-common/utils"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/xerrors"

	log "github.com/sirupsen/logrus"
)

// NewIRODSRoot returns root directory node for iRODS collection
func NewIRODSRoot(fs *IRODSFS, vpathEntry *irodsfs_common_vpath.VPathEntry) (*Dir, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "NewIRODSRoot",
	})

	err := ensureVPathEntryIsIRODSDir(fs.fsClient, vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		if isTransitiveConnectionError(err) {
			// continue
			inodeID := fs.inodeManager.GetInodeIDForVPathEntry("/")
			return NewDir(fs, inodeID, "/"), nil
		}

		return nil, syscall.EREMOTEIO
	}

	inodeID := fs.inodeManager.GetInodeIDForIRODSEntryID(vpathEntry.IRODSEntry.ID)
	return NewDir(fs, inodeID, "/"), nil
}

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
		mutex:   sync.RWMutex{},
	}
}

func (dir *Dir) getStableAttr() fusefs.StableAttr {
	return fusefs.StableAttr{
		Mode: uint32(fuse.S_IFDIR),
		Ino:  dir.inodeID,
		Gen:  0,
	}
}

func (dir *Dir) ensureDirIRODSPath(vpathEntry *irodsfs_common_vpath.VPathEntry) error {
	return ensureVPathEntryIsIRODSDir(dir.fs.fsClient, vpathEntry)
}

func (dir *Dir) ensureIRODSPath(vpathEntry *irodsfs_common_vpath.VPathEntry) error {
	return ensureVPathEntryIsIRODSEntry(dir.fs.fsClient, vpathEntry)
}

// Getattr returns stat of file entry
func (dir *Dir) Getattr(ctx context.Context, fh fusefs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Getattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Getattr (%d) - %q", operID, dir.path)
	defer logger.Infof("Called Getattr (%d) - %q", operID, dir.path)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", dir.path)
		return syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		if vpathEntry.Path == dir.path {
			setAttrOutForVirtualDirEntry(dir.fs.inodeManager, vpathEntry.VirtualDirEntry, dir.fs.uid, dir.fs.gid, &out.Attr)
			return fusefs.OK
		}
		return syscall.ENOENT
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		if isTransitiveConnectionError(err) {
			// return dummy
			logger.Errorf("returning dummy attr for path %q", dir.path)
			setAttrOutForDummy(dir.fs.inodeManager, dir.path, dir.fs.uid, dir.fs.gid, true, &out.Attr)
			return fusefs.OK
		}

		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return IRODSGetattr(ctx, dir.fs, irodsPath, vpathEntry.ReadOnly, out)
}

// Setattr sets dir attributes
func (dir *Dir) Setattr(ctx context.Context, fh fusefs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Setattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// do not return EOPNOTSUPP as it causes client errors, like git clone
	/*
		if _, ok := in.GetMode(); ok {
			// chmod
			// not supported
			return syscall.EOPNOTSUPP
		} else if _, ok := in.GetATime(); ok {
			// changing date
			// not supported
			return syscall.EOPNOTSUPP
		} else if _, ok := in.GetCTime(); ok {
			// changing date
			// not supported
			return syscall.EOPNOTSUPP
		} else if _, ok := in.GetMTime(); ok {
			// changing date
			// not supported
			return syscall.EOPNOTSUPP
		} else if _, ok := in.GetGID(); ok {
			// changing ownership
			// not supported
			return syscall.EOPNOTSUPP
		} else if _, ok := in.GetUID(); ok {
			// changing ownership
			// not supported
			return syscall.EOPNOTSUPP
		} else if size, ok := in.GetSize(); ok {
			// is this to truncate a file?
			// not supported
			logger.Errorf("cannot handle truncation of a directory - %q, size %q", dir.path, size)
			return syscall.EOPNOTSUPP
		}
	*/

	return fusefs.OK
}

// Listxattr lists xattr
// read all attributes (null terminated) into
// `dest`. If the `dest` buffer is too small, it should return ERANGE
// and the correct size.  If not defined, return an empty list and
// success.
func (dir *Dir) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	if dir.fs.terminated {
		return 0, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Listxattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Listxattr (%d) - %q", operID, dir.path)
	defer logger.Infof("Called Listxattr (%d) - %q", operID, dir.path)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", dir.path)
		return 0, syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		// no data
		return 0, fusefs.OK
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return 0, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return 0, syscall.EREMOTEIO
	}

	return IRODSListxattr(ctx, dir.fs, irodsPath, dest)
}

// Getxattr returns xattr
// return the number of bytes. If `dest` is too
// small, it should return ERANGE and the size of the attribute.
// If not defined, Getxattr will return ENOATTR.
func (dir *Dir) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	if dir.fs.terminated {
		return 0, syscall.ECONNABORTED
	}

	if IsUnhandledAttr(attr) {
		return 0, syscall.ENODATA
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Getxattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Getxattr (%d) - %q, name %q", operID, dir.path, attr)
	defer logger.Infof("Called Getxattr (%d) - %q, name %q", operID, dir.path, attr)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", dir.path)
		return 0, syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		return 0, syscall.ENODATA
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return 0, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return 0, syscall.EREMOTEIO
	}

	return IRODSGetxattr(ctx, dir.fs, irodsPath, attr, dest)
}

// Setxattr sets xattr
// If not defined, Setxattr will return ENOATTR.
func (dir *Dir) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Setxattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Setxattr (%d) - %q", operID, dir.path)
	defer logger.Infof("Called Setxattr (%d) - %q", operID, dir.path)

	if IsUnhandledAttr(attr) {
		return syscall.EINVAL
	}

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", dir.path)
		return syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		return syscall.EACCES
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return IRODSSetxattr(ctx, dir.fs, irodsPath, attr, data)
}

// Removexattr removes xattr
// If not defined, Removexattr will return ENOATTR.
func (dir *Dir) Removexattr(ctx context.Context, attr string) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Removexattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Removexattr (%d) - %q", operID, dir.path)
	defer logger.Infof("Called Removexattr (%d) - %q", operID, dir.path)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", dir.path)
		return syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		return syscall.EACCES
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return IRODSRemovexattr(ctx, dir.fs, irodsPath, attr)
}

// Lookup returns a node for the path
func (dir *Dir) Lookup(ctx context.Context, name string, out *fuse.EntryOut) (*fusefs.Inode, syscall.Errno) {
	if dir.fs.terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Lookup",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	targetPath := irodsfs_common_utils.JoinPath(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Lookup (%d) - %q", operID, targetPath)
	defer logger.Infof("Called Lookup (%d) - %q", operID, targetPath)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", targetPath)
		return nil, syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		if vpathEntry.Path == targetPath {
			inodeID := dir.fs.inodeManager.GetInodeIDForVPathEntryID(vpathEntry.VirtualDirEntry.ID)
			_, subDirInode := NewSubDirInode(ctx, dir, inodeID, targetPath)
			setAttrOutForVirtualDirEntry(dir.fs.inodeManager, vpathEntry.VirtualDirEntry, dir.fs.uid, dir.fs.gid, &out.Attr)
			return subDirInode, fusefs.OK
		}
		return nil, syscall.ENOENT
	}

	// IRODS Dir
	err := dir.ensureIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, syscall.EREMOTEIO
	}

	entryID, entryDir, errno := IRODSLookup(ctx, dir.fs, dir, irodsPath, vpathEntry.ReadOnly, out)
	if errno != fusefs.OK {
		return nil, errno
	}

	inodeID := dir.fs.inodeManager.GetInodeIDForIRODSEntryID(entryID)
	if entryDir {
		_, subDirInode := NewSubDirInode(ctx, dir, inodeID, targetPath)
		return subDirInode, fusefs.OK
	}

	_, subFileInode := NewSubFileInode(ctx, dir, inodeID, targetPath)
	return subFileInode, fusefs.OK
}

// Opendir validates the existance of a dir
func (dir *Dir) Opendir(ctx context.Context) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Opendir",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Opendir (%d) - %q", operID, dir.path)
	defer logger.Infof("Called Opendir (%d) - %q", operID, dir.path)

	// we must not lock here.
	// rename locks mutex and calls opendir, so goes deadlock
	//dir.mutex.RLock()
	//defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", dir.path)
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
		logger.Errorf("%+v", err)
		if isTransitiveConnectionError(err) {
			// return dummy
			logger.Errorf("opening dummy dir for path %q", dir.path)
			return fusefs.OK
		}

		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return IRODSOpendir(ctx, dir.fs, irodsPath)
}

// Readdir returns directory entries
func (dir *Dir) Readdir(ctx context.Context) (fusefs.DirStream, syscall.Errno) {
	if dir.fs.terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Readdir",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Readdir (%d) - %q", operID, dir.path)
	defer logger.Infof("Called Readdir (%d) - %q", operID, dir.path)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", dir.path)
		return nil, syscall.EREMOTEIO
	}

	dirEntries := getDefaultDirEntries()

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		if vpathEntry.Path == dir.path {
			for _, entry := range vpathEntry.VirtualDirEntry.DirEntries {
				if entry.IsVirtualDirEntry() {
					// Virtual Dir entry
					inodeID := dir.fs.inodeManager.GetInodeIDForVPathEntryID(entry.VirtualDirEntry.ID)
					dirEntry := fuse.DirEntry{
						Ino:  inodeID,
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

					inodeID := dir.fs.inodeManager.GetInodeIDForIRODSEntryID(entry.IRODSEntry.ID)
					dirEntry := fuse.DirEntry{
						Ino:  inodeID,
						Mode: entryType,
						Name: irodsfs_common_utils.GetFileName(entry.Path),
					}

					dirEntries = append(dirEntries, dirEntry)
				}
			}

			return fusefs.NewListDirStream(dirEntries), fusefs.OK
		}
		return nil, syscall.ENOENT
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		if isTransitiveConnectionError(err) {
			// return dummy
			logger.Errorf("returning dummy dir entries for path %q", dir.path)
			return fusefs.NewListDirStream(dirEntries), fusefs.OK
		}

		return nil, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, syscall.EREMOTEIO
	}

	irodsDirEntries, errno := IRODSReaddir(ctx, dir.fs, irodsPath)
	dirEntries = append(dirEntries, irodsDirEntries...)

	return fusefs.NewListDirStream(dirEntries), errno
}

// Rmdir removes a dir
func (dir *Dir) Rmdir(ctx context.Context, name string) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Rmdir",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	targetPath := irodsfs_common_utils.JoinPath(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Rmdir (%d) - %q", operID, targetPath)
	defer logger.Infof("Called Rmdir (%d) - %q", operID, targetPath)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", targetPath)
		return syscall.EREMOTEIO
	}

	if isVPathEntryUnmodifiable(vpathEntry, targetPath) {
		// failed to remove. read only
		err := xerrors.Errorf("failed to remove readonly vpath mapping entry %q", vpathEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return IRODSRmdir(ctx, dir.fs, irodsPath)
}

// Unlink removes a file for the path
func (dir *Dir) Unlink(ctx context.Context, name string) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Unlink",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	targetPath := irodsfs_common_utils.JoinPath(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Unlink (%d) - %q", operID, targetPath)
	defer logger.Infof("Called Unlink (%d) - %q", operID, targetPath)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", targetPath)
		return syscall.EREMOTEIO
	}

	if isVPathEntryUnmodifiable(vpathEntry, targetPath) {
		// failed to remove. read only
		err := xerrors.Errorf("failed to remove readonly vpath mapping entry %q", vpathEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return IRODSUnlink(ctx, dir.fs, irodsPath)
}

// Mkdir makes a dir for the path
func (dir *Dir) Mkdir(ctx context.Context, name string, mode uint32, out *fuse.EntryOut) (*fusefs.Inode, syscall.Errno) {
	if dir.fs.terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Mkdir",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	targetPath := irodsfs_common_utils.JoinPath(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Mkdir (%d) - %q", operID, targetPath)
	defer logger.Infof("Called Mkdir (%d) - %q", operID, targetPath)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", targetPath)
		return nil, syscall.EREMOTEIO
	}

	if isVPathEntryUnmodifiable(vpathEntry, targetPath) {
		// failed to remove. read only
		err := xerrors.Errorf("failed to remove readonly vpath mapping entry %q", vpathEntry.Path)
		logger.Error(err)
		return nil, syscall.EPERM
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, syscall.EREMOTEIO
	}

	entryID, errno := IRODSMkdir(ctx, dir.fs, dir, irodsPath, out)
	if errno != fusefs.OK {
		return nil, errno
	}

	inodeID := dir.fs.inodeManager.GetInodeIDForIRODSEntryID(entryID)
	_, subDirInode := NewSubDirInode(ctx, dir, inodeID, targetPath)
	return subDirInode, fusefs.OK
}

func (dir *Dir) renameNode(srcPath string, destPath string, node *fusefs.Inode) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "renameNode",
	})

	switch fsnode := node.Operations().(type) {
	case *Dir:
		relPath, err := irodsfs_common_utils.GetRelativePath(srcPath, fsnode.path)
		if err != nil {
			return err
		}

		newPath := irodsfs_common_utils.JoinPath(destPath, relPath)
		logger.Debugf("renaming a dir node %q to %q", fsnode.path, newPath)

		fsnode.path = newPath

		// recurse
		for _, childNode := range fsnode.Children() {
			err := dir.renameNode(srcPath, destPath, childNode)
			if err != nil {
				return err
			}
		}
	case *File:
		relPath, err := irodsfs_common_utils.GetRelativePath(srcPath, fsnode.path)
		if err != nil {
			return err
		}

		newPath := irodsfs_common_utils.JoinPath(destPath, relPath)
		logger.Debugf("renaming a file node %q to %q", fsnode.path, newPath)

		fsnode.path = newPath
	default:
		return xerrors.Errorf("unknown node type")
	}

	return nil
}

// Rename renames a node for the path
func (dir *Dir) Rename(ctx context.Context, name string, newParent fusefs.InodeEmbedder, newName string, flags uint32) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Rename",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	targetSrcPath := irodsfs_common_utils.JoinPath(dir.path, name)

	newdir, ok := newParent.(*Dir)
	if !ok || newdir == nil {
		logger.Error("failed to convert newParent to Dir type")
		return syscall.EREMOTEIO
	}

	targetDestPath := irodsfs_common_utils.JoinPath(newdir.path, newName)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Rename (%d) - %q to %q", operID, targetSrcPath, targetDestPath)
	defer logger.Infof("Called Rename (%d) - %q to %q", operID, targetSrcPath, targetDestPath)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	if newdir != dir {
		newdir.mutex.Lock()
		defer newdir.mutex.Unlock()
	}

	vpathSrcEntry := dir.fs.vpathManager.GetClosestEntry(targetSrcPath)
	if vpathSrcEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", targetSrcPath)
		return syscall.EREMOTEIO
	}

	vpathDestEntry := dir.fs.vpathManager.GetClosestEntry(targetDestPath)
	if vpathDestEntry == nil {
		logger.Errorf("failed to get VPath Entry for path %q", targetDestPath)
		return syscall.EREMOTEIO
	}

	if isVPathEntryUnmodifiable(vpathSrcEntry, targetSrcPath) {
		// failed to remove. read only
		err := xerrors.Errorf("failed to rename readonly vpath mapping entry %q", vpathSrcEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	if isVPathEntryUnmodifiable(vpathDestEntry, targetDestPath) {
		// failed to remove. read only
		err := xerrors.Errorf("failed to rename to readonly vpath mapping entry %q", vpathDestEntry.Path)
		logger.Error(err)
		return syscall.EPERM
	}

	// IRODS Dir
	err := dir.ensureIRODSPath(vpathSrcEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	err = dir.ensureIRODSPath(vpathDestEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	irodsSrcPath, err := vpathSrcEntry.GetIRODSPath(targetSrcPath)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	irodsDestPath, err := vpathDestEntry.GetIRODSPath(targetDestPath)
	if err != nil {
		logger.Errorf("%+v", err)
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

	errno := IRODSRename(ctx, dir.fs, dir, irodsSrcPath, irodsDestPath)
	if errno != fusefs.OK {
		return errno
	}

	// update
	childNode := dir.GetChild(name)
	if childNode == nil {
		logger.Errorf("failed to update the file or dir node - %q", irodsSrcPath)
		return syscall.EREMOTEIO
	}

	dir.renameNode(targetSrcPath, targetDestPath, childNode)

	// report update to fileHandleMap
	dir.fs.fileHandleMap.Rename(irodsSrcPath, irodsDestPath)

	return fusefs.OK
}

// Create creates a file for the path and returns file handle
func (dir *Dir) Create(ctx context.Context, name string, flags uint32, mode uint32, out *fuse.EntryOut) (*fusefs.Inode, fusefs.FileHandle, uint32, syscall.Errno) {
	if dir.fs.terminated {
		return nil, nil, 0, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Create",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	fuseFlag := uint32(0)
	// if we use Direct_IO, it will disable kernel cache, read-ahead, shared mmap
	//fuseFlag |= fuse.FOPEN_DIRECT_IO

	targetPath := irodsfs_common_utils.JoinPath(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Create (%d) - %q, mode %d", operID, targetPath, flags)
	defer logger.Infof("Called Create (%d) - %q, mode %d", operID, targetPath, flags)

	dir.mutex.Lock()
	defer dir.mutex.Unlock()

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", targetPath)
		return nil, nil, 0, syscall.EREMOTEIO
	}

	if isVPathEntryUnmodifiable(vpathEntry, targetPath) {
		// failed to remove. read only
		err := xerrors.Errorf("failed to rename readonly vpath mapping entry %q", vpathEntry.Path)
		logger.Error(err)
		return nil, nil, 0, syscall.EPERM
	}

	// IRODS Dir
	err := dir.ensureDirIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, nil, 0, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, nil, 0, syscall.EREMOTEIO
	}

	entryID, fileHandle, errno := IRODSCreate(ctx, dir.fs, dir, irodsPath, flags, out)
	if errno != fusefs.OK {
		return nil, nil, 0, errno
	}

	inodeID := dir.fs.inodeManager.GetInodeIDForIRODSEntryID(entryID)
	subFile, subFileInode := NewSubFileInode(ctx, dir, inodeID, targetPath)
	fileHandle.SetFile(subFile)

	// add to file handle map
	dir.fs.fileHandleMap.Add(fileHandle)

	return subFileInode, fileHandle, fuseFlag, fusefs.OK
}

// Fsync flushes content changes
func (dir *Dir) Fsync(ctx context.Context, fh fusefs.FileHandle, flags uint32) syscall.Errno {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Fsync",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Fsync (%d) - %q", operID, dir.path)
	defer logger.Infof("Called Fsync (%d) - %q", operID, dir.path)

	// do nothing
	return fusefs.OK
}

/*
func (dir *Dir) Statfs(ctx context.Context, out *fuse.StatfsOut) syscall.Errno {
}

func (dir *Dir) Link(ctx context.Context, target InodeEmbedder, name string, out *fuse.EntryOut) (node *Inode, errno syscall.Errno) {
}

func (dir *Dir) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (node *Inode, errno syscall.Errno) {
}

func (dir *Dir) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
}
*/
