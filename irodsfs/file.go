package irodsfs

import (
	"context"
	"sync"
	"syscall"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	irodsfs_common_utils "github.com/cyverse/irodsfs-common/utils"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
	"golang.org/x/xerrors"

	log "github.com/sirupsen/logrus"
)

// File is a file node
type File struct {
	fusefs.Inode

	fs      *IRODSFS
	inodeID uint64
	path    string
	mutex   sync.RWMutex
}

// NewFile creates a new File
func NewFile(fs *IRODSFS, inodeID uint64, path string) *File {
	return &File{
		fs:      fs,
		inodeID: inodeID,
		path:    path,
		mutex:   sync.RWMutex{},
	}
}

func (file *File) getStableAttr() fusefs.StableAttr {
	return fusefs.StableAttr{
		Mode: fuse.S_IFREG,
		Ino:  file.inodeID,
		Gen:  0,
	}
}

func (file *File) setAttrOutForIRODSEntry(ctx context.Context, entry *irodsclient_fs.Entry, readonly bool, out *fuse.Attr) {
	mode := IRODSGetACL(ctx, file.fs, entry, readonly)
	setAttrOutForIRODSEntry(file.fs.inodeManager, entry, file.fs.uid, file.fs.gid, mode, out)
}

func (file *File) ensureIRODSPath(vpathEntry *irodsfs_common_vpath.VPathEntry) error {
	return ensureVPathEntryIsIRODSEntry(file.fs.fsClient, vpathEntry)
}

// Getattr returns stat of file entry
func (file *File) Getattr(ctx context.Context, fh fusefs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Getattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Getattr (%d) - %q", operID, file.path)
	defer logger.Infof("Called Getattr (%d) - %q", operID, file.path)

	file.mutex.RLock()
	defer file.mutex.RUnlock()

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", file.path)
		return syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		logger.Errorf("failed to get file attribute from a virtual dir mapping")
		return syscall.EREMOTEIO
	}

	// IRODS File
	err := file.ensureIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(file.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return IRODSGetattr(ctx, file.fs, irodsPath, vpathEntry.ReadOnly, out)
}

// Setattr sets file attributes
func (file *File) Setattr(ctx context.Context, fh fusefs.FileHandle, in *fuse.SetAttrIn, out *fuse.AttrOut) syscall.Errno {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Setattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Setattr (%d) - %q", operID, file.path)
	defer logger.Infof("Called Setattr (%d) - %q", operID, file.path)

	// do not return EOPNOTSUPP as it causes client errors, like git clone
	/*
		if _, ok := in.GetMode(); ok {
			// chmod
			// not supported
			return syscall.EOPNOTSUPP
		} else if _, ok := in.GetATime(); ok {
			// changing date
			// not supported but return OK to not cause various errors in linux commands
			return fusefs.OK
		} else if _, ok := in.GetCTime(); ok {
			// changing date
			// not supported but return OK to not cause various errors in linux commands
			return fusefs.OK
		} else if _, ok := in.GetMTime(); ok {
			// changing date
			// not supported but return OK to not cause various errors in linux commands
			return fusefs.OK
		} else if _, ok := in.GetGID(); ok {
			// changing ownership
			// not supported
			return syscall.EOPNOTSUPP
		} else if _, ok := in.GetUID(); ok {
			// changing ownership
			// not supported
			return syscall.EOPNOTSUPP
		}
	*/
	if size, ok := in.GetSize(); ok {
		// truncate file
		errno := file.Truncate(ctx, size)
		if errno != fusefs.OK {
			return errno
		}

		out.Size = size
		return fusefs.OK
	}

	return fusefs.OK
}

// Listxattr lists xattr
// read all attributes (null terminated) into
// `dest`. If the `dest` buffer is too small, it should return ERANGE
// and the correct size.  If not defined, return an empty list and
// success.
func (file *File) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	if file.fs.terminated {
		return 0, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Listxattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Listxattr (%d) - %q", operID, file.path)
	defer logger.Infof("Called Listxattr (%d) - %q", operID, file.path)

	file.mutex.RLock()
	defer file.mutex.RUnlock()

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", file.path)
		return 0, syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		logger.Errorf("failed to get file extended attribute from a virtual dir mapping")
		return 0, syscall.EREMOTEIO
	}

	// IRODS File
	err := file.ensureIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return 0, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(file.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return 0, syscall.EREMOTEIO
	}

	return IRODSListxattr(ctx, file.fs, irodsPath, dest)
}

// Getxattr returns xattr
// return the number of bytes. If `dest` is too
// small, it should return ERANGE and the size of the attribute.
// If not defined, Getxattr will return ENOATTR.
func (file *File) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	if file.fs.terminated {
		return 0, syscall.ECONNABORTED
	}

	if IsUnhandledAttr(attr) {
		return 0, syscall.ENODATA
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Getxattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Getxattr (%d) - %q, attr %q", operID, file.path, attr)
	defer logger.Infof("Called Getxattr (%d) - %q, attr %q", operID, file.path, attr)

	file.mutex.RLock()
	defer file.mutex.RUnlock()

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", file.path)
		return 0, syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		logger.Errorf("failed to get file extended attribute from a virtual dir mapping")
		return 0, syscall.EREMOTEIO
	}

	// IRODS File
	err := file.ensureIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return 0, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(file.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return 0, syscall.EREMOTEIO
	}

	return IRODSGetxattr(ctx, file.fs, irodsPath, attr, dest)
}

// Setxattr sets xattr
// If not defined, Setxattr will return ENOATTR.
func (file *File) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Setxattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Setxattr (%d) - %q", operID, file.path)
	defer logger.Infof("Called Setxattr (%d) - %q", operID, file.path)

	if IsUnhandledAttr(attr) {
		return syscall.EINVAL
	}

	file.mutex.RLock()
	defer file.mutex.RUnlock()

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", file.path)
		return syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		logger.Errorf("failed to set file extended attribute from a virtual dir mapping")
		return syscall.EREMOTEIO
	}

	// IRODS File
	err := file.ensureIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(file.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return IRODSSetxattr(ctx, file.fs, irodsPath, attr, data)
}

// Removexattr removes xattr
// If not defined, Removexattr will return ENOATTR.
func (file *File) Removexattr(ctx context.Context, attr string) syscall.Errno {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Removexattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Removexattr (%d) - %q", operID, file.path)
	defer logger.Infof("Called Removexattr (%d) - %q", operID, file.path)

	file.mutex.RLock()
	defer file.mutex.RUnlock()

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", file.path)
		return syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		logger.Errorf("failed to remove file extended attribute from a virtual dir mapping")
		return syscall.EREMOTEIO
	}

	// IRODS File
	err := file.ensureIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(file.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	return IRODSRemovexattr(ctx, file.fs, irodsPath, attr)
}

// Truncate truncates file entry
func (file *File) Truncate(ctx context.Context, size uint64) syscall.Errno {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Truncate",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Truncate (%d) - %q, %d", operID, file.path, size)
	defer logger.Infof("Called Truncate (%d) - %q, %d", operID, file.path, size)

	file.mutex.Lock()
	defer file.mutex.Unlock()

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", file.path)
		return syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		logger.Errorf("failed to truncate a virtual dir")
		return syscall.EREMOTEIO
	}

	// IRODS File
	err := ensureVPathEntryIsIRODSEntry(file.fs.fsClient, vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(file.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	irodsEntry, err := IRODSStat(ctx, file.fs, irodsPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find a file - %q", file.path)
			return syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	// check if there're opened file handles
	// handle ftruncate operation
	callFtruncate := false
	handlesOpened := file.fs.fileHandleMap.ListByPath(irodsEntry.Path)
	for _, handle := range handlesOpened {
		if handle.openMode.IsWrite() {
			// is writing
			logger.Infof("Found opened file handle %q - %q", handle.file.path, handle.GetID())

			errno := handle.Truncate(ctx, size)
			if errno != 0 {
				logger.Errorf("failed to truncate a file - %q, %d", irodsEntry.Path, size)
				return errno
			}

			callFtruncate = true

			// avoid truncating a file multiple times
			break
		}
	}

	if !callFtruncate {
		if irodsEntry.Size != int64(size) {
			err = file.fs.fsClient.TruncateFile(irodsEntry.Path, int64(size))
			if err != nil {
				if irodsclient_types.IsFileNotFoundError(err) {
					logger.Debugf("failed to find a file - %q", irodsEntry.Path)
					return syscall.ENOENT
				}

				logger.Errorf("%+v", err)
				return syscall.EREMOTEIO
			}
		}
	}

	return fusefs.OK
}

// Open opens file for the path and returns file handle
func (file *File) Open(ctx context.Context, flags uint32) (fusefs.FileHandle, uint32, syscall.Errno) {
	if file.fs.terminated {
		return nil, 0, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Open",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	fuseFlag := uint32(0)
	// if we use Direct_IO, it will disable kernel cache, read-ahead, shared mmap
	//fuseFlag |= fuse.FOPEN_DIRECT_IO

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Open (%d) - %q, mode %d", operID, file.path, flags)
	defer logger.Infof("Called Open (%d) - %q, mode %d", operID, file.path, flags)

	file.mutex.RLock()
	defer file.mutex.RUnlock()

	vpathEntry := file.fs.vpathManager.GetClosestEntry(file.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %q", file.path)
		return nil, 0, syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		// failed to open directory
		err := xerrors.Errorf("failed to open mapped directory entry - %q", vpathEntry.Path)
		logger.Error(err)
		return nil, 0, syscall.EPERM
	}

	if vpathEntry.ReadOnly {
		openMode := IRODSGetOpenFlags(flags)

		if openMode != irodsclient_types.FileOpenModeReadOnly {
			logger.Errorf("failed to open a read-only file with non-read-only mode")
			return nil, 0, syscall.EPERM
		}
	}

	// IRODS File
	err := file.ensureIRODSPath(vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, 0, syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(file.path)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, 0, syscall.EREMOTEIO
	}

	fileHandle, errno := IRODSOpenLazy(ctx, file.fs, file, irodsPath, flags)
	if errno != fusefs.OK {
		return nil, 0, errno
	}

	fileHandle.SetFile(file)

	// add to file handle map
	file.fs.fileHandleMap.Add(fileHandle)

	return fileHandle, fuseFlag, fusefs.OK
}

// Getlk returns locks
func (file *File) Getlk(ctx context.Context, fh fusefs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32, out *fuse.FileLock) syscall.Errno {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Getlk",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Getattr (%d) - %q", operID, file.path)
	defer logger.Infof("Called Getattr (%d) - %q", operID, file.path)

	fileHandle, ok := fh.(*FileHandle)
	if !ok {
		logger.Errorf("failed to convert fh to a file handle - %q", fileHandle.file.path)
		return syscall.EREMOTEIO
	}

	return fileHandle.GetLocalLock(ctx, owner, lk, flags, out)
}

// Setlk obtains a lock on a file, or fail if the lock could not obtained
func (file *File) Setlk(ctx context.Context, fh fusefs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Setlk",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Setlk (%d) - %q", operID, file.path)
	defer logger.Infof("Called Setlk (%d) - %q", operID, file.path)

	fileHandle, ok := fh.(*FileHandle)
	if !ok {
		logger.Errorf("failed to convert fh to a file handle - %q", fileHandle.file.path)
		return syscall.EREMOTEIO
	}

	return fileHandle.SetLocalLock(ctx, owner, lk, flags)
}

// Setlkw obtains a lock on a file, waiting if necessary
func (file *File) Setlkw(ctx context.Context, fh fusefs.FileHandle, owner uint64, lk *fuse.FileLock, flags uint32) syscall.Errno {
	if file.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "File",
		"function": "Setlkw",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	operID := file.fs.GetNextOperationID()
	logger.Infof("Calling Setlkw (%d) - %q", operID, file.path)
	defer logger.Infof("Called Setlkw (%d) - %q", operID, file.path)

	fileHandle, ok := fh.(*FileHandle)
	if !ok {
		logger.Errorf("failed to convert fh to a file handle - %q", fileHandle.file.path)
		return syscall.EREMOTEIO
	}

	return fileHandle.SetLocalLockW(ctx, owner, lk, flags)
}

/*
func (dir *Dir) Link(ctx context.Context, target InodeEmbedder, name string, out *fuse.EntryOut) (node *Inode, errno syscall.Errno) {
}

func (dir *Dir) Symlink(ctx context.Context, target, name string, out *fuse.EntryOut) (node *Inode, errno syscall.Errno) {
}

func (dir *Dir) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
}
*/
