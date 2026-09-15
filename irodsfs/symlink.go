package irodsfs

import (
	"context"
	"strings"
	"sync"
	"syscall"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsfs_common_util "github.com/cyverse/irodsfs-common/util"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
)

const (
	// SymlinkSuffix marks a data object that holds a symbolic link target.
	// iRODS has no POSIX symbolic link, so a link shown as "X" is stored as a data
	// object named "X"+SymlinkSuffix whose content is the link target. Keeping the
	// marker in the name, rather than in metadata or in the data type column, is
	// what lets the staging layer carry it to iRODS unchanged.
	SymlinkSuffix string = ".irodssymlink"

	// SymlinkTargetMax is the largest link target we store, matching PATH_MAX
	SymlinkTargetMax int64 = 4096

	// symlinkMode is reported for every symbolic link. Link permissions are not
	// meaningful on Linux and are conventionally reported as 0777.
	symlinkMode uint32 = 0o777
)

// IsSymlinkStoredName returns true if the given iRODS name stores a symbolic link
func IsSymlinkStoredName(storedName string) bool {
	_, ok := SymlinkVisibleName(storedName)
	return ok
}

// SymlinkStoredName returns the iRODS name that stores the symbolic link shown under
// the given name. It applies equally to a full path, whose last component is the name.
func SymlinkStoredName(visibleName string) string {
	return visibleName + SymlinkSuffix
}

// SymlinkVisibleName returns the name a symbolic link stored under the given iRODS
// name is shown under. It returns false if the name does not store a symbolic link.
func SymlinkVisibleName(storedName string) (string, bool) {
	if !strings.HasSuffix(storedName, SymlinkSuffix) {
		return "", false
	}

	visibleName := strings.TrimSuffix(storedName, SymlinkSuffix)
	if len(visibleName) == 0 {
		// the suffix alone leaves no name to show
		return "", false
	}

	return visibleName, true
}

// ResolvedDirEntry is an iRODS entry paired with the name it is shown under
type ResolvedDirEntry struct {
	Entry       *irodsclient_fs.Entry
	VisibleName string
	IsSymlink   bool
}

// ResolveDirEntries maps iRODS entries to the names they are shown under.
//
// A real entry always wins over a symbolic link claiming the same visible name:
// given both "X" and "X"+SymlinkSuffix, "X" is shown and the link is returned as
// shadowed so that the caller can warn about it. Lookup probes the plain name
// first, so this keeps Readdir and Lookup in agreement by construction.
//
// A symbolic link is always a data object, so a collection keeps its own name even
// when that name ends with the suffix.
func ResolveDirEntries(entries []*irodsclient_fs.Entry) ([]*ResolvedDirEntry, []string) {
	resolvedEntries := make([]*ResolvedDirEntry, 0, len(entries))
	shadowedNames := []string{}
	takenNames := make(map[string]bool, len(entries))
	symlinkEntries := []*irodsclient_fs.Entry{}

	for _, entry := range entries {
		if !entry.IsDir() && IsSymlinkStoredName(entry.Name) {
			symlinkEntries = append(symlinkEntries, entry)
			continue
		}

		resolvedEntries = append(resolvedEntries, &ResolvedDirEntry{
			Entry:       entry,
			VisibleName: entry.Name,
		})
		takenNames[entry.Name] = true
	}

	for _, entry := range symlinkEntries {
		visibleName, _ := SymlinkVisibleName(entry.Name)
		if takenNames[visibleName] {
			shadowedNames = append(shadowedNames, entry.Name)
			continue
		}

		resolvedEntries = append(resolvedEntries, &ResolvedDirEntry{
			Entry:       entry,
			VisibleName: visibleName,
			IsSymlink:   true,
		})
		takenNames[visibleName] = true
	}

	return resolvedEntries, shadowedNames
}

// Symlink is a symbolic link node
type Symlink struct {
	fusefs.Inode

	fs      *IRODSFS
	inodeID uint64
	path    string // the visible path, without SymlinkSuffix
	target  string // empty until the target is read
	mutex   sync.RWMutex
}

// NewSymlink creates a new Symlink. The target may be empty, in which case it is
// read from iRODS on the first Readlink.
func NewSymlink(fs *IRODSFS, inodeID uint64, path string, target string) *Symlink {
	return &Symlink{
		fs:      fs,
		inodeID: inodeID,
		path:    path,
		target:  target,
	}
}

func (symlink *Symlink) getStableAttr() fusefs.StableAttr {
	return fusefs.StableAttr{
		Mode: fuse.S_IFLNK,
		Ino:  symlink.inodeID,
	}
}

// getStoredIRODSPath returns the irods path of the data object storing the link
func (symlink *Symlink) getStoredIRODSPath() (string, syscall.Errno) {
	vpathEntry := symlink.fs.vpathManager.GetClosestEntry(symlink.path)
	if vpathEntry == nil {
		symlink.fs.logger.Errorf("failed to get VPath Entry for %q", symlink.path)
		return "", syscall.EREMOTEIO
	}

	// Virtual Dir
	if vpathEntry.IsVirtualDirEntry() {
		symlink.fs.logger.Errorf("failed to get a symbolic link from a virtual dir mapping")
		return "", syscall.EREMOTEIO
	}

	err := ensureVPathEntryIsIRODSEntry(symlink.fs.fsClient, vpathEntry)
	if err != nil {
		symlink.fs.logger.Error(err)
		return "", syscall.EREMOTEIO
	}

	irodsPath, err := vpathEntry.GetIRODSPath(symlink.path)
	if err != nil {
		symlink.fs.logger.Error(err)
		return "", syscall.EREMOTEIO
	}

	return SymlinkStoredName(irodsPath), fusefs.OK
}

// Getattr returns stat of the symbolic link
func (symlink *Symlink) Getattr(ctx context.Context, fh fusefs.FileHandle, out *fuse.AttrOut) syscall.Errno {
	if symlink.fs.terminated.Load() {
		return syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(symlink.fs.logger)

	operID := symlink.fs.GetNextOperationID()
	symlink.fs.logger.Infof("Calling Getattr (%d) - %q", operID, symlink.path)
	defer symlink.fs.logger.Infof("Called Getattr (%d) - %q", operID, symlink.path)

	symlink.mutex.RLock()
	defer symlink.mutex.RUnlock()

	storedPath, errno := symlink.getStoredIRODSPath()
	if errno != fusefs.OK {
		return errno
	}

	return symlink.fs.IRODSGetattrSymlink(ctx, storedPath, out)
}

// Readlink returns the target of the symbolic link
func (symlink *Symlink) Readlink(ctx context.Context) ([]byte, syscall.Errno) {
	if symlink.fs.terminated.Load() {
		return nil, syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(symlink.fs.logger)

	operID := symlink.fs.GetNextOperationID()
	symlink.fs.logger.Infof("Calling Readlink (%d) - %q", operID, symlink.path)
	defer symlink.fs.logger.Infof("Called Readlink (%d) - %q", operID, symlink.path)

	symlink.mutex.RLock()
	target := symlink.target
	symlink.mutex.RUnlock()

	if len(target) > 0 {
		return []byte(target), fusefs.OK
	}

	storedPath, errno := symlink.getStoredIRODSPath()
	if errno != fusefs.OK {
		return nil, errno
	}

	target, errno = symlink.fs.IRODSReadlink(ctx, storedPath)
	if errno != fusefs.OK {
		return nil, errno
	}

	symlink.mutex.Lock()
	symlink.target = target
	symlink.mutex.Unlock()

	return []byte(target), fusefs.OK
}

// invalidateTarget drops the cached target so that the next Readlink reads iRODS again
func (symlink *Symlink) invalidateTarget() {
	symlink.mutex.Lock()
	defer symlink.mutex.Unlock()

	symlink.target = ""
}
