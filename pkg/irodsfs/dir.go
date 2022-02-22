package irodsfs

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"syscall"

	fuse "bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	"github.com/cyverse/irodsfs/pkg/io"
	"github.com/cyverse/irodsfs/pkg/irodsapi"
	"github.com/cyverse/irodsfs/pkg/utils"
	"github.com/cyverse/irodsfs/pkg/vfs"
	log "github.com/sirupsen/logrus"
)

// Dir is a directory node
type Dir struct {
	FS      *IRODSFS
	InodeID int64
	Path    string
	Mutex   sync.RWMutex // for accessing Path
}

func mapDirACL(vfsEntry *vfs.VFSEntry, dir *Dir, irodsEntry *irodsapi.IRODSEntry) os.FileMode {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "mapDirACL",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// we don't actually check permissions for reading file when vfsEntry is read only
	// because files with no-access for the user will not be visible
	if vfsEntry.ReadOnly {
		return 0o400
	}

	if irodsEntry.Owner == dir.FS.Config.ClientUser {
		// mine
		return 0o700
	}

	logger.Infof("Checking ACL information of the Entry for %s and user %s", irodsEntry.Path, dir.FS.Config.ClientUser)
	defer logger.Infof("Checked ACL information of the Entry for %s and user %s", irodsEntry.Path, dir.FS.Config.ClientUser)

	accesses, err := dir.FS.IRODSClient.ListDirACLs(irodsEntry.Path)
	if err != nil {
		logger.Errorf("failed to get ACL information of the Entry for %s", irodsEntry.Path)
	}

	var highestPermission os.FileMode = 0o400
	for _, access := range accesses {
		if access.UserType == irodsapi.IRODSUserRodsUser && access.UserName == dir.FS.Config.ClientUser {
			// found
			switch access.AccessLevel {
			case irodsapi.IRODSAccessLevelOwner:
				// highest, don't need to continue
				return 0o700
			case irodsapi.IRODSAccessLevelWrite:
				if highestPermission < 0o600 {
					highestPermission = 0o600
				}
			case irodsapi.IRODSAccessLevelRead:
				if highestPermission < 0o400 {
					highestPermission = 0o400
				}
			case irodsapi.IRODSAccessLevelNone:
				// nothing
			}
		} else if access.UserType == irodsapi.IRODSUserRodsGroup {
			if _, ok := dir.FS.UserGroupsMap[access.UserName]; ok {
				// my group
				switch access.AccessLevel {
				case irodsapi.IRODSAccessLevelOwner:
					// highest, don't need to continue
					return 0o700
				case irodsapi.IRODSAccessLevelWrite:
					if highestPermission < 0o600 {
						highestPermission = 0o600
					}
				case irodsapi.IRODSAccessLevelRead:
					if highestPermission < 0o400 {
						highestPermission = 0o400
					}
				case irodsapi.IRODSAccessLevelNone:
					// nothing
				}
			}
		}
	}

	logger.Errorf("failed to find ACL information of the Entry for %s and user %s", irodsEntry.Path, dir.FS.Config.ClientUser)
	return highestPermission
}

// Attr returns stat of file entry
func (dir *Dir) Attr(ctx context.Context, attr *fuse.Attr) error {
	if dir.FS.Terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Attr",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	dir.FS.FileMetaUpdater.Apply(dir)

	dir.Mutex.RLock()
	defer dir.Mutex.RUnlock()

	operID := dir.FS.GetNextOperationID()
	logger.Infof("Calling Attr (%d) - %s", operID, dir.Path)
	defer logger.Infof("Called Attr (%d) - %s", operID, dir.Path)

	vfsEntry := dir.FS.VFS.GetClosestEntry(dir.Path)
	if vfsEntry == nil {
		logger.Errorf("failed to get VFS Entry for %s", dir.Path)
		return syscall.EREMOTEIO
	}

	if vfsEntry.Type == vfs.VFSVirtualDirEntryType {
		if vfsEntry.Path == dir.Path {
			attr.Inode = uint64(vfsEntry.VirtualDirEntry.ID)
			attr.Uid = dir.FS.UID
			attr.Gid = dir.FS.GID
			attr.Ctime = vfsEntry.VirtualDirEntry.CreateTime
			attr.Mtime = vfsEntry.VirtualDirEntry.ModifyTime
			attr.Atime = vfsEntry.VirtualDirEntry.ModifyTime
			attr.Size = uint64(vfsEntry.VirtualDirEntry.Size)

			attr.Mode = os.ModeDir | 0o400
			return nil
		}
		return syscall.ENOENT
	} else if vfsEntry.Type == vfs.VFSIRODSEntryType {
		if vfsEntry.IRODSEntry.Type != irodsapi.DirectoryEntry {
			logger.Errorf("failed to get dir attribute from a data object")
			return syscall.EREMOTEIO
		}

		irodsPath, err := vfsEntry.GetIRODSPath(dir.Path)
		if err != nil {
			logger.WithError(err).Errorf("failed to get iRODS path")
			return syscall.EREMOTEIO
		}

		irodsEntry, err := dir.FS.IRODSClient.Stat(irodsPath)
		if err != nil {
			if irodsapi.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return syscall.EREMOTEIO
		}

		attr.Inode = uint64(irodsEntry.ID)
		attr.Uid = dir.FS.UID
		attr.Gid = dir.FS.GID
		attr.Ctime = irodsEntry.CreateTime
		attr.Mtime = irodsEntry.ModifyTime
		attr.Atime = irodsEntry.ModifyTime
		attr.Size = 0
		attr.Mode = os.ModeDir | mapDirACL(vfsEntry, dir, irodsEntry)
		return nil
	}

	logger.Errorf("unknown VFS Entry type : %s", vfsEntry.Type)
	return syscall.EREMOTEIO
}

// Lookup returns a node for the path
func (dir *Dir) Lookup(ctx context.Context, name string) (fusefs.Node, error) {
	if dir.FS.Terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Lookup",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	dir.FS.FileMetaUpdater.Apply(dir)

	dir.Mutex.RLock()
	defer dir.Mutex.RUnlock()

	targetPath := utils.JoinPath(dir.Path, name)

	operID := dir.FS.GetNextOperationID()
	logger.Infof("Calling Lookup (%d) - %s", operID, targetPath)
	defer logger.Infof("Called Lookup (%d) - %s", operID, targetPath)

	vfsEntry := dir.FS.VFS.GetClosestEntry(targetPath)
	if vfsEntry == nil {
		logger.Errorf("failed to get VFS Entry for %s", targetPath)
		return nil, syscall.EREMOTEIO
	}

	if vfsEntry.Type == vfs.VFSVirtualDirEntryType {
		if vfsEntry.Path == targetPath {
			return &Dir{
				FS:      dir.FS,
				InodeID: vfsEntry.VirtualDirEntry.ID,
				Path:    targetPath,
			}, nil
		}
		return nil, syscall.ENOENT
	} else if vfsEntry.Type == vfs.VFSIRODSEntryType {
		irodsPath, err := vfsEntry.GetIRODSPath(targetPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return nil, syscall.EREMOTEIO
		}

		irodsEntry, err := dir.FS.IRODSClient.Stat(irodsPath)
		if err != nil {
			if irodsapi.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return nil, syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return nil, syscall.EREMOTEIO
		}

		switch irodsEntry.Type {
		case irodsapi.FileEntry:
			return &File{
				FS:      dir.FS,
				InodeID: irodsEntry.ID,
				Path:    targetPath,
				Entry:   vfs.NewVFSEntryFromIRODSFSEntry(targetPath, irodsEntry, vfsEntry.ReadOnly),
			}, nil
		case irodsapi.DirectoryEntry:
			return &Dir{
				FS:      dir.FS,
				InodeID: irodsEntry.ID,
				Path:    targetPath,
			}, nil
		default:
			logger.Errorf("unknown entry type - %s", irodsEntry.Type)
			return nil, syscall.EREMOTEIO
		}
	} else {
		logger.Errorf("unknown VFS Entry type : %s", vfsEntry.Type)
		return nil, syscall.EREMOTEIO
	}
}

// ReadDirAll returns directory entries
func (dir *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	if dir.FS.Terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "ReadDirAll",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	dir.FS.FileMetaUpdater.Apply(dir)

	dir.Mutex.RLock()
	defer dir.Mutex.RUnlock()

	operID := dir.FS.GetNextOperationID()
	logger.Infof("Calling ReadDirAll (%d) - %s", operID, dir.Path)
	defer logger.Infof("Called ReadDirAll (%d) - %s", operID, dir.Path)

	vfsEntry := dir.FS.VFS.GetClosestEntry(dir.Path)
	if vfsEntry == nil {
		logger.Errorf("failed to get VFS Entry for %s", dir.Path)
		return nil, syscall.EREMOTEIO
	}

	if vfsEntry.Type == vfs.VFSVirtualDirEntryType {
		if vfsEntry.Path == dir.Path {
			dirEntries := []fuse.Dirent{}

			for _, entry := range vfsEntry.VirtualDirEntry.DirEntries {
				if entry.Type == vfs.VFSVirtualDirEntryType {
					dirEntry := fuse.Dirent{
						Inode: uint64(entry.VirtualDirEntry.ID),
						Type:  fuse.DT_Dir,
						Name:  entry.VirtualDirEntry.Name,
					}

					dirEntries = append(dirEntries, dirEntry)
				} else if entry.Type == vfs.VFSIRODSEntryType {
					entryType := fuse.DT_File

					switch entry.IRODSEntry.Type {
					case irodsapi.FileEntry:
						entryType = fuse.DT_File
					case irodsapi.DirectoryEntry:
						entryType = fuse.DT_Dir
					default:
						logger.Errorf("unknown entry type - %s", entry.Type)
						return nil, syscall.EREMOTEIO
					}

					dirEntry := fuse.Dirent{
						Inode: uint64(entry.IRODSEntry.ID),
						Type:  entryType,
						Name:  utils.GetFileName(entry.Path),
					}

					dirEntries = append(dirEntries, dirEntry)
				} else {
					logger.Errorf("unknown VFS Entry type : %s", entry.Type)
					return nil, syscall.EREMOTEIO
				}
			}

			return dirEntries, nil
		}
		return nil, syscall.ENOENT
	} else if vfsEntry.Type == vfs.VFSIRODSEntryType {
		irodsPath, err := vfsEntry.GetIRODSPath(dir.Path)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return nil, syscall.EREMOTEIO
		}

		irodsEntries, err := dir.FS.IRODSClient.List(irodsPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to list - %s", irodsPath)
			return nil, syscall.EREMOTEIO
		}

		dirEntries := []fuse.Dirent{}

		for _, irodsEntry := range irodsEntries {
			entryType := fuse.DT_File

			switch irodsEntry.Type {
			case irodsapi.FileEntry:
				entryType = fuse.DT_File
			case irodsapi.DirectoryEntry:
				entryType = fuse.DT_Dir
			default:
				logger.Errorf("unknown entry type - %s", irodsEntry.Type)
				return nil, syscall.EREMOTEIO
			}

			dirEntry := fuse.Dirent{
				Inode: uint64(irodsEntry.ID),
				Type:  entryType,
				Name:  irodsEntry.Name,
			}

			dirEntries = append(dirEntries, dirEntry)
			logger.Infof("Entry - %s %s", irodsPath, irodsEntry.Name)
		}

		return dirEntries, nil
	} else {
		logger.Errorf("unknown VFS Entry type : %s", vfsEntry.Type)
		return nil, syscall.EREMOTEIO
	}
}

// Remove removes a node for the path
func (dir *Dir) Remove(ctx context.Context, req *fuse.RemoveRequest) error {
	if dir.FS.Terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Remove",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	dir.FS.FileMetaUpdater.Apply(dir)

	dir.Mutex.RLock()
	defer dir.Mutex.RUnlock()

	targetPath := utils.JoinPath(dir.Path, req.Name)

	operID := dir.FS.GetNextOperationID()
	logger.Infof("Calling Remove (%d) - %s", operID, targetPath)
	defer logger.Infof("Called Remove (%d) - %s", operID, targetPath)

	vfsEntry := dir.FS.VFS.GetClosestEntry(targetPath)
	if vfsEntry == nil {
		logger.Errorf("failed to get VFS Entry for %s", targetPath)
		return syscall.EREMOTEIO
	}

	if vfsEntry.Path == targetPath {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove mapped entry - %s", vfsEntry.Path)
		logger.Error(err)
		return syscall.EACCES
	}

	if vfsEntry.Type == vfs.VFSVirtualDirEntryType {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove an entry on a read-only directory - %s", vfsEntry.Path)
		logger.Error(err)
		return syscall.EACCES
	} else if vfsEntry.Type == vfs.VFSIRODSEntryType {
		if vfsEntry.ReadOnly {
			// failed to remove. read only
			err := fmt.Errorf("failed to remove an entry on a read-only directory - %s", vfsEntry.Path)
			logger.Error(err)
			return syscall.EACCES
		}

		irodsPath, err := vfsEntry.GetIRODSPath(targetPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return syscall.EREMOTEIO
		}

		irodsEntry, err := dir.FS.IRODSClient.Stat(irodsPath)
		if err != nil {
			if irodsapi.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return syscall.EREMOTEIO
		}

		switch irodsEntry.Type {
		case irodsapi.FileEntry:
			err = dir.FS.IRODSClient.RemoveFile(irodsPath, true)
			if err != nil {
				if irodsapi.IsFileNotFoundError(err) {
					logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
					return syscall.ENOENT
				}

				logger.WithError(err).Errorf("failed to remove a file - %s", irodsPath)
				return syscall.EREMOTEIO
			}
			return nil
		case irodsapi.DirectoryEntry:
			err = dir.FS.IRODSClient.RemoveDir(irodsPath, false, true)
			if err != nil {
				if irodsapi.IsFileNotFoundError(err) {
					logger.WithError(err).Errorf("failed to find a dir - %s", irodsPath)
					return syscall.ENOENT
				} else if irodsapi.IsCollectionNotEmptyError(err) {
					logger.WithError(err).Errorf("the dir is not empty - %s", irodsPath)
					return syscall.ENOTEMPTY
				}

				logger.WithError(err).Errorf("failed to remove a dir - %s", irodsPath)
				return syscall.EREMOTEIO
			}
			return nil
		default:
			logger.Errorf("unknown entry type - %s", irodsEntry.Type)
			return syscall.EREMOTEIO
		}
	} else {
		logger.Errorf("unknown VFS Entry type : %s", vfsEntry.Type)
		return syscall.EREMOTEIO
	}
}

// Mkdir makes a directory node for the path
func (dir *Dir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fusefs.Node, error) {
	if dir.FS.Terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Mkdir",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	dir.FS.FileMetaUpdater.Apply(dir)

	dir.Mutex.RLock()
	defer dir.Mutex.RUnlock()

	targetPath := utils.JoinPath(dir.Path, req.Name)

	operID := dir.FS.GetNextOperationID()
	logger.Infof("Calling Mkdir (%d) - %s", operID, targetPath)
	defer logger.Infof("Called Mkdir (%d) - %s", operID, targetPath)

	vfsEntry := dir.FS.VFS.GetClosestEntry(targetPath)
	if vfsEntry == nil {
		logger.Errorf("failed to get VFS Entry for %s", targetPath)
		return nil, syscall.EREMOTEIO
	}

	if vfsEntry.Path == targetPath {
		// failed to create. read only
		err := fmt.Errorf("failed to recreate mapped entry - %s", vfsEntry.Path)
		logger.Error(err)
		return nil, syscall.EACCES
	}

	if vfsEntry.Type == vfs.VFSVirtualDirEntryType {
		// failed to create. read only
		err := fmt.Errorf("failed to make a new entry on a read-only directory  - %s", vfsEntry.Path)
		logger.Error(err)
		return nil, syscall.EACCES
	} else if vfsEntry.Type == vfs.VFSIRODSEntryType {
		if vfsEntry.ReadOnly {
			err := fmt.Errorf("failed to make a new entry on a read-only directory - %s", vfsEntry.Path)
			logger.Error(err)
			return nil, syscall.EACCES
		}

		irodsPath, err := vfsEntry.GetIRODSPath(targetPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return nil, syscall.EREMOTEIO
		}

		err = dir.FS.IRODSClient.MakeDir(irodsPath, false)
		if err != nil {
			logger.WithError(err).Errorf("failed to make a dir - %s", irodsPath)
			return nil, syscall.EREMOTEIO
		}

		entry, err := dir.FS.IRODSClient.Stat(irodsPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return nil, syscall.EREMOTEIO
		}

		return &Dir{
			FS:      dir.FS,
			InodeID: entry.ID,
			Path:    targetPath,
		}, nil
	} else {
		logger.Errorf("unknown VFS Entry type : %s", vfsEntry.Type)
		return nil, syscall.EREMOTEIO
	}
}

// Rename renames a node for the path
func (dir *Dir) Rename(ctx context.Context, req *fuse.RenameRequest, newDir fusefs.Node) error {
	if dir.FS.Terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Rename",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	dir.FS.FileMetaUpdater.Apply(dir)

	dir.Mutex.RLock()
	defer dir.Mutex.RUnlock()

	targetSrcPath := utils.JoinPath(dir.Path, req.OldName)

	newdir := newDir.(*Dir)

	newdir.Mutex.RLock()
	defer newdir.Mutex.RUnlock()

	targetDestPath := utils.JoinPath(newdir.Path, req.NewName)

	operID := dir.FS.GetNextOperationID()
	logger.Infof("Calling Rename (%d) - %s to %s", operID, targetSrcPath, targetDestPath)
	defer logger.Infof("Called Rename (%d) - %s to %s", operID, targetSrcPath, targetDestPath)

	vfsSrcEntry := dir.FS.VFS.GetClosestEntry(targetSrcPath)
	if vfsSrcEntry == nil {
		logger.Errorf("failed to get VFS Entry for %s", targetSrcPath)
		return syscall.EREMOTEIO
	}

	vfsDestEntry := dir.FS.VFS.GetClosestEntry(targetDestPath)
	if vfsDestEntry == nil {
		logger.Errorf("failed to get VFS Entry for %s", targetDestPath)
		return syscall.EREMOTEIO
	}

	if vfsSrcEntry.Path == targetSrcPath {
		// failed to remove. read only
		err := fmt.Errorf("failed to rename a read-only entry - %s", vfsSrcEntry.Path)
		logger.Error(err)
		return syscall.EACCES
	}

	if vfsDestEntry.Path == targetDestPath {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove a read-only entry - %s", vfsDestEntry.Path)
		logger.Error(err)
		return syscall.EACCES
	}

	if vfsSrcEntry.Type == vfs.VFSVirtualDirEntryType {
		// failed to remove. read only
		err := fmt.Errorf("failed to rename a read-only entry - %s", vfsSrcEntry.Path)
		logger.Error(err)
		return syscall.EACCES
	} else if vfsDestEntry.Type == vfs.VFSVirtualDirEntryType {
		// failed to remove. read only
		err := fmt.Errorf("failed to rename a read-only entry - %s", vfsDestEntry.Path)
		logger.Error(err)
		return syscall.EACCES
	} else if vfsSrcEntry.Type == vfs.VFSIRODSEntryType && vfsDestEntry.Type == vfs.VFSIRODSEntryType {
		if vfsSrcEntry.ReadOnly {
			// failed to remove. read only
			err := fmt.Errorf("failed to remove a read-only entry - %s", vfsSrcEntry.Path)
			logger.Error(err)
			return syscall.EACCES
		}

		if vfsDestEntry.ReadOnly {
			// failed to remove. read only
			err := fmt.Errorf("failed to remove a read-only entry - %s", vfsDestEntry.Path)
			logger.Error(err)
			return syscall.EACCES
		}

		irodsSrcPath, err := vfsSrcEntry.GetIRODSPath(targetSrcPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return syscall.EREMOTEIO
		}

		irodsDestPath, err := vfsDestEntry.GetIRODSPath(targetDestPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return syscall.EREMOTEIO
		}

		irodsEntry, err := dir.FS.IRODSClient.Stat(irodsSrcPath)
		if err != nil {
			if irodsapi.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsSrcPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsSrcPath)
			return syscall.EREMOTEIO
		}

		switch irodsEntry.Type {
		case irodsapi.DirectoryEntry:
			err = dir.FS.IRODSClient.RenameDirToDir(irodsSrcPath, irodsDestPath)
			if err != nil {
				logger.WithError(err).Errorf("failed to rename dir - %s to %s", irodsSrcPath, irodsDestPath)
				return syscall.EREMOTEIO
			}

			// report update of path
			if irodsEntry.ID > 0 {
				dir.FS.FileMetaUpdater.Add(irodsEntry.ID, targetDestPath)
			}
			return nil
		case irodsapi.FileEntry:
			destEntry, err := dir.FS.IRODSClient.Stat(irodsDestPath)
			if err != nil {
				if !irodsapi.IsFileNotFoundError(err) {
					logger.WithError(err).Errorf("failed to stat - %s", irodsDestPath)
					return syscall.EREMOTEIO
				}
			} else {
				// no error
				if destEntry.ID > 0 {
					// delete first
					err = dir.FS.IRODSClient.RemoveFile(irodsDestPath, true)
					if err != nil {
						logger.WithError(err).Errorf("failed to delete file - %s", irodsDestPath)
						return syscall.EREMOTEIO
					}
				}
			}

			err = dir.FS.IRODSClient.RenameFileToFile(irodsSrcPath, irodsDestPath)
			if err != nil {
				logger.WithError(err).Errorf("failed to rename file - %s to %s", irodsSrcPath, irodsDestPath)
				return syscall.EREMOTEIO
			}

			// report update of path
			if irodsEntry.ID > 0 {
				dir.FS.FileMetaUpdater.Add(irodsEntry.ID, targetDestPath)
			}
			return nil
		default:
			logger.Errorf("unknown entry type - %s", irodsEntry.Type)
			return syscall.EREMOTEIO
		}
	} else {
		logger.Errorf("unknown VFS Entry type : %s", vfsSrcEntry.Type)
		return syscall.EREMOTEIO
	}
}

// Create creates a file for the path and returns file handle
func (dir *Dir) Create(ctx context.Context, req *fuse.CreateRequest, resp *fuse.CreateResponse) (fusefs.Node, fusefs.Handle, error) {
	if dir.FS.Terminated {
		return nil, nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Create",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	// apply pending update if exists
	dir.FS.FileMetaUpdater.Apply(dir)

	dir.Mutex.RLock()
	defer dir.Mutex.RUnlock()

	targetPath := utils.JoinPath(dir.Path, req.Name)

	operID := dir.FS.GetNextOperationID()
	logger.Infof("Calling Create (%d) - %s", operID, targetPath)
	defer logger.Infof("Called Create (%d) - %s", operID, targetPath)

	openMode := string(irodsapi.FileOpenModeReadOnly)

	if req.Flags.IsWriteOnly() {
		openMode = string(irodsapi.FileOpenModeWriteOnly)

		if req.Flags&fuse.OpenAppend == fuse.OpenAppend {
			// append
			openMode = string(irodsapi.FileOpenModeAppend)
		} else if req.Flags&fuse.OpenTruncate == fuse.OpenTruncate {
			// truncate
			openMode = string(irodsapi.FileOpenModeWriteTruncate)
		}
		resp.Flags |= fuse.OpenDirectIO
	} else if req.Flags.IsReadWrite() {
		openMode = string(irodsapi.FileOpenModeReadWrite)
	} else {
		logger.Errorf("unknown file open mode - %s", req.Flags.String())
		return nil, nil, syscall.EACCES
	}

	vfsEntry := dir.FS.VFS.GetClosestEntry(targetPath)
	if vfsEntry == nil {
		logger.Errorf("failed to get VFS Entry for %s", targetPath)
		return nil, nil, syscall.EREMOTEIO
	}

	if vfsEntry.Path == targetPath {
		// failed to create. read only
		err := fmt.Errorf("failed to recreate mapped entry - %s", vfsEntry.Path)
		logger.Error(err)
		return nil, nil, syscall.EACCES
	}

	if vfsEntry.Type == vfs.VFSVirtualDirEntryType {
		// failed to create. read only
		err := fmt.Errorf("failed to make a new entry on a read-only directory - %s", vfsEntry.Path)
		logger.Error(err)
		return nil, nil, syscall.EACCES
	} else if vfsEntry.Type == vfs.VFSIRODSEntryType {
		if vfsEntry.ReadOnly {
			// failed to create. read only
			err := fmt.Errorf("failed to make a new entry on a read-only directory - %s", vfsEntry.Path)
			logger.Error(err)
			return nil, nil, syscall.EACCES
		}

		irodsPath, err := vfsEntry.GetIRODSPath(targetPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return nil, nil, syscall.EREMOTEIO
		}

		handle, err := dir.FS.IRODSClient.CreateFile(irodsPath, "")
		if err != nil {
			logger.WithError(err).Errorf("failed to create a file - %s", irodsPath)
			return nil, nil, syscall.EREMOTEIO
		}

		err = handle.Close()
		if err != nil {
			logger.WithError(err).Errorf("failed to close - %s", irodsPath)
			return nil, nil, syscall.EREMOTEIO
		}

		fileNode, err := dir.Lookup(ctx, req.Name)
		if err != nil {
			logger.WithError(err).Errorf("failed to lookup - %s", irodsPath)
			return nil, nil, syscall.EREMOTEIO
		}

		file := fileNode.(*File)

		// reopen - to open file with openmode
		logger.Infof("Openning - %s, mode(%s)", irodsPath, openMode)
		handle, err = file.FS.IRODSClient.OpenFile(irodsPath, "", openMode)
		if err != nil {
			if irodsapi.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return nil, nil, syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to open a file - %s", irodsPath)
			return nil, nil, syscall.EREMOTEIO
		}

		if file.FS.MonitoringReporter != nil {
			file.FS.MonitoringReporter.ReportNewFileTransferStart(file.Entry.IRODSEntry.Path, handle, file.Entry.IRODSEntry.Size)
		}

		handleMutex := &sync.Mutex{}

		var writer io.Writer
		if req.Flags.IsWriteOnly() && len(dir.FS.Config.PoolHost) == 0 {
			asyncWriter := io.NewAsyncWriter(irodsPath, handle, handleMutex, dir.FS.Buffer, dir.FS.MonitoringReporter)
			//syncWriter := asyncwrite.NewSyncWriter(irodsPath, handle, handleMutex, dir.FS.MonitoringReporter)
			writer = io.NewBufferedWriter(irodsPath, asyncWriter)
		} else {
			writer = io.NewSyncWriter(irodsPath, handle, handleMutex, dir.FS.MonitoringReporter)
		}

		fileHandle := &FileHandle{
			FS:             file.FS,
			Path:           file.Path,
			Entry:          file.Entry,
			IRODSFSEntry:   file.Entry.IRODSEntry,
			FileHandle:     handle,
			FileHandleLock: handleMutex,

			Writer: writer,
		}

		return file, fileHandle, nil
	} else {
		logger.Errorf("unknown VFS Entry type : %s", vfsEntry.Type)
		return nil, nil, syscall.EREMOTEIO
	}
}
