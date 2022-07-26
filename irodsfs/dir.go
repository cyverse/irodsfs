package irodsfs

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	irodsfs_common_utils "github.com/cyverse/irodsfs-common/utils"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	fuse "github.com/seaweedfs/fuse"
	fusefs "github.com/seaweedfs/fuse/fs"

	log "github.com/sirupsen/logrus"
)

// Dir is a directory node
type Dir struct {
	fs      *IRODSFS
	inodeID int64
	path    string
	mutex   sync.RWMutex // for accessing Path
}

// NewDir creates a new Dir
func NewDir(fs *IRODSFS, inodeID int64, path string) *Dir {
	return &Dir{
		fs:      fs,
		inodeID: inodeID,
		path:    path,
		mutex:   sync.RWMutex{},
	}
}

func mapDirACL(vpathEntry *irodsfs_common_vpath.VPathEntry, dir *Dir, irodsEntry *irodsclient_fs.Entry) os.FileMode {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "mapDirACL",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// we don't actually check permissions for reading file when vpathEntry is read only
	// because files with no-access for the user will not be visible
	if vpathEntry.ReadOnly {
		return 0o500
	}

	if dir.fs.config.NoPermissionCheck {
		// skip perform permission check
		// give the highest permission, but this doesn't mean that the user can write data
		// since iRODS will check permission
		return 0o700
	}

	if irodsEntry.Owner == dir.fs.config.ClientUser {
		// mine
		return 0o700
	}

	logger.Debugf("Checking ACL information of the Entry for %s and user %s", irodsEntry.Path, dir.fs.config.ClientUser)
	defer logger.Debugf("Checked ACL information of the Entry for %s and user %s", irodsEntry.Path, dir.fs.config.ClientUser)

	logger.Infof("Checking ACL info for %s", irodsEntry.Path)
	accesses, err := dir.fs.fsClient.ListDirACLs(irodsEntry.Path)
	if err != nil {
		logger.Errorf("failed to get ACL information of the Entry for %s", irodsEntry.Path)
	}

	logger.Infof("Checked ACL info for %s, %d ACL entries", irodsEntry.Path, len(accesses))

	var highestPermission os.FileMode = 0o500
	for _, access := range accesses {
		if access.UserType == irodsclient_types.IRODSUserRodsUser && access.UserName == dir.fs.config.ClientUser {
			// found
			switch access.AccessLevel {
			case irodsclient_types.IRODSAccessLevelOwner:
				// highest, don't need to continue
				return 0o700
			case irodsclient_types.IRODSAccessLevelWrite:
				if highestPermission < 0o700 {
					highestPermission = 0o700
				}
			case irodsclient_types.IRODSAccessLevelRead:
				if highestPermission < 0o500 {
					highestPermission = 0o500
				}
			case irodsclient_types.IRODSAccessLevelNone:
				// nothing
			}
		} else if access.UserType == irodsclient_types.IRODSUserRodsGroup {
			if _, ok := dir.fs.userGroupsMap[access.UserName]; ok {
				// my group
				switch access.AccessLevel {
				case irodsclient_types.IRODSAccessLevelOwner:
					// highest, don't need to continue
					return 0o700
				case irodsclient_types.IRODSAccessLevelWrite:
					if highestPermission < 0o700 {
						highestPermission = 0o700
					}
				case irodsclient_types.IRODSAccessLevelRead:
					if highestPermission < 0o500 {
						highestPermission = 0o500
					}
				case irodsclient_types.IRODSAccessLevelNone:
					// nothing
				}
			}
		}
	}

	logger.Debugf("failed to find ACL information of the Entry for %s and user %s", irodsEntry.Path, dir.fs.config.ClientUser)
	return highestPermission
}

// Attr returns stat of file entry
func (dir *Dir) Attr(ctx context.Context, attr *fuse.Attr) error {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Attr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// apply pending update if exists
	dir.fs.fileMetaUpdater.Apply(dir)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Attr (%d) - %s", operID, dir.path)
	defer logger.Infof("Called Attr (%d) - %s", operID, dir.path)

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", dir.path)
		return syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		if vpathEntry.Path == dir.path {
			attr.Inode = uint64(vpathEntry.VirtualDirEntry.ID)
			attr.Uid = dir.fs.uid
			attr.Gid = dir.fs.gid
			attr.Ctime = vpathEntry.VirtualDirEntry.CreateTime
			attr.Mtime = vpathEntry.VirtualDirEntry.ModifyTime
			attr.Atime = vpathEntry.VirtualDirEntry.ModifyTime
			attr.Size = uint64(vpathEntry.VirtualDirEntry.Size)

			attr.Mode = os.ModeDir | 0o400
			return nil
		}
		return syscall.ENOENT
	} else if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		if vpathEntry.IRODSEntry.Type != irodsclient_fs.DirectoryEntry {
			logger.Errorf("failed to get dir attribute from a data object")
			return syscall.EREMOTEIO
		}

		irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
		if err != nil {
			logger.WithError(err).Errorf("failed to get iRODS path")
			return syscall.EREMOTEIO
		}

		irodsEntry, err := dir.fs.fsClient.Stat(irodsPath)
		if err != nil {
			if irodsclient_types.IsFileNotFoundError(err) {
				logger.WithError(err).Debugf("failed to find a file - %s", irodsPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return syscall.EREMOTEIO
		}

		attr.Inode = uint64(irodsEntry.ID)
		attr.Uid = dir.fs.uid
		attr.Gid = dir.fs.gid
		attr.Ctime = irodsEntry.CreateTime
		attr.Mtime = irodsEntry.ModifyTime
		attr.Atime = irodsEntry.ModifyTime
		attr.Size = 0
		attr.Mode = os.ModeDir | mapDirACL(vpathEntry, dir, irodsEntry)

		return nil
	}

	logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
	return syscall.EREMOTEIO
}

// Setattr sets dir attributes
func (dir *Dir) Setattr(ctx context.Context, req *fuse.SetattrRequest, resp *fuse.SetattrResponse) error {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Setattr",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	if req.Valid.Mode() {
		// chmod
		// not supported
		return syscall.EOPNOTSUPP
	} else if req.Valid.Atime() || req.Valid.AtimeNow() || req.Valid.Mtime() || req.Valid.MtimeNow() {
		// changing date
		// not supported
		return syscall.EOPNOTSUPP
	} else if req.Valid.Gid() || req.Valid.Uid() {
		// changing ownership
		// not supported
		return syscall.EOPNOTSUPP
	}

	return nil
}

// Lookup returns a node for the path
func (dir *Dir) Lookup(ctx context.Context, name string) (fusefs.Node, error) {
	if dir.fs.terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Lookup",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// apply pending update if exists
	dir.fs.fileMetaUpdater.Apply(dir)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	targetPath := irodsfs_common_utils.JoinPath(dir.path, name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Lookup (%d) - %s", operID, targetPath)
	defer logger.Infof("Called Lookup (%d) - %s", operID, targetPath)

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", targetPath)
		return nil, syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		if vpathEntry.Path == targetPath {
			return &Dir{
				fs:      dir.fs,
				inodeID: vpathEntry.VirtualDirEntry.ID,
				path:    targetPath,
			}, nil
		}
		return nil, syscall.ENOENT
	} else if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return nil, syscall.EREMOTEIO
		}

		irodsEntry, err := dir.fs.fsClient.Stat(irodsPath)
		if err != nil {
			if irodsclient_types.IsFileNotFoundError(err) {
				logger.WithError(err).Debugf("failed to find a file - %s", irodsPath)
				return nil, syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return nil, syscall.EREMOTEIO
		}

		switch irodsEntry.Type {
		case irodsclient_fs.FileEntry:
			newVPathEntry := irodsfs_common_vpath.NewVPathEntryFromIRODSFSEntry(targetPath, irodsEntry, vpathEntry.ReadOnly)
			return NewFile(dir.fs, irodsEntry.ID, targetPath, newVPathEntry), nil
		case irodsclient_fs.DirectoryEntry:
			return NewDir(dir.fs, irodsEntry.ID, targetPath), nil
		default:
			logger.Errorf("unknown entry type - %s", irodsEntry.Type)
			return nil, syscall.EREMOTEIO
		}
	} else {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return nil, syscall.EREMOTEIO
	}
}

// ReadDirAll returns directory entries
func (dir *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	if dir.fs.terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "ReadDirAll",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// apply pending update if exists
	dir.fs.fileMetaUpdater.Apply(dir)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling ReadDirAll (%d) - %s", operID, dir.path)
	defer logger.Infof("Called ReadDirAll (%d) - %s", operID, dir.path)

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(dir.path)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", dir.path)
		return nil, syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		if vpathEntry.Path == dir.path {
			dirEntries := []fuse.Dirent{}

			for _, entry := range vpathEntry.VirtualDirEntry.DirEntries {
				if entry.Type == irodsfs_common_vpath.VPathVirtualDir {
					dirEntry := fuse.Dirent{
						Inode: uint64(entry.VirtualDirEntry.ID),
						Type:  fuse.DT_Dir,
						Name:  entry.VirtualDirEntry.Name,
					}

					dirEntries = append(dirEntries, dirEntry)
				} else if entry.Type == irodsfs_common_vpath.VPathIRODS {
					entryType := fuse.DT_File

					switch entry.IRODSEntry.Type {
					case irodsclient_fs.FileEntry:
						entryType = fuse.DT_File
					case irodsclient_fs.DirectoryEntry:
						entryType = fuse.DT_Dir
					default:
						logger.Errorf("unknown entry type - %s", entry.Type)
						return nil, syscall.EREMOTEIO
					}

					dirEntry := fuse.Dirent{
						Inode: uint64(entry.IRODSEntry.ID),
						Type:  entryType,
						Name:  irodsfs_common_utils.GetFileName(entry.Path),
					}

					dirEntries = append(dirEntries, dirEntry)
				} else {
					logger.Errorf("unknown VPath Entry type : %s", entry.Type)
					return nil, syscall.EREMOTEIO
				}
			}

			return dirEntries, nil
		}
		return nil, syscall.ENOENT
	} else if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		irodsPath, err := vpathEntry.GetIRODSPath(dir.path)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return nil, syscall.EREMOTEIO
		}

		irodsEntries, err := dir.fs.fsClient.List(irodsPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to list - %s", irodsPath)
			return nil, syscall.EREMOTEIO
		}

		dirEntries := []fuse.Dirent{}

		for _, irodsEntry := range irodsEntries {
			entryType := fuse.DT_File

			switch irodsEntry.Type {
			case irodsclient_fs.FileEntry:
				entryType = fuse.DT_File
			case irodsclient_fs.DirectoryEntry:
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
			logger.Debugf("Entry - %s %s", irodsPath, irodsEntry.Name)
		}

		if !dir.fs.config.NoPermissionCheck && !vpathEntry.ReadOnly {
			// list ACLs
			// this caches all ACLs of entries in irodsPath, so make future ACL queries fast
			_, err = dir.fs.fsClient.ListACLsForEntries(irodsPath)
			if err != nil {
				logger.WithError(err).Errorf("failed to list ACLs - %s", irodsPath)
				return nil, syscall.EREMOTEIO
			}
		}

		return dirEntries, nil
	} else {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return nil, syscall.EREMOTEIO
	}
}

// Remove removes a node for the path
func (dir *Dir) Remove(ctx context.Context, req *fuse.RemoveRequest) error {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Remove",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// apply pending update if exists
	dir.fs.fileMetaUpdater.Apply(dir)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	targetPath := irodsfs_common_utils.JoinPath(dir.path, req.Name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Remove (%d) - %s", operID, targetPath)
	defer logger.Infof("Called Remove (%d) - %s", operID, targetPath)

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", targetPath)
		return syscall.EREMOTEIO
	}

	if vpathEntry.Path == targetPath {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove mapped entry - %s", vpathEntry.Path)
		logger.Error(err)
		return syscall.EACCES
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove an entry on a read-only directory - %s", vpathEntry.Path)
		logger.Error(err)
		return syscall.EACCES
	} else if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		if vpathEntry.ReadOnly {
			// failed to remove. read only
			err := fmt.Errorf("failed to remove an entry on a read-only directory - %s", vpathEntry.Path)
			logger.Error(err)
			return syscall.EACCES
		}

		irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return syscall.EREMOTEIO
		}

		irodsEntry, err := dir.fs.fsClient.Stat(irodsPath)
		if err != nil {
			if irodsclient_types.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return syscall.EREMOTEIO
		}

		switch irodsEntry.Type {
		case irodsclient_fs.FileEntry:
			err = dir.fs.fsClient.RemoveFile(irodsPath, true)
			if err != nil {
				if irodsclient_types.IsFileNotFoundError(err) {
					logger.WithError(err).Errorf("failed to find a file - %s", irodsPath)
					return syscall.ENOENT
				}

				logger.WithError(err).Errorf("failed to remove a file - %s", irodsPath)
				return syscall.EREMOTEIO
			}
			return nil
		case irodsclient_fs.DirectoryEntry:
			err = dir.fs.fsClient.RemoveDir(irodsPath, false, true)
			if err != nil {
				if irodsclient_types.IsFileNotFoundError(err) {
					logger.WithError(err).Errorf("failed to find a dir - %s", irodsPath)
					return syscall.ENOENT
				} else if irodsclient_types.IsCollectionNotEmptyError(err) {
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
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return syscall.EREMOTEIO
	}
}

// Mkdir makes a directory node for the path
func (dir *Dir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fusefs.Node, error) {
	if dir.fs.terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Mkdir",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// apply pending update if exists
	dir.fs.fileMetaUpdater.Apply(dir)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	targetPath := irodsfs_common_utils.JoinPath(dir.path, req.Name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Mkdir (%d) - %s", operID, targetPath)
	defer logger.Infof("Called Mkdir (%d) - %s", operID, targetPath)

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", targetPath)
		return nil, syscall.EREMOTEIO
	}

	if vpathEntry.Path == targetPath {
		// failed to create. read only
		err := fmt.Errorf("failed to recreate mapped entry - %s", vpathEntry.Path)
		logger.Error(err)
		return nil, syscall.EACCES
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// failed to create. read only
		err := fmt.Errorf("failed to make a new entry on a read-only directory  - %s", vpathEntry.Path)
		logger.Error(err)
		return nil, syscall.EACCES
	} else if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		if vpathEntry.ReadOnly {
			err := fmt.Errorf("failed to make a new entry on a read-only directory - %s", vpathEntry.Path)
			logger.Error(err)
			return nil, syscall.EACCES
		}

		irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return nil, syscall.EREMOTEIO
		}

		err = dir.fs.fsClient.MakeDir(irodsPath, false)
		if err != nil {
			logger.WithError(err).Errorf("failed to make a dir - %s", irodsPath)
			return nil, syscall.EREMOTEIO
		}

		entry, err := dir.fs.fsClient.Stat(irodsPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return nil, syscall.EREMOTEIO
		}

		return &Dir{
			fs:      dir.fs,
			inodeID: entry.ID,
			path:    targetPath,
		}, nil
	} else {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return nil, syscall.EREMOTEIO
	}
}

// Rename renames a node for the path
func (dir *Dir) Rename(ctx context.Context, req *fuse.RenameRequest, newDir fusefs.Node) error {
	if dir.fs.terminated {
		return syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Rename",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// apply pending update if exists
	dir.fs.fileMetaUpdater.Apply(dir)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	targetSrcPath := irodsfs_common_utils.JoinPath(dir.path, req.OldName)

	newdir := newDir.(*Dir)

	newdir.mutex.RLock()
	defer newdir.mutex.RUnlock()

	targetDestPath := irodsfs_common_utils.JoinPath(newdir.path, req.NewName)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Rename (%d) - %s to %s", operID, targetSrcPath, targetDestPath)
	defer logger.Infof("Called Rename (%d) - %s to %s", operID, targetSrcPath, targetDestPath)

	vpathSrcEntry := dir.fs.vpathManager.GetClosestEntry(targetSrcPath)
	if vpathSrcEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", targetSrcPath)
		return syscall.EREMOTEIO
	}

	vpathDestEntry := dir.fs.vpathManager.GetClosestEntry(targetDestPath)
	if vpathDestEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", targetDestPath)
		return syscall.EREMOTEIO
	}

	if vpathSrcEntry.Path == targetSrcPath {
		// failed to remove. read only
		err := fmt.Errorf("failed to rename a read-only entry - %s", vpathSrcEntry.Path)
		logger.Error(err)
		return syscall.EACCES
	}

	if vpathDestEntry.Path == targetDestPath {
		// failed to remove. read only
		err := fmt.Errorf("failed to remove a read-only entry - %s", vpathDestEntry.Path)
		logger.Error(err)
		return syscall.EACCES
	}

	if vpathSrcEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// failed to remove. read only
		err := fmt.Errorf("failed to rename a read-only entry - %s", vpathSrcEntry.Path)
		logger.Error(err)
		return syscall.EACCES
	} else if vpathDestEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// failed to remove. read only
		err := fmt.Errorf("failed to rename a read-only entry - %s", vpathDestEntry.Path)
		logger.Error(err)
		return syscall.EACCES
	} else if vpathSrcEntry.Type == irodsfs_common_vpath.VPathIRODS && vpathDestEntry.Type == irodsfs_common_vpath.VPathIRODS {
		if vpathSrcEntry.ReadOnly {
			// failed to remove. read only
			err := fmt.Errorf("failed to remove a read-only entry - %s", vpathSrcEntry.Path)
			logger.Error(err)
			return syscall.EACCES
		}

		if vpathDestEntry.ReadOnly {
			// failed to remove. read only
			err := fmt.Errorf("failed to remove a read-only entry - %s", vpathDestEntry.Path)
			logger.Error(err)
			return syscall.EACCES
		}

		irodsSrcPath, err := vpathSrcEntry.GetIRODSPath(targetSrcPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return syscall.EREMOTEIO
		}

		irodsDestPath, err := vpathDestEntry.GetIRODSPath(targetDestPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return syscall.EREMOTEIO
		}

		irodsEntry, err := dir.fs.fsClient.Stat(irodsSrcPath)
		if err != nil {
			if irodsclient_types.IsFileNotFoundError(err) {
				logger.WithError(err).Errorf("failed to find a file - %s", irodsSrcPath)
				return syscall.ENOENT
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsSrcPath)
			return syscall.EREMOTEIO
		}

		switch irodsEntry.Type {
		case irodsclient_fs.DirectoryEntry:
			// lock first
			openFilePaths := dir.fs.fileHandleMap.ListPathsInDir(irodsSrcPath)
			for _, openFilePath := range openFilePaths {
				handlesOpened := dir.fs.fileHandleMap.ListByPath(openFilePath)
				for _, handle := range handlesOpened {
					handle.mutex.Lock()
					defer handle.mutex.Unlock()
				}
			}

			err = dir.fs.fsClient.RenameDirToDir(irodsSrcPath, irodsDestPath)
			if err != nil {
				logger.WithError(err).Errorf("failed to rename dir - %s to %s", irodsSrcPath, irodsDestPath)
				return syscall.EREMOTEIO
			}

			// report update to fileHandleMap
			dir.fs.fileHandleMap.RenameDir(irodsSrcPath, irodsDestPath)

			// report update of path
			if irodsEntry.ID > 0 {
				dir.fs.fileMetaUpdater.Add(irodsEntry.ID, targetDestPath)
			}
			return nil
		case irodsclient_fs.FileEntry:
			destEntry, err := dir.fs.fsClient.Stat(irodsDestPath)
			if err != nil {
				if !irodsclient_types.IsFileNotFoundError(err) {
					logger.WithError(err).Errorf("failed to stat - %s", irodsDestPath)
					return syscall.EREMOTEIO
				}
			} else {
				// no error
				if destEntry.ID > 0 {
					// delete first
					err = dir.fs.fsClient.RemoveFile(irodsDestPath, true)
					if err != nil {
						logger.WithError(err).Errorf("failed to delete file - %s", irodsDestPath)
						return syscall.EREMOTEIO
					}
				}
			}

			// lock first
			handlesOpened := dir.fs.fileHandleMap.ListByPath(irodsSrcPath)
			for _, handle := range handlesOpened {
				handle.mutex.Lock()
				defer handle.mutex.Unlock()
			}

			err = dir.fs.fsClient.RenameFileToFile(irodsSrcPath, irodsDestPath)
			if err != nil {
				logger.WithError(err).Errorf("failed to rename file - %s to %s", irodsSrcPath, irodsDestPath)
				return syscall.EREMOTEIO
			}

			// report update to fileHandleMap
			dir.fs.fileHandleMap.Rename(irodsSrcPath, irodsDestPath)

			// report update of path
			if irodsEntry.ID > 0 {
				dir.fs.fileMetaUpdater.Add(irodsEntry.ID, targetDestPath)
			}
			return nil
		default:
			logger.Errorf("unknown entry type - %s", irodsEntry.Type)
			return syscall.EREMOTEIO
		}
	} else {
		logger.Errorf("unknown VPath Entry type : %s", vpathSrcEntry.Type)
		return syscall.EREMOTEIO
	}
}

// Create creates a file for the path and returns file handle
func (dir *Dir) Create(ctx context.Context, req *fuse.CreateRequest, resp *fuse.CreateResponse) (fusefs.Node, fusefs.Handle, error) {
	if dir.fs.terminated {
		return nil, nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "Dir",
		"function": "Create",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// apply pending update if exists
	dir.fs.fileMetaUpdater.Apply(dir)

	dir.mutex.RLock()
	defer dir.mutex.RUnlock()

	targetPath := irodsfs_common_utils.JoinPath(dir.path, req.Name)

	operID := dir.fs.GetNextOperationID()
	logger.Infof("Calling Create (%d) - %s", operID, targetPath)
	defer logger.Infof("Called Create (%d) - %s", operID, targetPath)

	var openMode string

	if req.Flags.IsWriteOnly() {
		openMode = string(irodsclient_types.FileOpenModeWriteOnly)

		if req.Flags&fuse.OpenAppend == fuse.OpenAppend {
			// append
			openMode = string(irodsclient_types.FileOpenModeAppend)
		} else if req.Flags&fuse.OpenTruncate == fuse.OpenTruncate {
			// truncate
			openMode = string(irodsclient_types.FileOpenModeWriteTruncate)
		}
		resp.Flags |= fuse.OpenDirectIO
	} else if req.Flags.IsReadWrite() {
		openMode = string(irodsclient_types.FileOpenModeReadWrite)
	} else {
		logger.Errorf("unknown file open mode - %s", req.Flags.String())
		return nil, nil, syscall.EACCES
	}

	vpathEntry := dir.fs.vpathManager.GetClosestEntry(targetPath)
	if vpathEntry == nil {
		logger.Errorf("failed to get VPath Entry for %s", targetPath)
		return nil, nil, syscall.EREMOTEIO
	}

	if vpathEntry.Path == targetPath {
		// failed to create. read only
		err := fmt.Errorf("failed to recreate mapped entry - %s", vpathEntry.Path)
		logger.Error(err)
		return nil, nil, syscall.EACCES
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		// failed to create. read only
		err := fmt.Errorf("failed to make a new entry on a read-only directory - %s", vpathEntry.Path)
		logger.Error(err)
		return nil, nil, syscall.EACCES
	} else if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		if vpathEntry.ReadOnly {
			// failed to create. read only
			err := fmt.Errorf("failed to make a new entry on a read-only directory - %s", vpathEntry.Path)
			logger.Error(err)
			return nil, nil, syscall.EACCES
		}

		irodsPath, err := vpathEntry.GetIRODSPath(targetPath)
		if err != nil {
			logger.WithError(err).Errorf("failed to get IRODS path")
			return nil, nil, syscall.EREMOTEIO
		}

		handle, err := dir.fs.fsClient.CreateFile(irodsPath, "", openMode)
		if err != nil {
			logger.WithError(err).Errorf("failed to create a file - %s", irodsPath)
			return nil, nil, syscall.EREMOTEIO
		}

		irodsEntry, err := dir.fs.fsClient.Stat(irodsPath)
		if err != nil {
			if irodsclient_types.IsFileNotFoundError(err) {
				logger.WithError(err).Infof("failed to find a file - %s", irodsPath)
				return nil, nil, syscall.EREMOTEIO
			}

			logger.WithError(err).Errorf("failed to stat - %s", irodsPath)
			return nil, nil, syscall.EREMOTEIO
		}

		newVPathEntry := irodsfs_common_vpath.NewVPathEntryFromIRODSFSEntry(targetPath, irodsEntry, vpathEntry.ReadOnly)
		file := NewFile(dir.fs, irodsEntry.ID, targetPath, newVPathEntry)

		if dir.fs.instanceReportClient != nil {
			dir.fs.instanceReportClient.StartFileAccess(handle)
		}

		fileHandle := NewFileHandle(file, handle)

		// add to file handle map
		dir.fs.fileHandleMap.Add(fileHandle)

		return file, fileHandle, nil
	} else {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return nil, nil, syscall.EREMOTEIO
	}
}

/*
func (dir *Dir) Symlink(ctx context.Context, req *fuse.SymlinkRequest) (fusefs.Node, error) {
}

func (dir *Dir) Readlink(ctx context.Context, req *fuse.ReadlinkRequest) (string, error) {

}
*/
