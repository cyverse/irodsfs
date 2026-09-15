package irodsfs

import (
	"context"
	"io"
	"os"
	"syscall"

	"github.com/cockroachdb/errors"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
)

// IRODSGetACL returns permission flag from iRODS access level type
func (fs *IRODSFS) IRODSGetPermission(level irodsclient_types.IRODSAccessLevelType) os.FileMode {
	switch level {
	case irodsclient_types.IRODSAccessLevelAdministerObject, irodsclient_types.IRODSAccessLevelOwner, irodsclient_types.IRODSAccessLevelModifyObject, irodsclient_types.IRODSAccessLevelCreateObject:
		return 0o700
	case irodsclient_types.IRODSAccessLevelReadObject, irodsclient_types.IRODSAccessLevelExecute, irodsclient_types.IRODSAccessLevelCurate:
		return 0o500
	case irodsclient_types.IRODSAccessLevelNull:
		fallthrough
	default:
		return 0o0
	}
}

// IRODSGetOpenFlags converts file open flags to iRODS file open mode
func (fs *IRODSFS) IRODSGetOpenFlags(flags uint32) irodsclient_types.FileOpenMode {
	if flags&uint32(os.O_WRONLY) == uint32(os.O_WRONLY) {
		openMode := irodsclient_types.FileOpenModeWriteOnly

		if flags&uint32(os.O_APPEND) == uint32(os.O_APPEND) {
			// append
			openMode = irodsclient_types.FileOpenModeAppend
		} else if flags&uint32(os.O_TRUNC) == uint32(os.O_TRUNC) {
			// truncate
			openMode = irodsclient_types.FileOpenModeWriteTruncate
		}

		return openMode
	} else if flags&uint32(os.O_RDWR) == uint32(os.O_RDWR) {
		return irodsclient_types.FileOpenModeReadWrite
	}

	return irodsclient_types.FileOpenModeReadOnly
}

// IRODSGetACL returns ACL flag from iRODS entry
func (fs *IRODSFS) IRODSGetACL(ctx context.Context, entry *irodsclient_fs.Entry, readonly bool) os.FileMode {
	// we don't actually check permissions for reading file when vpathEntry is read only
	// because files with no-access for the user will not be visible
	if readonly {
		return 0o500
	}

	if entry.Owner == fs.config.ClientUsername {
		// mine
		return 0o700
	}

	// we don't do full permission check here.
	// it's too slow.
	return 0o700
}

// IRODSStat returns a stat for the given irods path
func (fs *IRODSFS) IRODSStat(ctx context.Context, path string) (*irodsclient_fs.Entry, error) {
	return fs.fsClient.Stat(path)
}

// IRODSGetattr returns an attr for the given irods path
func (fs *IRODSFS) IRODSGetattr(ctx context.Context, path string, vpathReadonly bool, out *fuse.AttrOut) syscall.Errno {
	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find file or dir for path %q", path)
			return syscall.ENOENT
		}

		fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	mode := fs.IRODSGetACL(ctx, entry, vpathReadonly)
	err = fs.setAttrOutForIRODSEntry(entry, mode, &out.Attr)
	if err != nil {
		fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// IRODSLookup returns entry for the given irods path
func (fs *IRODSFS) IRODSLookup(ctx context.Context, dir *Dir, path string, vpathReadonly bool, out *fuse.EntryOut) (int64, bool, syscall.Errno) {
	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find file or dir for path %q", path)
			return 0, false, syscall.ENOENT
		}

		fs.logger.Error(err)
		return 0, false, syscall.EREMOTEIO
	}

	mode := fs.IRODSGetACL(ctx, entry, vpathReadonly)
	err = fs.setAttrOutForIRODSEntry(entry, mode, &out.Attr)
	if err != nil {
		fs.logger.Error(err)
		return 0, false, syscall.EREMOTEIO
	}

	return entry.ID, entry.IsDir(), fusefs.OK
}

// IRODSOpendir opens dir for the given irods path
func (fs *IRODSFS) IRODSOpendir(ctx context.Context, path string) syscall.Errno {
	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find file or dir for path %q", path)
			return syscall.ENOENT
		}

		fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	if !entry.IsDir() {
		fs.logger.Errorf("entry type for path %q is not a directory", path)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// IRODSReaddir reads dir entries for the given irods path
func (fs *IRODSFS) IRODSReaddir(ctx context.Context, path string) ([]fuse.DirEntry, syscall.Errno) {
	dirEntries := []fuse.DirEntry{}

	entries, err := fs.fsClient.List(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find dir for path %q", path)
			return nil, syscall.ENOENT
		}

		fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}

	resolvedEntries, shadowedNames := ResolveDirEntries(entries)
	for _, shadowedName := range shadowedNames {
		fs.logger.Warnf("hiding symbolic link %q in %q, an entry of the same name exists", shadowedName, path)
	}

	for _, resolvedEntry := range resolvedEntries {
		entryType := uint32(fuse.S_IFREG)

		switch {
		case resolvedEntry.IsSymlink:
			entryType = uint32(fuse.S_IFLNK)
		case resolvedEntry.Entry.IsDir():
			entryType = uint32(fuse.S_IFDIR)
		}

		inode, err := fs.getInodeIDForIRODSEntry(resolvedEntry.Entry)
		if err != nil {
			fs.logger.Error(err)
		} else {
			dirEntry := fuse.DirEntry{
				Ino:  inode,
				Mode: entryType,
				Name: resolvedEntry.VisibleName,
			}

			dirEntries = append(dirEntries, dirEntry)
		}
	}

	return dirEntries, fusefs.OK
}

// IRODSRmdir removes dir for the given irods path
func (fs *IRODSFS) IRODSRmdir(ctx context.Context, path string) syscall.Errno {
	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find dir for path %q", path)
			return syscall.ENOENT
		}

		fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	if !entry.IsDir() {
		fs.logger.Errorf("failed to remove a file %q using rmdir", entry.Path)
		return syscall.EREMOTEIO
	}

	// dir
	err = fs.fsClient.RemoveDir(entry.Path, false, false)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find dir for path %q", entry.Path)
			return syscall.ENOENT
		} else if irodsclient_types.IsCollectionNotEmptyError(err) {
			fs.logger.Debugf("the dir is not empty %q", entry.Path)
			return syscall.ENOTEMPTY
		}

		fs.logger.Error(err)
		return syscall.EREMOTEIO
	}
	return fusefs.OK
}

// IRODSUnlink removes file for the given irods path
func (fs *IRODSFS) IRODSUnlink(ctx context.Context, path string) syscall.Errno {
	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find file for path %q", path)
			return syscall.ENOENT
		}

		fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	if entry.IsDir() {
		fs.logger.Errorf("failed to remove a dir %q using unlink", entry.Path)
		return syscall.EREMOTEIO
	}

	// file
	err = fs.fsClient.RemoveFile(entry.Path, false)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find file for path %q", path)
			return syscall.ENOENT
		}

		fs.logger.Error(err)
		return syscall.EREMOTEIO
	}
	return fusefs.OK
}

// IRODSMkdir removes dir for the given irods path
func (fs *IRODSFS) IRODSMkdir(ctx context.Context, dir *Dir, path string, out *fuse.EntryOut) (int64, syscall.Errno) {
	err := fs.fsClient.MakeDir(path, false)
	if err != nil {
		fs.logger.Error(err)
		return 0, syscall.EREMOTEIO
	}

	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		fs.logger.Error(err)
		return 0, syscall.EREMOTEIO
	}

	if !entry.IsDir() {
		fs.logger.Errorf("failed to create a dir, but found a file")
		return 0, syscall.EREMOTEIO
	}

	mode := fs.IRODSGetACL(ctx, entry, false)
	err = fs.setAttrOutForIRODSEntry(entry, mode, &out.Attr)
	if err != nil {
		fs.logger.Error(err)
		return 0, syscall.EREMOTEIO
	}

	return entry.ID, fusefs.OK
}

// IRODSRename renames file or dir for the given irods path
func (fs *IRODSFS) IRODSRename(ctx context.Context, dir *Dir, srcPath string, destPath string) syscall.Errno {
	srcEntry, err := fs.fsClient.Stat(srcPath)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find file or dir for path %q", srcPath)
			return syscall.ENOENT
		}

		fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	if srcEntry.IsDir() {
		err = dir.fs.fsClient.RenameDirToDir(srcPath, destPath)
		if err != nil {
			fs.logger.Error(err)
			return syscall.EREMOTEIO
		}

		return fusefs.OK
	}

	destEntry, err := fs.fsClient.Stat(destPath)
	if err != nil {
		if !irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find file or dir for path %q", destPath)
			return syscall.EREMOTEIO
		}
	} else {
		// no error - file exists
		if destEntry.ID > 0 {
			// delete first
			if !destEntry.IsDir() {
				err = dir.fs.fsClient.RemoveFile(destPath, false)
				if err != nil {
					fs.logger.Error(err)
					return syscall.EREMOTEIO
				}
			}
		}
	}

	err = dir.fs.fsClient.RenameFileToFile(srcPath, destPath)
	if err != nil {
		fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// IRODSCreate creates file for the given irods path
func (fs *IRODSFS) IRODSCreate(ctx context.Context, dir *Dir, path string, flags uint32, out *fuse.EntryOut) (int64, *FileHandle, syscall.Errno) {
	openMode := fs.IRODSGetOpenFlags(flags)
	fs.logger.Infof("Create file %q with flag %d, mode %q", path, flags, openMode)

	handle, err := fs.fsClient.CreateFile(path, string(openMode))
	if err != nil {
		fs.logger.Error(err)
		return 0, nil, syscall.EREMOTEIO
	}

	entry := handle.GetEntry()

	fileHandle, err := NewFileHandle(fs, handle)
	if err != nil {
		fs.logger.Error(err)
		return 0, nil, syscall.EREMOTEIO
	}

	mode := fs.IRODSGetACL(ctx, entry, false)
	err = fs.setAttrOutForIRODSEntry(entry, mode, &out.Attr)
	if err != nil {
		fs.logger.Error(err)
		return 0, nil, syscall.EREMOTEIO
	}

	return entry.ID, fileHandle, fusefs.OK
}

// IRODSOpen opens file for the given irods path
func (fs *IRODSFS) IRODSOpen(ctx context.Context, file *File, path string, flags uint32) (*FileHandle, syscall.Errno) {
	openMode := fs.IRODSGetOpenFlags(flags)
	fs.logger.Infof("Open file %q with flag %d, mode %q", path, flags, openMode)

	handle, err := fs.fsClient.OpenFile(path, string(openMode))
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find a file %q", path)
			return nil, syscall.ENOENT
		}

		fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}

	fileHandle, err := NewFileHandle(fs, handle)
	if err != nil {
		fs.logger.Error(err)
		return nil, syscall.EREMOTEIO
	}

	return fileHandle, fusefs.OK
}

// IRODSFsync syncs filesytem
func (fs *IRODSFS) IRODSFsync(ctx context.Context) syscall.Errno {
	err := fs.fsClient.Sync()
	if err != nil {
		fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// IRODSGetattrSymlink returns an attr for the symbolic link stored at the given irods path
func (fs *IRODSFS) IRODSGetattrSymlink(ctx context.Context, path string, out *fuse.AttrOut) syscall.Errno {
	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find symbolic link for path %q", path)
			return syscall.ENOENT
		}

		fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	err = fs.setAttrOutForSymlinkEntry(entry, &out.Attr)
	if err != nil {
		fs.logger.Error(err)
		return syscall.EREMOTEIO
	}

	return fusefs.OK
}

// IRODSLookupSymlink returns entry for the symbolic link stored at the given irods path
func (fs *IRODSFS) IRODSLookupSymlink(ctx context.Context, path string, out *fuse.EntryOut) (int64, syscall.Errno) {
	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find symbolic link for path %q", path)
			return 0, syscall.ENOENT
		}

		fs.logger.Error(err)
		return 0, syscall.EREMOTEIO
	}

	if entry.IsDir() {
		// a collection is never a symbolic link, even when its name ends with the suffix
		fs.logger.Debugf("failed to find symbolic link for path %q, it is a collection", path)
		return 0, syscall.ENOENT
	}

	err = fs.setAttrOutForSymlinkEntry(entry, &out.Attr)
	if err != nil {
		fs.logger.Error(err)
		return 0, syscall.EREMOTEIO
	}

	return entry.ID, fusefs.OK
}

// IRODSReadlink returns the target of the symbolic link stored at the given irods path
func (fs *IRODSFS) IRODSReadlink(ctx context.Context, path string) (string, syscall.Errno) {
	fs.logger.Infof("Read symbolic link %q", path)

	handle, err := fs.fsClient.OpenFile(path, string(irodsclient_types.FileOpenModeReadOnly))
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			fs.logger.Debugf("failed to find symbolic link for path %q", path)
			return "", syscall.ENOENT
		}

		fs.logger.Error(err)
		return "", syscall.EREMOTEIO
	}

	entry := handle.GetEntry()
	if entry.Size <= 0 || entry.Size > SymlinkTargetMax {
		// the content is the link target, so an empty or oversized object is corrupt
		fs.logger.Errorf("failed to read symbolic link %q, it holds an invalid target of %d bytes", path, entry.Size)
		_ = handle.Close()
		return "", syscall.EIO
	}

	buffer := make([]byte, entry.Size)
	totalReadLen := 0
	for totalReadLen < len(buffer) {
		readLen, err := handle.ReadAt(buffer[totalReadLen:], int64(totalReadLen))
		totalReadLen += readLen

		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}

			fs.logger.Error(err)
			_ = handle.Close()
			return "", syscall.EREMOTEIO
		}

		if readLen == 0 {
			break
		}
	}

	err = handle.Close()
	if err != nil {
		fs.logger.Error(err)
		return "", syscall.EREMOTEIO
	}

	if totalReadLen == 0 {
		fs.logger.Errorf("failed to read symbolic link %q, it holds an empty target", path)
		return "", syscall.EIO
	}

	return string(buffer[:totalReadLen]), fusefs.OK
}

// IRODSExists returns true if an entry exists at the given irods path
func (fs *IRODSFS) IRODSExists(ctx context.Context, path string) (bool, syscall.Errno) {
	_, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			return false, fusefs.OK
		}

		fs.logger.Error(err)
		return false, syscall.EREMOTEIO
	}

	return true, fusefs.OK
}

// IRODSSymlink creates a symbolic link holding the given target at the given irods path
func (fs *IRODSFS) IRODSSymlink(ctx context.Context, path string, target string, out *fuse.EntryOut) (int64, syscall.Errno) {
	fs.logger.Infof("Create symbolic link %q -> %q", path, target)

	handle, err := fs.fsClient.CreateFile(path, string(irodsclient_types.FileOpenModeWriteOnly))
	if err != nil {
		fs.logger.Error(err)
		return 0, syscall.EREMOTEIO
	}

	entry := handle.GetEntry()

	writeErr := func() error {
		if _, err := handle.WriteAt([]byte(target), 0); err != nil {
			return err
		}
		return handle.Close()
	}()

	if writeErr != nil {
		fs.logger.Error(writeErr)

		// the object exists but does not hold the target, so remove it rather than
		// leave something that reads back as a link to nowhere
		if removeErr := fs.fsClient.RemoveFile(path, true); removeErr != nil {
			fs.logger.Error(removeErr)
		}

		return 0, syscall.EREMOTEIO
	}

	// the handle entry was taken before the target was written, so report the size
	// the target gives it. A copy keeps the correction out of any cached entry.
	symlinkEntry := *entry
	symlinkEntry.Size = int64(len(target))

	err = fs.setAttrOutForSymlinkEntry(&symlinkEntry, &out.Attr)
	if err != nil {
		fs.logger.Error(err)
		return 0, syscall.EREMOTEIO
	}

	return symlinkEntry.ID, fusefs.OK
}
