package irodsfs

import (
	"context"
	"os"
	"path"
	"syscall"

	"bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	irodsfs_clienttype "github.com/cyverse/go-irodsclient/irods/types"
	log "github.com/sirupsen/logrus"
)

// Dir is a directory node
type Dir struct {
	FS           *IRODSFS
	Path         string
	IRODSFSEntry *irodsfs_client.FSEntry
}

// Attr returns stat of file entry
func (dir *Dir) Attr(ctx context.Context, attr *fuse.Attr) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Dir.Attr",
	})

	irodsPath := path.Join(dir.FS.Config.IRODSPath, dir.Path)

	logger.Infof("Calling Attr - %s", irodsPath)

	attr.Inode = uint64(dir.IRODSFSEntry.ID)
	attr.Ctime = dir.IRODSFSEntry.CreateTime
	attr.Mtime = dir.IRODSFSEntry.ModifyTime
	attr.Atime = dir.IRODSFSEntry.ModifyTime
	attr.Size = 0
	if dir.IRODSFSEntry.Owner == dir.FS.Config.ClientUser {
		// mine
		attr.Mode = os.ModeDir | 0o600
	} else {
		// others - readonly
		attr.Mode = os.ModeDir | 0o400
	}
	return nil
}

// ReadDirAll returns directory entries
func (dir *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Dir.ReadDirAll",
	})

	irodsPath := path.Join(dir.FS.Config.IRODSPath, dir.Path)
	logger.Infof("Calling ReadDirAll - %s", irodsPath)

	entries, err := dir.FS.IRODSClient.List(irodsPath)
	if err != nil {
		logger.WithError(err).Errorf("List error - %s", irodsPath)
		return nil, syscall.EREMOTEIO
	}

	dirEntries := []fuse.Dirent{}

	for _, entry := range entries {
		entryType := fuse.DT_File

		switch entry.Type {
		case irodsfs_client.FSFileEntry:
			entryType = fuse.DT_File
		case irodsfs_client.FSDirectoryEntry:
			entryType = fuse.DT_Dir
		default:
			logger.Errorf("Unknown entry type - %s", entry.Type)
			return nil, syscall.EREMOTEIO
		}

		dirEntry := fuse.Dirent{
			Inode: uint64(entry.ID),
			Type:  entryType,
			Name:  entry.Name,
		}

		dirEntries = append(dirEntries, dirEntry)
	}

	return dirEntries, nil
}

// Lookup returns a node for the path
func (dir *Dir) Lookup(ctx context.Context, name string) (fusefs.Node, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Dir.Lookup",
	})

	irodsPath := path.Join(dir.FS.Config.IRODSPath, dir.Path, name)
	logger.Infof("Calling Lookup - %s", irodsPath)

	entry, err := dir.FS.IRODSClient.Stat(irodsPath)
	if err != nil {
		if irodsfs_clienttype.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("File not found - %s", irodsPath)
			return nil, syscall.ENOENT
		}

		logger.WithError(err).Errorf("Stat error - %s", irodsPath)
		return nil, syscall.EREMOTEIO
	}

	switch entry.Type {
	case irodsfs_client.FSFileEntry:
		return &File{
			FS:           dir.FS,
			Path:         path.Join(dir.Path, name),
			IRODSFSEntry: entry,
			FileHandle:   nil,
		}, nil
	case irodsfs_client.FSDirectoryEntry:
		return &Dir{
			FS:           dir.FS,
			Path:         path.Join(dir.Path, name),
			IRODSFSEntry: entry,
		}, nil
	default:
		logger.Errorf("Unknown entry type - %s", entry.Type)
		return nil, syscall.EREMOTEIO
	}
}

// Remove removes a node for the path
func (dir *Dir) Remove(ctx context.Context, req *fuse.RemoveRequest) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Dir.Remove",
	})

	irodsPath := path.Join(dir.FS.Config.IRODSPath, dir.Path, req.Name)
	logger.Infof("Calling Remove - %s", irodsPath)

	entry, err := dir.FS.IRODSClient.Stat(irodsPath)
	if err != nil {
		if irodsfs_clienttype.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("File not found - %s", irodsPath)
			return syscall.ENOENT
		}

		logger.WithError(err).Errorf("Stat error - %s", irodsPath)
		return syscall.EREMOTEIO
	}

	switch entry.Type {
	case irodsfs_client.FSFileEntry:
		err = dir.FS.IRODSClient.RemoveFile(irodsPath, true)
		if err != nil {
			logger.WithError(err).Errorf("Could not remove file - %s", irodsPath)
			return syscall.EREMOTEIO
		}
		return nil
	case irodsfs_client.FSDirectoryEntry:
		err = dir.FS.IRODSClient.RemoveDir(irodsPath, false, true)
		if err != nil {
			logger.WithError(err).Errorf("Could not remove dir - %s", irodsPath)
			return syscall.EREMOTEIO
		}
		return nil
	default:
		logger.Errorf("Unknown entry type - %s", entry.Type)
		return syscall.EREMOTEIO
	}
}

// Mkdir makes a directory node for the path
func (dir *Dir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fusefs.Node, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Dir.Mkdir",
	})

	irodsPath := path.Join(dir.FS.Config.IRODSPath, dir.Path, req.Name)
	logger.Infof("Calling Mkdir - %s", irodsPath)

	err := dir.FS.IRODSClient.MakeDir(irodsPath, false)
	if err != nil {
		logger.WithError(err).Errorf("Could not make a dir - %s", irodsPath)
		return nil, syscall.EREMOTEIO
	}

	entry, err := dir.FS.IRODSClient.Stat(irodsPath)
	if err != nil {
		logger.WithError(err).Errorf("Stat error - %s", irodsPath)
		return nil, syscall.EREMOTEIO
	}

	return &Dir{
		FS:           dir.FS,
		Path:         path.Join(dir.Path, req.Name),
		IRODSFSEntry: entry,
	}, nil
}

// Rename renames a node for the path
func (dir *Dir) Rename(ctx context.Context, req *fuse.RenameRequest, newDir fusefs.Node) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Dir.Rename",
	})

	irodsSrcPath := path.Join(dir.FS.Config.IRODSPath, dir.Path, req.OldName)
	logger.Infof("Calling Rename - %s", irodsSrcPath)

	newdir := newDir.(*Dir)
	irodsDestPath := path.Join(dir.FS.Config.IRODSPath, newdir.Path, req.NewName)

	entry, err := dir.FS.IRODSClient.Stat(irodsSrcPath)
	if err != nil {
		if irodsfs_clienttype.IsFileNotFoundError(err) {
			logger.WithError(err).Errorf("File not found - %s", irodsSrcPath)
			return syscall.ENOENT
		}

		logger.WithError(err).Errorf("Stat error - %s", irodsSrcPath)
		return syscall.EREMOTEIO
	}

	switch entry.Type {
	case irodsfs_client.FSFileEntry:
		err = dir.FS.IRODSClient.RenameDirToDir(irodsSrcPath, irodsDestPath)
		if err != nil {
			logger.WithError(err).Errorf("Could not rename dir - %s to %s", irodsSrcPath, irodsDestPath)
			return syscall.EREMOTEIO
		}
		return nil
	case irodsfs_client.FSDirectoryEntry:
		err = dir.FS.IRODSClient.RenameFileToFile(irodsSrcPath, irodsDestPath)
		if err != nil {
			logger.WithError(err).Errorf("Could not rename file - %s to %s", irodsSrcPath, irodsDestPath)
			return syscall.EREMOTEIO
		}
		return nil
	default:
		logger.Errorf("Unknown entry type - %s", entry.Type)
		return syscall.EREMOTEIO
	}
}
