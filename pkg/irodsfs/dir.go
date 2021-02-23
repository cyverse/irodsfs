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
)

type Dir struct {
	FS           *IRODSFS
	Path         string
	IRODSFSEntry *irodsfs_client.FSEntry
}

func (dir *Dir) Attr(ctx context.Context, attr *fuse.Attr) error {
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

func (dir *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	irodsPath := path.Join(dir.FS.Config.IRODSPath, dir.Path)
	entries, err := dir.FS.IRODSClient.List(irodsPath)
	if err != nil {
		//return nil, err
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
			//return nil, fmt.Errorf("Unknown entry type %s", entry.Type)
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

func (dir *Dir) Lookup(ctx context.Context, name string) (fusefs.Node, error) {
	irodsPath := path.Join(dir.FS.Config.IRODSPath, dir.Path, name)

	entry, err := dir.FS.IRODSClient.Stat(irodsPath)
	if err != nil {
		if irodsfs_clienttype.IsFileNotFoundError(err) {
			return nil, syscall.ENOENT
		} else {
			//return nil, err
			return nil, syscall.EREMOTEIO
		}
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
		//return nil, fmt.Errorf("Unknown entry type %s", entry.Type)
		return nil, syscall.EREMOTEIO
	}
}

func (dir *Dir) Remove(ctx context.Context, req *fuse.RemoveRequest) error {
	irodsPath := path.Join(dir.FS.Config.IRODSPath, dir.Path, req.Name)

	entry, err := dir.FS.IRODSClient.Stat(irodsPath)
	if err != nil {
		if irodsfs_clienttype.IsFileNotFoundError(err) {
			return syscall.ENOENT
		} else {
			//return nil, err
			return syscall.EREMOTEIO
		}
	}

	switch entry.Type {
	case irodsfs_client.FSFileEntry:
		err = dir.FS.IRODSClient.RemoveFile(irodsPath, true)
		if err != nil {
			//return nil, err
			return syscall.EREMOTEIO
		}
		return nil
	case irodsfs_client.FSDirectoryEntry:
		err = dir.FS.IRODSClient.RemoveDir(irodsPath, false, true)
		if err != nil {
			//return nil, err
			return syscall.EREMOTEIO
		}
		return nil
	default:
		//return nil, fmt.Errorf("Unknown entry type %s", entry.Type)
		return syscall.EREMOTEIO
	}
}

func (dir *Dir) Mkdir(ctx context.Context, req *fuse.MkdirRequest) (fusefs.Node, error) {
	irodsPath := path.Join(dir.FS.Config.IRODSPath, dir.Path, req.Name)
	err := dir.FS.IRODSClient.MakeDir(irodsPath, false)
	if err != nil {
		//return nil, err
		return nil, syscall.EREMOTEIO
	}

	entry, err := dir.FS.IRODSClient.Stat(irodsPath)
	if err != nil {
		//return nil, err
		return nil, syscall.EREMOTEIO
	}

	return &Dir{
		FS:           dir.FS,
		Path:         path.Join(dir.Path, req.Name),
		IRODSFSEntry: entry,
	}, nil
}

func (dir *Dir) Rename(ctx context.Context, req *fuse.RenameRequest, newDir fusefs.Node) error {
	irodsSrcPath := path.Join(dir.FS.Config.IRODSPath, dir.Path, req.OldName)

	newdir := newDir.(*Dir)
	irodsDestPath := path.Join(dir.FS.Config.IRODSPath, newdir.Path, req.NewName)

	err := dir.FS.IRODSClient.RenameDirToDir(irodsSrcPath, irodsDestPath)
	if err != nil {
		//return err
		return syscall.EREMOTEIO
	}
	return nil
}
