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
