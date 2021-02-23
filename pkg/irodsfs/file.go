package irodsfs

import (
	"context"
	"path"
	"syscall"

	"bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	irodsfs_clienttype "github.com/cyverse/go-irodsclient/irods/types"
)

type File struct {
	FS           *IRODSFS
	Path         string
	IRODSFSEntry *irodsfs_client.FSEntry
	FileHandle   *irodsfs_client.FileHandle
}

func (file *File) Attr(ctx context.Context, attr *fuse.Attr) error {
	attr.Inode = uint64(file.IRODSFSEntry.ID)
	attr.Ctime = file.IRODSFSEntry.CreateTime
	attr.Mtime = file.IRODSFSEntry.ModifyTime
	attr.Atime = file.IRODSFSEntry.ModifyTime
	attr.Size = uint64(file.IRODSFSEntry.Size)

	if file.IRODSFSEntry.Owner == file.FS.Config.ClientUser {
		// mine
		attr.Mode = 0o600
	} else {
		// others - readonly
		attr.Mode = 0o400
	}
	return nil
}

func (file *File) Open(ctx context.Context, req *fuse.OpenRequest, resp *fuse.OpenResponse) (fusefs.Handle, error) {
	irodsPath := path.Join(file.FS.Config.IRODSPath, file.Path)
	openMode := string(irodsfs_clienttype.FileOpenModeReadOnly)

	if req.Flags.IsReadOnly() {
		openMode = string(irodsfs_clienttype.FileOpenModeReadOnly)
		resp.Flags |= fuse.OpenKeepCache
	} else if req.Flags.IsWriteOnly() {
		openMode = string(irodsfs_clienttype.FileOpenModeWriteOnly)
	} else if req.Flags.IsReadWrite() {
		openMode = string(irodsfs_clienttype.FileOpenModeReadWrite)
	} else {
		return nil, syscall.EACCES
	}

	handle, err := file.FS.IRODSClient.OpenFile(irodsPath, "", openMode)
	if err != nil {
		if irodsfs_clienttype.IsFileNotFoundError(err) {
			return nil, syscall.ENOENT
		}
		//return err
		return nil, syscall.EREMOTEIO
	}

	file.FileHandle = handle

	return file, nil
}

func (file *File) Read(ctx context.Context, req *fuse.ReadRequest, resp *fuse.ReadResponse) error {
	if file.FileHandle == nil {
		return syscall.EREMOTEIO
	}

	if req.Offset > file.FileHandle.Entry.Size {
		resp.Data = resp.Data[:0]
		return nil
	}

	if file.FileHandle.GetOffset() != req.Offset {
		_, err := file.FileHandle.Seek(req.Offset, irodsfs_clienttype.SeekSet)
		if err != nil {
			return syscall.EREMOTEIO
		}
	}

	data, err := file.FileHandle.Read(req.Size)
	if err != nil {
		return syscall.EREMOTEIO
	}

	copiedLen := copy(resp.Data[:req.Size], data)
	resp.Data = resp.Data[:copiedLen]
	return nil
}

func (file *File) Flush(ctx context.Context, req *fuse.FlushRequest) error {
	if file.FileHandle == nil {
		return syscall.EREMOTEIO
	}
	return nil
}

func (file *File) Release(ctx context.Context, req *fuse.ReleaseRequest) error {
	if file.FileHandle == nil {
		return syscall.EREMOTEIO
	}

	err := file.FileHandle.Close()
	if err != nil {
		return syscall.EREMOTEIO
	}
	return nil
}
