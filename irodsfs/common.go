package irodsfs

import (
	"context"
	"io/fs"
	"time"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	irodsfs_common_inode "github.com/cyverse/irodsfs-common/inode"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
)

func setAttrOutForVirtualDirEntry(inodeManager *irodsfs_common_inode.InodeManager, entry *irodsfs_common_vpath.VPathVirtualDirEntry, uid uint32, gid uint32, out *fuse.Attr) {
	out.Ino = entry.ID
	out.Uid = uid
	out.Gid = gid
	out.SetTimes(&entry.ModifyTime, &entry.ModifyTime, &entry.ModifyTime)
	out.Size = uint64(entry.Size)

	out.Mode = uint32(fuse.S_IFDIR | 0o500)
}

func setAttrOutForIRODSEntry(inodeManager *irodsfs_common_inode.InodeManager, entry *irodsclient_fs.Entry, uid uint32, gid uint32, mode fs.FileMode, out *fuse.Attr) {
	out.Ino = inodeManager.GetInodeIDForIRODSEntryID(entry.ID)
	out.Uid = uid
	out.Gid = gid
	out.SetTimes(&entry.ModifyTime, &entry.ModifyTime, &entry.ModifyTime)
	out.Size = uint64(entry.Size)

	if entry.IsDir() {
		out.Mode = uint32(fuse.S_IFDIR | mode)
	} else {
		out.Mode = uint32(fuse.S_IFREG | mode)
	}
}

func setAttrOutForDummy(inodeManager *irodsfs_common_inode.InodeManager, vpath string, uid uint32, gid uint32, dir bool, out *fuse.Attr) {
	out.Ino = inodeManager.GetInodeIDForVPathEntry(vpath)
	out.Uid = uid
	out.Gid = gid

	now := time.Now()

	out.SetTimes(&now, &now, &now)
	out.Size = uint64(0)

	if dir {
		out.Mode = uint32(fuse.S_IFDIR | 0o500)
	} else {
		out.Mode = uint32(fuse.S_IFREG | 0o500)
	}
}

func getDefaultDirEntries() []fuse.DirEntry {
	dirEntries := make([]fuse.DirEntry, 2)

	dirEntries[0] = fuse.DirEntry{
		Ino:  0,
		Mode: uint32(fuse.S_IFDIR),
		Name: ".",
	}

	dirEntries[1] = fuse.DirEntry{
		Ino:  0,
		Mode: uint32(fuse.S_IFDIR),
		Name: "..",
	}

	return dirEntries
}

func NewSubDirInode(ctx context.Context, dir *Dir, inodeID uint64, path string) (*Dir, *fusefs.Inode) {
	subDir := NewDir(dir.fs, inodeID, path)
	subDirInode := dir.NewInode(ctx, subDir, subDir.getStableAttr())

	return subDir, subDirInode
}

func NewSubFileInode(ctx context.Context, dir *Dir, inodeID uint64, path string) (*File, *fusefs.Inode) {
	subFile := NewFile(dir.fs, inodeID, path)
	subFileInode := dir.NewInode(ctx, subFile, subFile.getStableAttr())

	return subFile, subFileInode
}

func isTransitiveConnectionError(err error) bool {
	return irodsclient_types.IsConnectionError(err) || irodsclient_types.IsConnectionPoolFullError(err)
}
