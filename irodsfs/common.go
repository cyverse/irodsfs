package irodsfs

import (
	"context"
	"io/fs"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
)

func setAttrOutForVirtualDirEntry(entry *irodsfs_common_vpath.VPathVirtualDirEntry, uid uint32, gid uint32, out *fuse.Attr) {
	out.Ino = getInodeIDFromEntryID(entry.ID)
	out.Uid = uid
	out.Gid = gid
	out.SetTimes(&entry.ModifyTime, &entry.ModifyTime, &entry.ModifyTime)
	out.Size = uint64(entry.Size)

	out.Mode = uint32(fuse.S_IFDIR | 0o500)
}

func setAttrOutForIRODSEntry(entry *irodsclient_fs.Entry, uid uint32, gid uint32, mode fs.FileMode, out *fuse.Attr) {
	out.Ino = getInodeIDFromEntryID(entry.ID)
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

func NewSubDirInode(ctx context.Context, dir *Dir, entryID int64, path string) (*Dir, *fusefs.Inode) {
	subDir := NewDir(dir.fs, entryID, path)
	subDirInode := dir.NewInode(ctx, subDir, subDir.getStableAttr())

	return subDir, subDirInode
}

func NewSubFileInode(ctx context.Context, dir *Dir, entryID int64, path string) (*File, *fusefs.Inode) {
	subFile := NewFile(dir.fs, entryID, path)
	subFileInode := dir.NewInode(ctx, subFile, subFile.getStableAttr())

	return subFile, subFileInode
}
