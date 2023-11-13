package irodsfs

import (
	"io/fs"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
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

	if entry.Type == irodsclient_fs.DirectoryEntry {
		out.Mode = uint32(fuse.S_IFDIR | mode)
	} else {
		out.Mode = uint32(fuse.S_IFREG | mode)
	}
}
