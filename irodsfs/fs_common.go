package irodsfs

import (
	"io/fs"

	"github.com/cockroachdb/errors"
	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
)

func (fs *IRODSFS) setAttrOutForDummy(vpath string, dir bool, out *fuse.Attr) error {
	inode, err := fs.inodeManager.GetInodeIDForVirtualEntry(vpath)
	if err != nil {
		return errors.Wrapf(err, "failed to get inode ID for virtual entry %q", vpath)
	}

	out.Ino = inode
	out.Uid = fs.uid
	out.Gid = fs.gid

	out.SetTimes(&fs.startTime, &fs.startTime, &fs.startTime)
	out.Size = uint64(0)

	if dir {
		out.Mode = uint32(fuse.S_IFDIR | 0o500)
		out.Nlink = 2
	} else {
		out.Mode = uint32(fuse.S_IFREG | 0o500)
		out.Nlink = 1
	}

	return nil
}

func (fs *IRODSFS) setAttrOutForVirtualDirEntry(entry *irodsfs_common_vpath.VPathVirtualDirEntry, out *fuse.Attr) error {
	out.Ino = entry.ID
	out.Ino = entry.ID
	out.Uid = fs.uid
	out.Gid = fs.gid

	out.SetTimes(&entry.ModifyTime, &entry.ModifyTime, &entry.ModifyTime)
	out.Size = uint64(entry.Size)
	out.Mode = uint32(fuse.S_IFDIR | 0o500)
	out.Nlink = 2

	return nil
}

func (fs *IRODSFS) setAttrOutForIRODSEntry(entry *irodsclient_fs.Entry, mode fs.FileMode, out *fuse.Attr) error {
	inode, err := fs.inodeManager.GetInodeIDForIRODSEntryID(uint64(entry.ID))
	if err != nil {
		return errors.Wrapf(err, "failed to get inode ID for irods entry %q (id %q)", entry.Path, entry.ID)
	}
	out.Ino = inode

	out.Uid = fs.uid
	out.Gid = fs.gid

	out.SetTimes(&entry.ModifyTime, &entry.ModifyTime, &entry.ModifyTime)
	out.Size = uint64(entry.Size)

	if entry.IsDir() {
		out.Mode = uint32(fuse.S_IFDIR | mode)
		out.Nlink = 2
	} else {
		out.Mode = uint32(fuse.S_IFREG | mode)
		out.Nlink = 1
	}

	return nil
}
