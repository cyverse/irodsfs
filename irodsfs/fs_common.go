package irodsfs

import (
	"io/fs"

	"github.com/cockroachdb/errors"
	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/irodsfs-common/inode"
	"github.com/cyverse/irodsfs-common/irods/vpath"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
)

func (fs *IRODSFS) getInodeIDForIRODSEntryID(entryID uint64) (uint64, error) {
	// entry can be either a real irods entry or a staging entry
	if inode.IsStagingEntryID(entryID) {
		// staging
		return entryID, nil
	}

	// irods
	inode, err := inode.GetInodeIDForIRODSEntryID(entryID)
	if err != nil {
		return 0, errors.Wrapf(err, "failed to get inode ID for irods entry (id %q)", entryID)
	}
	return inode, nil
}

func (fs *IRODSFS) getInodeIDForIRODSEntry(entry *irodsclient_fs.Entry) (uint64, error) {
	// entry can be either a real irods entry or a staging entry
	if inode.IsStagingEntryID(uint64(entry.ID)) {
		// staging
		return uint64(entry.ID), nil
	}

	// irods
	inode, err := inode.GetInodeIDForIRODSEntryID(uint64(entry.ID))
	if err != nil {
		return 0, errors.Wrapf(err, "failed to get inode ID for irods entry %q (id %q)", entry.Path, entry.ID)
	}
	return inode, nil
}

func (fs *IRODSFS) setAttrOutForVirtualDirEntry(entry *vpath.VPathVirtualDirEntry, out *fuse.Attr) error {
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
	inodeID, err := fs.getInodeIDForIRODSEntry(entry)
	if err != nil {
		return err
	}
	out.Ino = inodeID

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
