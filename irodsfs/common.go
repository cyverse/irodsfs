package irodsfs

import (
	fuse "github.com/hanwen/go-fuse/v2/fuse"
)

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
