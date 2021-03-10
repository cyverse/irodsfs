package irodsfs

import (
	"time"

	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	log "github.com/sirupsen/logrus"
)

// VFS ...
type VFS struct {
	Entries map[string]*VFSEntry
}

// NewVFS creates a new VFS
func NewVFS(fsclient *irodsfs_client.FileSystem, mappings []PathMapping) (*VFS, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "NewVFS",
	})

	entries := map[string]*VFSEntry{}

	// build
	for _, mapping := range mappings {
		err := buildVFS(fsclient, entries, &mapping)
		if err != nil {
			logger.Error(err)
			return nil, err
		}
	}

	return &VFS{
		Entries: entries,
	}, nil
}

// HasEntry returns true if it has VFS Entry for the path
func (vfs *VFS) HasEntry(vpath string) bool {
	_, ok := vfs.Entries[vpath]
	return ok
}

// GetEntry returns VFS Entry for the Path
func (vfs *VFS) GetEntry(vpath string) *VFSEntry {
	if entry, ok := vfs.Entries[vpath]; ok {
		return entry
	}

	return nil
}

// GetClosestEntry returns the closest VFS Entry for the path
func (vfs *VFS) GetClosestEntry(vpath string) *VFSEntry {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "GetClosestEntry",
	})

	entry := vfs.GetEntry(vpath)
	if entry != nil {
		return entry
	}

	parentDirs := GetParentDirs(vpath)
	logger.Infof("Searching pdirs %v", parentDirs)
	var closestEntry *VFSEntry
	for _, parentDir := range parentDirs {
		logger.Infof("Searching pdir %s", parentDir)
		if entry, ok := vfs.Entries[parentDir]; ok {
			closestEntry = entry
			logger.Infof("Searching pdir %s - found", parentDir)
		}
	}

	return closestEntry
}

func buildVFS(fsclient *irodsfs_client.FileSystem, entries map[string]*VFSEntry, mapping *PathMapping) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "buildVFS",
	})

	now := time.Now()

	parentDirs := GetParentDirs(mapping.MappingPath)
	for idx, parentDir := range parentDirs {
		dirEntry, ok := entries[parentDir]
		if !ok {
			// add parentDir if not exists
			dirEntry = &VFSEntry{
				Type: VFSVirtualDirEntryType,
				Path: parentDir,
				VirtualDirEntry: &VFSVirtualDirEntry{
					ID:         now.UnixNano(),
					Name:       GetFileName(parentDir),
					Path:       parentDir,
					Owner:      fsclient.Account.ClientUser,
					Size:       0,
					CreateTime: now,
					ModifyTime: now,
					DirEntries: []*VFSEntry{},
				},
				IRODSEntry: nil,
			}
			entries[parentDir] = dirEntry

			// add entry to its parent
			if idx != 0 {
				parentPath := parentDirs[idx-1]
				parentEntry := entries[parentPath]
				parentEntry.VirtualDirEntry.DirEntries = append(parentEntry.VirtualDirEntry.DirEntries, dirEntry)
			}
		}
	}

	// add leaf
	fsEntry, err := fsclient.Stat(mapping.IRODSPath)
	if err != nil {
		logger.WithError(err).Errorf("Stat error - %s", mapping.IRODSPath)
		return err
	}

	entry := NewVFSEntryFromIRODSFSEntry(mapping.MappingPath, fsEntry)
	entries[mapping.MappingPath] = entry

	// add to parent
	if len(parentDirs) > 0 {
		parentPath := parentDirs[len(parentDirs)-1]
		parentEntry := entries[parentPath]
		parentEntry.VirtualDirEntry.DirEntries = append(parentEntry.VirtualDirEntry.DirEntries, entry)
	}

	return nil
}
