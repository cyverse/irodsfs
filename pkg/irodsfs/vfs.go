package irodsfs

import (
	"time"

	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	log "github.com/sirupsen/logrus"
)

// VFS is used to provide custom path mapping.
// physical resources in iRODS are mapped to VFS entries.
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
	entry := vfs.GetEntry(vpath)
	if entry != nil {
		return entry
	}

	parentDirs := GetParentDirs(vpath)
	var closestEntry *VFSEntry
	for _, parentDir := range parentDirs {
		if entry, ok := vfs.Entries[parentDir]; ok {
			closestEntry = entry
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
		_, ok := entries[parentDir]
		if !ok {
			// add parentDir if not exists
			dirEntry := &VFSEntry{
				Type: VFSVirtualDirEntryType,
				Path: parentDir,
				VirtualDirEntry: &VFSVirtualDirEntry{
					ID:         0,
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

	if mapping.ResourceType == PathMappingDirectory && mapping.CreateDir {
		if !fsclient.ExistsDir(mapping.IRODSPath) {
			err := fsclient.MakeDir(mapping.IRODSPath, true)
			if err != nil {
				logger.WithError(err).Errorf("MakeDir error - %s", mapping.IRODSPath)
				// fall
			}
		}
	}

	// add leaf
	fsEntry, err := fsclient.Stat(mapping.IRODSPath)
	if err != nil {
		if mapping.IgnoreNotExist {
			// ignore
			return nil
		}

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
