package vfs

import (
	"fmt"
	"time"

	irodsfscommon_irods "github.com/cyverse/irodsfs-common/irods"
	irodsfscommon_utils "github.com/cyverse/irodsfs-common/utils"
	log "github.com/sirupsen/logrus"
)

// VFS is a virtual file system.
// iRODS FUSE Lite uses VFS to map iRODS data objects and collections to VFS entries.
// Custom path mapping can change the mapping.
type VFS struct {
	pathMappings []PathMapping
	// entries is a map holding VFS entries.
	// Key is absolute path in VFS, value is entry object
	entries  map[string]*VFSEntry
	fsClient irodsfscommon_irods.IRODSFSClient
}

// NewVFS creates a new VFS
func NewVFS(fsclient irodsfscommon_irods.IRODSFSClient, mappings []PathMapping) (*VFS, error) {
	logger := log.WithFields(log.Fields{
		"package":  "vfs",
		"function": "NewVFS",
	})

	vfs := &VFS{
		pathMappings: mappings,
		entries:      map[string]*VFSEntry{},
		fsClient:     fsclient,
	}

	logger.Info("Building VFS")
	err := vfs.Build()
	if err != nil {
		logger.WithError(err).Error("failed to build VFS")
		return nil, err
	}

	return vfs, nil
}

// Build builds VFS from mappings
func (vfs *VFS) Build() error {
	logger := log.WithFields(log.Fields{
		"package":  "vfs",
		"struct":   "VFS",
		"function": "Build",
	})

	vfs.entries = map[string]*VFSEntry{}

	// build
	for _, mapping := range vfs.pathMappings {
		err := vfs.buildOne(&mapping)
		if err != nil {
			logger.Error(err)
			return err
		}
	}
	return nil
}

// HasEntry returns true if it has VFS Entry for the path
func (vfs *VFS) HasEntry(vpath string) bool {
	_, ok := vfs.entries[vpath]
	return ok
}

// GetEntry returns VFS Entry for the Path
func (vfs *VFS) GetEntry(vpath string) *VFSEntry {
	if entry, ok := vfs.entries[vpath]; ok {
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

	parentDirs := irodsfscommon_utils.GetParentDirs(vpath)
	var closestEntry *VFSEntry
	for _, parentDir := range parentDirs {
		if entry, ok := vfs.entries[parentDir]; ok {
			closestEntry = entry
		}
	}

	return closestEntry
}

// buildOne builds one VFS mapping
func (vfs *VFS) buildOne(mapping *PathMapping) error {
	logger := log.WithFields(log.Fields{
		"package":  "vfs",
		"struct":   "VFS",
		"function": "buildOne",
	})

	logger.Infof("Building VFS Entry - %s", mapping.IRODSPath)

	now := time.Now()

	parentDirs := irodsfscommon_utils.GetParentDirs(mapping.MappingPath)
	for idx, parentDir := range parentDirs {
		// add parentDir if not exists
		if parentDirEntry, ok := vfs.entries[parentDir]; ok {
			// exists, check if it is VFSVirtualDirEntryType
			if parentDirEntry.Type != VFSVirtualDirEntryType {
				err := fmt.Errorf("failed to create a virtual dir entry %s, iRODS dir entry already exists", parentDir)
				logger.Error(err)
				return err
			}
		} else {
			dirEntry := &VFSEntry{
				Type:     VFSVirtualDirEntryType,
				Path:     parentDir,
				ReadOnly: true,
				VirtualDirEntry: &VFSVirtualDirEntry{
					ID:         0,
					Name:       irodsfscommon_utils.GetFileName(parentDir),
					Path:       parentDir,
					Owner:      vfs.fsClient.GetAccount().ClientUser,
					Size:       0,
					CreateTime: now,
					ModifyTime: now,
					DirEntries: []*VFSEntry{},
				},
				IRODSEntry: nil,
			}
			vfs.entries[parentDir] = dirEntry

			// add entry to its parent
			if idx != 0 {
				parentPath := parentDirs[idx-1]
				if parentEntry, ok := vfs.entries[parentPath]; ok {
					parentEntry.VirtualDirEntry.DirEntries = append(parentEntry.VirtualDirEntry.DirEntries, dirEntry)
				}
			}
		}
	}

	if mapping.ResourceType == PathMappingDirectory && mapping.CreateDir {
		logger.Infof("Checking if path exists - %s", mapping.IRODSPath)
		if !vfs.fsClient.ExistsDir(mapping.IRODSPath) {
			logger.Infof("Creating path - %s", mapping.IRODSPath)
			err := vfs.fsClient.MakeDir(mapping.IRODSPath, true)
			if err != nil {
				logger.WithError(err).Errorf("failed to make a dir - %s", mapping.IRODSPath)
				// fall below
			}
		}
	}

	// add leaf
	logger.Infof("Checking path - %s", mapping.IRODSPath)
	irodsEntry, err := vfs.fsClient.Stat(mapping.IRODSPath)
	if err != nil {
		if mapping.IgnoreNotExist {
			// ignore
			return nil
		}

		logger.WithError(err).Errorf("failed to stat - %s", mapping.IRODSPath)
		return err
	}

	logger.Infof("Creating VFS entry mapping - irods path %s => vfs path %s (%t)", irodsEntry.Path, mapping.MappingPath, mapping.ReadOnly)
	entry := NewVFSEntryFromIRODSFSEntry(mapping.MappingPath, irodsEntry, mapping.ReadOnly)
	vfs.entries[mapping.MappingPath] = entry

	// add to parent
	if len(parentDirs) > 0 {
		parentPath := parentDirs[len(parentDirs)-1]
		if parentEntry, ok := vfs.entries[parentPath]; ok {
			parentEntry.VirtualDirEntry.DirEntries = append(parentEntry.VirtualDirEntry.DirEntries, entry)
		}
	}

	return nil
}
