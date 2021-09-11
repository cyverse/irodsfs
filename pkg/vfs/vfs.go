package vfs

import (
	"fmt"
	"time"

	"github.com/cyverse/irodsfs/pkg/irodsapi"
	"github.com/cyverse/irodsfs/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// VFS is a virtual file system.
// iRODS FUSE Lite uses VFS to map iRODS data objects and collections to VFS entries.
// Custom path mapping can change the mapping.
type VFS struct {
	PathMappings []PathMapping
	// Entries is a map holding VFS Entries.
	// Key is absolute path in VFS, value is entry object
	Entries     map[string]*VFSEntry
	IRODSClient irodsapi.IRODSClient
}

// NewVFS creates a new VFS
func NewVFS(client irodsapi.IRODSClient, mappings []PathMapping) (*VFS, error) {
	logger := log.WithFields(log.Fields{
		"package":  "vfs",
		"function": "NewVFS",
	})

	vfs := &VFS{
		PathMappings: mappings,
		Entries:      map[string]*VFSEntry{},
		IRODSClient:  client,
	}

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

	vfs.Entries = map[string]*VFSEntry{}

	// build
	for _, mapping := range vfs.PathMappings {
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

	parentDirs := utils.GetParentDirs(vpath)
	var closestEntry *VFSEntry
	for _, parentDir := range parentDirs {
		if entry, ok := vfs.Entries[parentDir]; ok {
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

	now := time.Now()

	parentDirs := utils.GetParentDirs(mapping.MappingPath)
	for idx, parentDir := range parentDirs {
		// add parentDir if not exists
		if parentDirEntry, ok := vfs.Entries[parentDir]; ok {
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
					Name:       utils.GetFileName(parentDir),
					Path:       parentDir,
					Owner:      vfs.IRODSClient.GetAccount().ClientUser,
					Size:       0,
					CreateTime: now,
					ModifyTime: now,
					DirEntries: []*VFSEntry{},
				},
				IRODSEntry: nil,
			}
			vfs.Entries[parentDir] = dirEntry

			// add entry to its parent
			if idx != 0 {
				parentPath := parentDirs[idx-1]
				if parentEntry, ok := vfs.Entries[parentPath]; ok {
					parentEntry.VirtualDirEntry.DirEntries = append(parentEntry.VirtualDirEntry.DirEntries, dirEntry)
				}
			}
		}
	}

	if mapping.ResourceType == PathMappingDirectory && mapping.CreateDir {
		if !vfs.IRODSClient.ExistsDir(mapping.IRODSPath) {
			err := vfs.IRODSClient.MakeDir(mapping.IRODSPath, true)
			if err != nil {
				logger.WithError(err).Errorf("failed to make a dir - %s", mapping.IRODSPath)
				// fall below
			}
		}
	}

	// add leaf
	irodsEntry, err := vfs.IRODSClient.Stat(mapping.IRODSPath)
	if err != nil {
		if mapping.IgnoreNotExist {
			// ignore
			return nil
		}

		logger.WithError(err).Errorf("failed to stat - %s", mapping.IRODSPath)
		return err
	}

	entry := NewVFSEntryFromIRODSFSEntry(mapping.MappingPath, irodsEntry, mapping.ReadOnly)
	vfs.Entries[mapping.MappingPath] = entry

	// add to parent
	if len(parentDirs) > 0 {
		parentPath := parentDirs[len(parentDirs)-1]
		if parentEntry, ok := vfs.Entries[parentPath]; ok {
			parentEntry.VirtualDirEntry.DirEntries = append(parentEntry.VirtualDirEntry.DirEntries, entry)
		}
	}

	return nil
}
