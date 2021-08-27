package vfs

import (
	"fmt"
	"strings"
	"time"

	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/irodsfs/pkg/utils"
	log "github.com/sirupsen/logrus"
)

// VFSEntryType determins if the VFS entry is actual iRODS entry (irods) or virtual/temporary entry (virtual) (irods).
// Virtual entries are read-only, and a directory containing irods or virtual entries in it.
type VFSEntryType string

const (
	// VFSVirtualDirEntryType is an entry type for virtual vfs entry
	VFSVirtualDirEntryType VFSEntryType = "virtual"
	// VFSIRODSEntryType is an entry type for irods vfs entry
	VFSIRODSEntryType VFSEntryType = "irods"
)

// VFSVirtualDirEntry is a virtual VFS entry struct
type VFSVirtualDirEntry struct {
	ID         int64
	Name       string
	Path       string
	Owner      string
	Size       int64
	CreateTime time.Time
	ModifyTime time.Time
	DirEntries []*VFSEntry
}

// VFSEntry is a VFS entry struct
type VFSEntry struct {
	Type     VFSEntryType
	Path     string
	ReadOnly bool

	// Only one of fields below is filled according to the Type
	VirtualDirEntry *VFSVirtualDirEntry
	IRODSEntry      *irodsfs_client.FSEntry
}

// NewVFSEntryFromIRODSFSEntry creates a new VFSEntry from IRODSFSEntry
func NewVFSEntryFromIRODSFSEntry(path string, fsEntry *irodsfs_client.FSEntry, readonly bool) *VFSEntry {
	return &VFSEntry{
		Type:            VFSIRODSEntryType,
		Path:            path,
		ReadOnly:        readonly,
		VirtualDirEntry: nil,
		IRODSEntry:      fsEntry,
	}
}

// ToString stringifies the object
func (entry *VFSEntry) ToString() string {
	return fmt.Sprintf("<VFSEntry %s %s %t %p %p>", entry.Type, entry.Path, &entry.ReadOnly, entry.VirtualDirEntry, entry.IRODSEntry)
}

// GetIRODSPath returns relative path
func (entry *VFSEntry) GetIRODSPath(vpath string) (string, error) {
	logger := log.WithFields(log.Fields{
		"package":  "vfs",
		"function": "VFSEntry.GetIRODSPath",
	})

	if entry.Type != VFSIRODSEntryType {
		err := fmt.Errorf("failed to compute IRODS Path from non-irods entry")
		logger.Error(err)
		return "", err
	}

	relPath, err := utils.GetRelativePath(entry.Path, vpath)
	if err != nil {
		logger.WithError(err).Errorf("failed to compute relative path")
		return "", err
	}

	if strings.HasPrefix(relPath, "../") {
		err := fmt.Errorf("failed to compute relative path - %s to %s", entry.Path, vpath)
		return "", err
	}

	if relPath == "." {
		return entry.IRODSEntry.Path, nil
	}

	return utils.JoinPath(entry.IRODSEntry.Path, relPath), nil
}
