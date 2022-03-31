package vfs

import (
	"fmt"
	"strings"
	"time"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsfscommon_utils "github.com/cyverse/irodsfs-common/utils"
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
	IRODSEntry      *irodsclient_fs.Entry
}

// NewVFSEntryFromIRODSFSEntry creates a new VFSEntry from IRODSEntry
func NewVFSEntryFromIRODSFSEntry(path string, irodsEntry *irodsclient_fs.Entry, readonly bool) *VFSEntry {
	return &VFSEntry{
		Type:            VFSIRODSEntryType,
		Path:            path,
		ReadOnly:        readonly,
		VirtualDirEntry: nil,
		IRODSEntry:      irodsEntry,
	}
}

// ToString stringifies the object
func (entry *VFSEntry) ToString() string {
	return fmt.Sprintf("<VFSEntry %s %s %t %p %p>", entry.Type, entry.Path, entry.ReadOnly, entry.VirtualDirEntry, entry.IRODSEntry)
}

// GetIRODSPath returns relative path
func (entry *VFSEntry) GetIRODSPath(vpath string) (string, error) {
	logger := log.WithFields(log.Fields{
		"package":  "vfs",
		"struct":   "VFSEntry",
		"function": "GetIRODSPath",
	})

	if entry.Type != VFSIRODSEntryType {
		err := fmt.Errorf("failed to compute IRODS Path from non-irods entry")
		logger.Error(err)
		return "", err
	}

	relPath, err := irodsfscommon_utils.GetRelativePath(entry.Path, vpath)
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

	return irodsfscommon_utils.JoinPath(entry.IRODSEntry.Path, relPath), nil
}
