package irodsfs

import (
	"fmt"
	"strings"
	"time"

	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	log "github.com/sirupsen/logrus"
)

type VFSEntryType string

const (
	VFSVirtualDirEntryType VFSEntryType = "virtual"
	VFSIRODSEntryType      VFSEntryType = "irods"
)

// VFSVirtualDirEntry ...
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

// VFSEntry ...
type VFSEntry struct {
	Type            VFSEntryType
	Path            string
	VirtualDirEntry *VFSVirtualDirEntry
	IRODSEntry      *irodsfs_client.FSEntry
}

// NewVFSEntryFromIRODSFSEntry ...
func NewVFSEntryFromIRODSFSEntry(path string, fsEntry *irodsfs_client.FSEntry) *VFSEntry {
	return &VFSEntry{
		Type:            VFSIRODSEntryType,
		Path:            path,
		VirtualDirEntry: nil,
		IRODSEntry:      fsEntry,
	}
}

// ToString stringifies the object
func (entry *VFSEntry) ToString() string {
	return fmt.Sprintf("<VFSEntry %s %p %p>", entry.Type, entry.Path, entry.VirtualDirEntry, entry.IRODSEntry)
}

// GetIRODSPath returns relative path
func (entry *VFSEntry) GetIRODSPath(vpath string) (string, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "VFSEntry.GetIRODSPath",
	})

	if entry.Type != VFSIRODSEntryType {
		err := fmt.Errorf("Cannot compute IRODS Path from non-irods entry")
		logger.Error(err)
		return "", err
	}

	relPath, err := GetRelativePath(entry.Path, vpath)
	if err != nil {
		logger.WithError(err).Errorf("cannot compute relative path")
		return "", err
	}

	if strings.HasPrefix(relPath, "../") {
		err := fmt.Errorf("cannot compute relative path - %s to %s", entry.Path, vpath)
		return "", err
	}

	if relPath == "." {
		return entry.IRODSEntry.Path, nil
	}

	return JoinPath(entry.IRODSEntry.Path, vpath), nil
}
