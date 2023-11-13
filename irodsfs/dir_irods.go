package irodsfs

import (
	"syscall"

	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	log "github.com/sirupsen/logrus"
)

// NewIRODSRoot returns root directory node for iRODS collection
func NewIRODSRoot(fs *IRODSFS, vpathEntry *irodsfs_common_vpath.VPathEntry) (*Dir, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "NewIRODSRoot",
	})

	err := ensureVPathEntryIsIRODSDir(fs.fsClient, vpathEntry)
	if err != nil {
		logger.Errorf("%+v", err)
		return nil, syscall.EREMOTEIO
	}

	return NewDir(fs, vpathEntry.IRODSEntry.ID, "/"), nil
}
