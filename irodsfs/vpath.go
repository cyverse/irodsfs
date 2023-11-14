package irodsfs

import (
	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsfs_common_irods "github.com/cyverse/irodsfs-common/irods"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	"golang.org/x/xerrors"
)

func ensureVPathEntryIsIRODSDir(fsClient irodsfs_common_irods.IRODSFSClient, vpathEntry *irodsfs_common_vpath.VPathEntry) error {
	err := ensureVPathEntryIsIRODSEntry(fsClient, vpathEntry)
	if err != nil {
		return err
	}

	if vpathEntry.IRODSEntry.Type != irodsclient_fs.DirectoryEntry {
		return xerrors.Errorf("failed to mount a data object as a root")
	}

	return nil
}

func ensureVPathEntryIsIRODSEntry(fsClient irodsfs_common_irods.IRODSFSClient, vpathEntry *irodsfs_common_vpath.VPathEntry) error {
	if !vpathEntry.IsIRODSEntry() {
		return xerrors.Errorf("VPath Entry %s is not iRODS entry", vpathEntry.Path)
	}

	if vpathEntry.RequireIRODSEntryUpdate() {
		// update
		err := vpathEntry.UpdateIRODSEntry(fsClient)
		if err != nil {
			return err
		}
	}

	return nil
}

func isVPathEntryUnmodifiable(vpathEntry *irodsfs_common_vpath.VPathEntry, targetPath string) bool {
	if vpathEntry.Path == targetPath {
		return true
	}

	if vpathEntry.ReadOnly || vpathEntry.IsVirtualDirEntry() {
		return true
	}

	return false
}
