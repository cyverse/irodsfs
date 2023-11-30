package irodsfs

import (
	"context"
	"syscall"

	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
	log "github.com/sirupsen/logrus"
)

// DummyDirGetattr returns an attr for the given irods path
func DummyDirGetattr(ctx context.Context, fs *IRODSFS, path string, vpathReadonly bool, out *fuse.AttrOut) syscall.Errno {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "DummyDirGetattr",
	})

	entry, err := fs.fsClient.Stat(path)
	if err != nil {
		if irodsclient_types.IsFileNotFoundError(err) {
			logger.Debugf("failed to find file or dir for path %q", path)
			return syscall.ENOENT
		}

		logger.Errorf("%+v", err)
		return syscall.EREMOTEIO
	}

	mode := IRODSGetACL(ctx, fs, entry, vpathReadonly)
	setAttrOutForIRODSEntry(fs.inodeManager, entry, fs.uid, fs.gid, mode, &out.Attr)
	return fusefs.OK
}
