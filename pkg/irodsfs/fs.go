package irodsfs

import (
	"fmt"
	"syscall"

	"bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	irodsfs_clienttype "github.com/cyverse/go-irodsclient/irods/types"
	log "github.com/sirupsen/logrus"
)

const (
	FSName  string = "irodsfs"
	Subtype string = "irodsfs"
)

// GetFuseMountOptions ...
func GetFuseMountOptions(config *Config) []fuse.MountOption {
	options := []fuse.MountOption{
		fuse.FSName(FSName),
		fuse.Subtype(Subtype),
	}
	return options
}

// IRODSFS ...
type IRODSFS struct {
	Config      *Config
	Fuse        *fusefs.Server
	IRODSClient *irodsfs_client.FileSystem
}

// NewFileSystem ...
func NewFileSystem(config *Config, fuseServer *fusefs.Server) (*IRODSFS, error) {
	account, err := irodsfs_clienttype.CreateIRODSProxyAccount(config.Host, config.Port,
		config.ClientUser, config.Zone, config.ProxyUser, config.Zone,
		irodsfs_clienttype.AuthSchemeNative, config.Password)
	if err != nil {
		return nil, fmt.Errorf("Could not create IRODS Account - %v", err)
	}

	fsconfig := irodsfs_client.NewFileSystemConfig(
		FSName,
		config.OperationTimeout, config.ConnectionIdleTimeout,
		config.ConnectionMax, config.CacheTimeout,
		config.CacheCleanupTime)

	fsclient := irodsfs_client.NewFileSystem(account, fsconfig)
	return &IRODSFS{
		Config:      config,
		Fuse:        fuseServer,
		IRODSClient: fsclient,
	}, nil
}

func (fs *IRODSFS) Destroy() {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Destroy",
	})

	logger.Info("Destroying FileSystem")

	fs.IRODSClient.Release()
}

func (fs *IRODSFS) Root() (fusefs.Node, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Root",
	})

	logger.Infof("Mounting %s", fs.Config.IRODSPath)
	fsEntry, err := fs.IRODSClient.StatDir(fs.Config.IRODSPath)
	if err != nil {
		if irodsfs_clienttype.IsFileNotFoundError(err) {
			return nil, syscall.ENOENT
		}
		//return err
		return nil, syscall.EREMOTEIO
	}

	return &Dir{
		FS:           fs,
		Path:         "/",
		IRODSFSEntry: fsEntry,
	}, nil
}
