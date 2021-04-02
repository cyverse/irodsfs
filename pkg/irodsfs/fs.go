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

// GetFuseMountOptions returns fuse mount options
func GetFuseMountOptions(config *Config) []fuse.MountOption {
	options := []fuse.MountOption{
		fuse.FSName(FSName),
		fuse.Subtype(Subtype),
		fuse.AsyncRead(),
		fuse.WritebackCache(),
		fuse.MaxReadahead(uint32(config.ReadAheadMax)),
	}

	// handle allow other
	if config.AllowOther {
		options = append(options, fuse.AllowOther())
	}

	return options
}

// IRODSFS is a file system object
type IRODSFS struct {
	Config          *Config
	Fuse            *fusefs.Server
	VFS             *VFS
	FileMetaUpdater *FileMetaUpdater
	IRODSClient     *irodsfs_client.FileSystem
	FileBuffer      *FileBuffer
}

// NewFileSystem creates a new file system
func NewFileSystem(config *Config) (*IRODSFS, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "NewFileSystem",
	})

	account, err := irodsfs_clienttype.CreateIRODSProxyAccount(config.Host, config.Port,
		config.ClientUser, config.Zone, config.ProxyUser, config.Zone,
		irodsfs_clienttype.AuthSchemeNative, config.Password)
	if err != nil {
		logger.WithError(err).Error("Could not create IRODS Account")
		return nil, fmt.Errorf("Could not create IRODS Account - %v", err)
	}

	fsconfig := irodsfs_client.NewFileSystemConfig(
		FSName,
		config.OperationTimeout, config.ConnectionIdleTimeout,
		config.ConnectionMax, config.MetadataCacheTimeout,
		config.MetadataCacheCleanupTime)

	fsclient, err := irodsfs_client.NewFileSystem(account, fsconfig)
	if err != nil {
		logger.WithError(err).Error("Could not create IRODS FileSystem Client")
		return nil, fmt.Errorf("Could not create IRODS FileSystem Client - %v", err)
	}

	vfs, err := NewVFS(fsclient, config.PathMappings)
	if err != nil {
		logger.WithError(err).Error("Could not create VFS")
		return nil, fmt.Errorf("Could not create VFS - %v", err)
	}

	fileMetaUpdater := NewFileMetaUpdater()

	fileBuffer, err := NewFileBuffer(config.FileBufferStoragePath, config.FileBufferSizeMax)
	if err != nil {
		logger.WithError(err).Error("Could not create FileBuffer")
		return nil, fmt.Errorf("Could not create FileBuffer - %v", err)
	}

	return &IRODSFS{
		Config:          config,
		Fuse:            nil,
		VFS:             vfs,
		FileMetaUpdater: fileMetaUpdater,
		IRODSClient:     fsclient,
		FileBuffer:      fileBuffer,
	}, nil
}

func (fs *IRODSFS) StartFuse() error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "StartFuse",
	})

	fuseConn, err := fuse.Mount(fs.Config.MountPath, GetFuseMountOptions(fs.Config)...)
	if err != nil {
		logger.WithError(err).Error("Could not connect to FUSE")
		return err
	}
	defer fuseConn.Close()

	fuseServer := fusefs.New(fuseConn, nil)
	fs.Fuse = fuseServer

	if err := fuseServer.Serve(fs); err != nil {
		logger.WithError(err).Error("Could not start FUSE server")
		return err
	}
	return nil
}

// Destroy destroys the file system
func (fs *IRODSFS) Destroy() {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Destroy",
	})

	logger.Info("Destroying FileSystem")

	fs.IRODSClient.Release()
	fs.FileBuffer.Destroy()
}

// Root returns root directory node
func (fs *IRODSFS) Root() (fusefs.Node, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Root",
	})

	vfsEntry := fs.VFS.GetEntry("/")
	if vfsEntry == nil {
		logger.Errorf("Could not get Root VFS Entry")
		return nil, syscall.EREMOTEIO
	}

	if vfsEntry.Type == VFSVirtualDirEntryType {
		return &Dir{
			FS:      fs,
			InodeID: vfsEntry.VirtualDirEntry.ID,
			Path:    "/",
		}, nil
	} else if vfsEntry.Type == VFSIRODSEntryType {
		if vfsEntry.IRODSEntry.Type != irodsfs_client.FSDirectoryEntry {
			logger.Errorf("Could not mount a data object as a root")
			return nil, syscall.EREMOTEIO
		}

		return &Dir{
			FS:      fs,
			InodeID: vfsEntry.IRODSEntry.ID,
			Path:    "/",
		}, nil
	} else {
		logger.Errorf("Unknown VFS Entry type : %s", vfsEntry.Type)
		return nil, syscall.EREMOTEIO
	}
}
