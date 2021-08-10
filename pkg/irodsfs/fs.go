package irodsfs

import (
	"fmt"
	"os/user"
	"strconv"
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
	FuseConnection  *fuse.Conn
	Fuse            *fusefs.Server
	VFS             *VFS
	FileMetaUpdater *FileMetaUpdater
	IRODSClient     *irodsfs_client.FileSystem
	FileBuffer      *FileBuffer

	UID uint32
	GID uint32

	MonitoringReporter *MonitoringReporter

	Terminated bool
}

// NewFileSystem creates a new file system
func NewFileSystem(config *Config) (*IRODSFS, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "NewFileSystem",
	})

	// user
	user, err := user.Current()
	if err != nil {
		logger.WithError(err).Error("User.Current error")
		return nil, fmt.Errorf("Could not get current system user info - %v", err)
	}

	uid, err := strconv.ParseUint(user.Uid, 10, 32)
	if err != nil {
		logger.WithError(err).Errorf("Could not parse uid - %s", user.Uid)
		return nil, fmt.Errorf("Could not parse uid - %s", user.Uid)
	}

	gid, err := strconv.ParseUint(user.Gid, 10, 32)
	if err != nil {
		logger.WithError(err).Errorf("Could not parse gid - %s", user.Gid)
		return nil, fmt.Errorf("Could not parse gid - %s", user.Gid)
	}

	account, err := irodsfs_clienttype.CreateIRODSProxyAccount(config.Host, config.Port,
		config.ClientUser, config.Zone, config.ProxyUser, config.Zone,
		irodsfs_clienttype.AuthSchemeNative, config.Password)
	if err != nil {
		logger.WithError(err).Error("Could not create IRODS Account")
		return nil, fmt.Errorf("Could not create IRODS Account - %v", err)
	}

	if config.AuthScheme == AuthSchemePAM {
		sslConfig, err := irodsfs_clienttype.CreateIRODSSSLConfig(config.CACertificateFile, config.EncryptionKeySize,
			config.EncryptionAlgorithm, config.SaltSize, config.HashRounds)
		if err != nil {
			logger.WithError(err).Error("Could not create IRODS SSL Config")
			return nil, fmt.Errorf("Could not create IRODS SSL Config - %v", err)
		}

		account.SetSSLConfiguration(sslConfig)
	}

	fsconfig := irodsfs_client.NewFileSystemConfig(
		FSName,
		config.OperationTimeout, config.ConnectionIdleTimeout,
		config.ConnectionMax, config.MetadataCacheTimeout,
		config.MetadataCacheCleanupTime,
		true,
	)

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

		UID: uint32(uid),
		GID: uint32(gid),

		MonitoringReporter: NewMonitoringReporter(config.MonitorURL),
		Terminated:         false,
	}, nil
}

// ConnectToFuse connects to FUSE, must be performed before calling StartFuse
func (fs *IRODSFS) ConnectToFuse() error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "ConnectToFuse",
	})

	fuseConn, err := fuse.Mount(fs.Config.MountPath, GetFuseMountOptions(fs.Config)...)
	if err != nil {
		logger.WithError(err).Error("Could not connect to FUSE")
		return err
	}

	fs.FuseConnection = fuseConn

	// register a new client
	if fs.MonitoringReporter != nil {
		err = fs.MonitoringReporter.ReportNewInstance(fs.Config)
		if err != nil {
			return err
		}
	}

	return nil
}

// StartFuse starts fuse server, must be performed after calling ConnectToFuse
func (fs *IRODSFS) StartFuse() error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "StartFuse",
	})

	if fs.FuseConnection == nil {
		logger.Error("Could not start FUSE server without connection")
		return fmt.Errorf("Could not start FUSE server without connection")
	}

	fuseServer := fusefs.New(fs.FuseConnection, nil)
	fs.Fuse = fuseServer

	if err := fuseServer.Serve(fs); err != nil {
		logger.WithError(err).Error("Could not start FUSE server")
		return err
	}
	return nil
}

// Destroy destroys the file system
func (fs *IRODSFS) Destroy() {
	if fs.Terminated {
		// already terminated
		return
	}

	fs.Terminated = true

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "Destroy",
	})

	logger.Info("Destroying FileSystem")

	if fs.MonitoringReporter != nil {
		fs.MonitoringReporter.ReportInstanceTermination()
		fs.MonitoringReporter = nil
	}

	if fs.FuseConnection != nil {
		logger.Info("Closing fuse connection")
		fs.FuseConnection.Close()
		fs.FuseConnection = nil
	}

	// try to unmount (error may occur but ignore it)
	logger.Info("Unmounting mountpath")
	fuse.Unmount(fs.Config.MountPath)

	logger.Info("Releasing resources")
	if fs.IRODSClient != nil {
		fs.IRODSClient.Release()
		fs.IRODSClient = nil
	}

	if fs.FileBuffer != nil {
		fs.FileBuffer.Destroy()
		fs.FileBuffer = nil
	}
}

// Root returns root directory node
func (fs *IRODSFS) Root() (fusefs.Node, error) {
	if fs.Terminated {
		return nil, syscall.ECONNABORTED
	}

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
