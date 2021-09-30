package irodsfs

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"bazil.org/fuse"
	fusefs "bazil.org/fuse/fs"
	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	"github.com/cyverse/irodsfs/pkg/asyncwrite"
	"github.com/cyverse/irodsfs/pkg/commons"
	"github.com/cyverse/irodsfs/pkg/irodsapi"
	"github.com/cyverse/irodsfs/pkg/report"
	"github.com/cyverse/irodsfs/pkg/vfs"
	log "github.com/sirupsen/logrus"
)

const (
	FSName  string = "irodsfs"
	Subtype string = "irodsfs"
)

// GetFuseMountOptions returns fuse mount options
func GetFuseMountOptions(config *commons.Config) []fuse.MountOption {
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
	Config          *commons.Config
	FuseConnection  *fuse.Conn
	Fuse            *fusefs.Server
	VFS             *vfs.VFS
	FileMetaUpdater *FileMetaUpdater
	IRODSClient     irodsapi.IRODSClient
	Buffer          asyncwrite.Buffer

	UID uint32
	GID uint32

	MonitoringReporter *report.MonitoringReporter

	Terminated bool
	KillFUSE   bool
}

// NewFileSystem creates a new file system
func NewFileSystem(config *commons.Config) (*IRODSFS, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "NewFileSystem",
	})

	account, err := irodsclient_types.CreateIRODSProxyAccount(config.Host, config.Port,
		config.ClientUser, config.Zone, config.ProxyUser, config.Zone,
		irodsclient_types.AuthSchemeNative, config.Password)
	if err != nil {
		logger.WithError(err).Error("failed to create IRODS Account")
		return nil, fmt.Errorf("failed to create IRODS Account - %v", err)
	}

	if config.AuthScheme == commons.AuthSchemePAM {
		sslConfig, err := irodsclient_types.CreateIRODSSSLConfig(config.CACertificateFile, config.EncryptionKeySize,
			config.EncryptionAlgorithm, config.SaltSize, config.HashRounds)
		if err != nil {
			logger.WithError(err).Error("failed to create IRODS SSL Config")
			return nil, fmt.Errorf("failed to create IRODS SSL Config - %v", err)
		}

		account.SetSSLConfiguration(sslConfig)
	}

	fsconfig := irodsclient_fs.NewFileSystemConfig(
		FSName,
		config.OperationTimeout, config.ConnectionIdleTimeout,
		config.ConnectionMax, config.MetadataCacheTimeout,
		config.MetadataCacheCleanupTime,
		true,
	)

	var irodsClient irodsapi.IRODSClient = nil
	if len(config.PoolHost) > 0 {
		// use pool driver
		irodsClient, err = irodsapi.NewPoolClientDriver(config.PoolHost, config.PoolPort, account, fsconfig)
		if err != nil {
			logger.WithError(err).Error("failed to create a new iRODS Pool Client")
			return nil, fmt.Errorf("failed to create a new iRODS Pool Client - %v", err)
		}
	} else {
		// use go-irodsclient driver
		irodsClient, err = irodsapi.NewGoIRODSClientDriver(account, fsconfig)
		if err != nil {
			logger.WithError(err).Error("failed to create a new iRODS Client")
			return nil, fmt.Errorf("failed to create a new iRODS Client - %v", err)
		}
	}

	vfs, err := vfs.NewVFS(irodsClient, config.PathMappings)
	if err != nil {
		logger.WithError(err).Error("failed to create VFS")
		return nil, fmt.Errorf("failed to create VFS - %v", err)
	}

	fileMetaUpdater := NewFileMetaUpdater()

	var ramBuffer asyncwrite.Buffer
	if len(config.PoolHost) == 0 && config.BufferSizeMax > 0 {
		ramBuffer = asyncwrite.NewRAMBuffer(config.BufferSizeMax)
	}

	return &IRODSFS{
		Config:          config,
		Fuse:            nil,
		VFS:             vfs,
		FileMetaUpdater: fileMetaUpdater,
		IRODSClient:     irodsClient,
		Buffer:          ramBuffer,

		UID: uint32(config.UID),
		GID: uint32(config.GID),

		MonitoringReporter: report.NewMonitoringReporter(config.MonitorURL, true),
		Terminated:         false,
	}, nil
}

// ConnectToFuse connects to FUSE, must be performed before calling StartFuse
func (fs *IRODSFS) ConnectToFuse() error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "IRODSFS",
		"function": "ConnectToFuse",
	})

	fuseConn, err := fuse.Mount(fs.Config.MountPath, GetFuseMountOptions(fs.Config)...)
	if err != nil {
		logger.WithError(err).Error("failed to connect to FUSE")
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
		"struct":   "IRODSFS",
		"function": "StartFuse",
	})

	if fs.FuseConnection == nil {
		logger.Error("failed to start FUSE server without connection")
		return fmt.Errorf("failed to start FUSE server without connection")
	}

	fuseServer := fusefs.New(fs.FuseConnection, nil)
	fs.Fuse = fuseServer

	if err := fuseServer.Serve(fs); err != nil {
		if fs.KillFUSE {
			// suppress error
			return nil
		}

		logger.WithError(err).Error("failed to start FUSE server")
		return err
	}
	return nil
}

func (fs *IRODSFS) StopFuse() {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "IRODSFS",
		"function": "StopFuse",
	})

	logger.Info("Stopping FileSystem")

	go func() {
		logger.Info("Testing mount point")
		time.Sleep(100 * time.Millisecond)
		// this is to create a request to dead fuse
		// causing the fuse client to notice it's closing
		os.Stat(fs.Config.MountPath)
	}()

	// forcefully close the fuse connection
	fs.KillFUSE = true
	fs.FuseConnection.Close()
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
		"struct":   "IRODSFS",
		"function": "Destroy",
	})

	logger.Info("Destroying FileSystem")

	if fs.MonitoringReporter != nil {
		fs.MonitoringReporter.ReportInstanceTermination()
		fs.MonitoringReporter = nil
	}

	logger.Info("Releasing resources")
	if fs.IRODSClient != nil {
		fs.IRODSClient.Release()
		fs.IRODSClient = nil
	}

	if fs.Buffer != nil {
		fs.Buffer.Release()
		fs.Buffer = nil
	}

	if fs.FuseConnection != nil {
		logger.Info("Closing fuse connection")
		fs.FuseConnection.Close()
		fs.FuseConnection = nil
	}

	// try to unmount (error may occur but ignore it)
	logger.Info("Unmounting mountpath")
	fuse.Unmount(fs.Config.MountPath)
}

// Root returns root directory node
func (fs *IRODSFS) Root() (fusefs.Node, error) {
	if fs.Terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "IRODSFS",
		"function": "Root",
	})

	vfsEntry := fs.VFS.GetEntry("/")
	if vfsEntry == nil {
		logger.Errorf("failed to get Root VFS Entry")
		return nil, syscall.EREMOTEIO
	}

	if vfsEntry.Type == vfs.VFSVirtualDirEntryType {
		return &Dir{
			FS:      fs,
			InodeID: vfsEntry.VirtualDirEntry.ID,
			Path:    "/",
		}, nil
	} else if vfsEntry.Type == vfs.VFSIRODSEntryType {
		if vfsEntry.IRODSEntry.Type != irodsapi.DirectoryEntry {
			logger.Errorf("failed to mount a data object as a root")
			return nil, syscall.EREMOTEIO
		}

		return &Dir{
			FS:      fs,
			InodeID: vfsEntry.IRODSEntry.ID,
			Path:    "/",
		}, nil
	} else {
		logger.Errorf("unknown VFS Entry type : %s", vfsEntry.Type)
		return nil, syscall.EREMOTEIO
	}
}
