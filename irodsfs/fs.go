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
	irodsfscommon_io "github.com/cyverse/irodsfs-common/io"
	irodsfscommon_irods "github.com/cyverse/irodsfs-common/irods"
	irodsfscommon_report "github.com/cyverse/irodsfs-common/report"
	irodsfscommon_utils "github.com/cyverse/irodsfs-common/utils"
	monitor_types "github.com/cyverse/irodsfs-monitor/types"
	irodspoolclient "github.com/cyverse/irodsfs-pool/client"

	"github.com/cyverse/irodsfs/commons"
	"github.com/cyverse/irodsfs/vfs"
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
	config          *commons.Config
	fuseConnection  *fuse.Conn
	fuse            *fusefs.Server
	vfs             *vfs.VFS
	fileMetaUpdater *FileMetaUpdater
	fsClient        irodsfscommon_irods.IRODSFSClient
	fileHandleMap   *FileHandleMap
	buffer          irodsfscommon_io.Buffer
	userGroupsMap   map[string]*irodsclient_types.IRODSUser

	uid uint32
	gid uint32

	reportClient         irodsfscommon_report.IRODSFSReportClient
	instanceReportClient irodsfscommon_report.IRODSFSInstanceReportClient

	terminated bool
	killFUSE   bool

	operationIDCurrent uint64
}

// NewFileSystem creates a new file system
func NewFileSystem(config *commons.Config) (*IRODSFS, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "NewFileSystem",
	})

	defer irodsfscommon_utils.StackTraceFromPanic(logger)

	account, err := irodsclient_types.CreateIRODSProxyAccount(config.Host, config.Port,
		config.ClientUser, config.Zone, config.ProxyUser, config.Zone,
		irodsclient_types.AuthScheme(config.AuthScheme), config.Password, config.Resource)
	if err != nil {
		logger.WithError(err).Error("failed to create IRODS Account")
		return nil, fmt.Errorf("failed to create IRODS Account - %v", err)
	}

	if irodsclient_types.AuthScheme(config.AuthScheme) == irodsclient_types.AuthSchemePAM {
		sslConfig, err := irodsclient_types.CreateIRODSSSLConfig(config.CACertificateFile, config.EncryptionKeySize,
			config.EncryptionAlgorithm, config.SaltSize, config.HashRounds)
		if err != nil {
			logger.WithError(err).Error("failed to create IRODS SSL Config")
			return nil, fmt.Errorf("failed to create IRODS SSL Config - %v", err)
		}

		account.SetSSLConfiguration(sslConfig)
	}

	cacheTimeoutSettings := []irodsclient_fs.MetadataCacheTimeoutSetting{}
	for _, metadataCacheTimeoutSetting := range config.MetadataCacheTimeoutSettings {
		if len(metadataCacheTimeoutSetting.Path) > 0 {
			cacheTimeoutSetting := irodsclient_fs.MetadataCacheTimeoutSetting{
				Path:    metadataCacheTimeoutSetting.Path,
				Timeout: time.Duration(metadataCacheTimeoutSetting.Timeout),
				Inherit: metadataCacheTimeoutSetting.Inherit,
			}
			cacheTimeoutSettings = append(cacheTimeoutSettings, cacheTimeoutSetting)
		}
	}

	fsConfig := irodsclient_fs.NewFileSystemConfig(
		FSName,
		time.Duration(config.ConnectionLifespan),
		time.Duration(config.OperationTimeout), time.Duration(config.ConnectionIdleTimeout),
		config.ConnectionMax, time.Duration(config.MetadataCacheTimeout),
		time.Duration(config.MetadataCacheCleanupTime),
		cacheTimeoutSettings,
		config.StartNewTransaction,
		config.InvalidateParentEntryCacheImmediately,
	)

	logger.Info("Initializing an iRODS file system client")
	var fsClient irodsfscommon_irods.IRODSFSClient = nil
	if len(config.PoolHost) > 0 {
		// use pool driver
		logger.Info("Initializing irodsfs-pool fs client")
		fsClient, err = irodspoolclient.NewIRODSFSClientPool(config.PoolHost, config.PoolPort, account, fsConfig, config.InstanceID)
		if err != nil {
			logger.WithError(err).Error("failed to create a new irodsfs-pool fs client")
			return nil, fmt.Errorf("failed to create a new irodsfs-pool fs client - %v", err)
		}
	} else {
		// use go-irodsclient driver
		logger.Info("Initializing an iRODS native file system client")
		fsClient, err = irodsfscommon_irods.NewIRODSFSClientDirect(account, fsConfig)
		if err != nil {
			logger.WithError(err).Error("failed to create a new go-irodsclient fs client")
			return nil, fmt.Errorf("failed to create a new go-irodsclient fs client - %v", err)
		}
	}

	logger.Info("Initializing VFS")
	vfs, err := vfs.NewVFS(fsClient, config.PathMappings)
	if err != nil {
		logger.WithError(err).Error("failed to create VFS")
		return nil, fmt.Errorf("failed to create VFS - %v", err)
	}

	logger.Info("Initializing File Meta Updater")
	fileMetaUpdater := NewFileMetaUpdater()

	logger.Info("Initializing File Handle Map")
	fileHandleMap := NewFileHandleMap()

	var ramBuffer irodsfscommon_io.Buffer
	if len(config.PoolHost) == 0 && config.BufferSizeMax > 0 {
		logger.Infof("Initializing RAMBuffer, bufferSize %d", config.BufferSizeMax)
		ramBuffer = irodsfscommon_io.NewRAMBuffer(config.BufferSizeMax)
	}

	var reportClient irodsfscommon_report.IRODSFSReportClient
	var instanceReportClient irodsfscommon_report.IRODSFSInstanceReportClient
	if len(config.MonitorURL) > 0 {
		logger.Info("Initializing Monitoring Reporter")
		reportClient = irodsfscommon_report.NewIRODSFSRestReporter(config.MonitorURL, true, 100, 10)

		instanceInfo := &monitor_types.ReportInstance{
			Host:                     config.Host,
			Port:                     config.Port,
			Zone:                     config.Zone,
			ClientUser:               config.ClientUser,
			ProxyUser:                config.ProxyUser,
			AuthScheme:               config.AuthScheme,
			ReadAheadMax:             config.ReadAheadMax,
			OperationTimeout:         time.Duration(config.OperationTimeout).String(),
			ConnectionIdleTimeout:    time.Duration(config.ConnectionIdleTimeout).String(),
			ConnectionMax:            config.ConnectionMax,
			MetadataCacheTimeout:     time.Duration(config.MetadataCacheTimeout).String(),
			MetadataCacheCleanupTime: time.Duration(config.MetadataCacheCleanupTime).String(),
			BufferSizeMax:            config.BufferSizeMax,

			PoolHost: config.PoolHost,
			PoolPort: config.PoolPort,

			InstanceID: config.InstanceID,

			CreationTime: time.Now().UTC(),
		}

		instanceReportClient, err = reportClient.StartInstance(instanceInfo)
		if err != nil {
			logger.WithError(err).Errorf("failed to report the instance to monitoring service")
			// keep going.
		}
	}

	userGroups, err := fsClient.ListUserGroups(account.ClientUser)
	if err != nil {
		logger.WithError(err).Errorf("failed to list groups for a user - %s", account.ClientUser)
		return nil, fmt.Errorf("failed to list groups for a user - %s", account.ClientUser)
	}

	userGroupsMap := map[string]*irodsclient_types.IRODSUser{}
	for _, userGroup := range userGroups {
		userGroupsMap[userGroup.Name] = userGroup
	}

	return &IRODSFS{
		config:          config,
		fuse:            nil,
		vfs:             vfs,
		fileMetaUpdater: fileMetaUpdater,
		fsClient:        fsClient,
		fileHandleMap:   fileHandleMap,
		buffer:          ramBuffer,
		userGroupsMap:   userGroupsMap,

		uid: uint32(config.UID),
		gid: uint32(config.GID),

		reportClient:         reportClient,
		instanceReportClient: instanceReportClient,
		terminated:           false,

		operationIDCurrent: 0,
	}, nil
}

// ConnectToFuse connects to FUSE, must be performed before calling StartFuse
func (fs *IRODSFS) ConnectToFuse() error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "IRODSFS",
		"function": "ConnectToFuse",
	})

	defer irodsfscommon_utils.StackTraceFromPanic(logger)

	logger.Infof("Connecting to FUSE, mount on %s", fs.config.MountPath)

	fuseConn, err := fuse.Mount(fs.config.MountPath, GetFuseMountOptions(fs.config)...)
	if err != nil {
		logger.WithError(err).Error("failed to connect to FUSE")
		return err
	}

	fs.fuseConnection = fuseConn

	logger.Infof("Connected to FUSE, mount on %s", fs.config.MountPath)
	return nil
}

// StartFuse starts fuse server, must be performed after calling ConnectToFuse
func (fs *IRODSFS) StartFuse() error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "IRODSFS",
		"function": "StartFuse",
	})

	defer irodsfscommon_utils.StackTraceFromPanic(logger)

	if fs.fuseConnection == nil {
		logger.Error("failed to start FUSE server without connection")
		return fmt.Errorf("failed to start FUSE server without connection")
	}

	fuseServer := fusefs.New(fs.fuseConnection, nil)
	fs.fuse = fuseServer

	if err := fuseServer.Serve(fs); err != nil {
		if fs.killFUSE {
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
		os.Stat(fs.config.MountPath)
	}()

	// forcefully close the fuse connection
	fs.killFUSE = true
	fs.fuseConnection.Close()
}

// Destroy destroys the file system
func (fs *IRODSFS) Destroy() {
	if fs.terminated {
		// already terminated
		return
	}

	fs.terminated = true

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "IRODSFS",
		"function": "Destroy",
	})

	logger.Info("Destroying FileSystem")

	if fs.instanceReportClient != nil {
		fs.instanceReportClient.Terminate()
		fs.instanceReportClient = nil
	}

	if fs.reportClient != nil {
		fs.reportClient.Release()
		fs.reportClient = nil
	}

	if fs.fileHandleMap != nil {
		fs.fileHandleMap.Clear()
		fs.fileHandleMap = nil
	}

	logger.Info("> Releasing resources")
	if fs.fsClient != nil {
		fs.fsClient.Release()
		fs.fsClient = nil
	}

	if fs.buffer != nil {
		fs.buffer.Release()
		fs.buffer = nil
	}

	if fs.fuseConnection != nil {
		logger.Info("> Closing fuse connection")
		fs.fuseConnection.Close()
		fs.fuseConnection = nil
	}

	// try to unmount (error may occur but ignore it)
	logger.Info("> Unmounting mountpath")
	fuse.Unmount(fs.config.MountPath)

	logger.Info("Destroyed FileSystem")
}

// Root returns root directory node
func (fs *IRODSFS) Root() (fusefs.Node, error) {
	if fs.terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "IRODSFS",
		"function": "Root",
	})

	defer irodsfscommon_utils.StackTraceFromPanic(logger)

	vfsEntry := fs.vfs.GetEntry("/")
	if vfsEntry == nil {
		logger.Errorf("failed to get Root VFS Entry")
		return nil, syscall.EREMOTEIO
	}

	if vfsEntry.Type == vfs.VFSVirtualDirEntryType {
		return NewDir(fs, vfsEntry.VirtualDirEntry.ID, "/"), nil
	} else if vfsEntry.Type == vfs.VFSIRODSEntryType {
		if vfsEntry.IRODSEntry.Type != irodsclient_fs.DirectoryEntry {
			logger.Errorf("failed to mount a data object as a root")
			return nil, syscall.EREMOTEIO
		}

		return NewDir(fs, vfsEntry.IRODSEntry.ID, "/"), nil
	} else {
		logger.Errorf("unknown VFS Entry type : %s", vfsEntry.Type)
		return nil, syscall.EREMOTEIO
	}
}

// GetNextOperationID returns next operation ID
func (fs *IRODSFS) GetNextOperationID() uint64 {
	fs.operationIDCurrent++
	return fs.operationIDCurrent
}