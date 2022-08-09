package irodsfs

import (
	"fmt"
	"syscall"
	"time"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	irodsfs_common_irods "github.com/cyverse/irodsfs-common/irods"
	irodsfs_common_report "github.com/cyverse/irodsfs-common/report"
	irodsfs_common_utils "github.com/cyverse/irodsfs-common/utils"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	monitor_types "github.com/cyverse/irodsfs-monitor/types"
	irodspoolclient "github.com/cyverse/irodsfs-pool/client"

	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"

	"github.com/cyverse/irodsfs/commons"
	log "github.com/sirupsen/logrus"
)

const (
	FSName  string = "irodsfs"
	Subtype string = "irodsfs"
)

// GetFuseOptions returns fuse options
func GetFuseOptions(config *commons.Config) *fusefs.Options {
	options := &fusefs.Options{}

	options.AllowOther = config.AllowOther
	options.AttrTimeout = (*time.Duration)(&config.MetadataCacheTimeout)
	options.Debug = false
	options.EntryTimeout = (*time.Duration)(&config.MetadataCacheTimeout)
	options.NegativeTimeout = (*time.Duration)(&config.MetadataCacheTimeout)
	options.UID = uint32(config.UID)
	options.GID = uint32(config.GID)
	options.MaxReadAhead = config.ReadAheadMax
	options.FsName = FSName
	options.Name = Subtype
	options.SingleThreaded = false

	return options
}

// IRODSFS is a file system object
type IRODSFS struct {
	config *commons.Config

	fuseServer    *fuse.Server
	vpathManager  *irodsfs_common_vpath.VPathManager
	fsClient      irodsfs_common_irods.IRODSFSClient
	fileHandleMap *FileHandleMap
	userGroupsMap map[string]*irodsclient_types.IRODSUser

	uid uint32
	gid uint32

	reportClient         irodsfs_common_report.IRODSFSReportClient
	instanceReportClient irodsfs_common_report.IRODSFSInstanceReportClient

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

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

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
		account.SetCSNegotiation(true, irodsclient_types.CSNegotiationRequire(commons.CSNegotiationRequireSSL))
	} else if config.ClientServerNegotiation {
		if len(config.CACertificateFile) > 0 {
			sslConfig, err := irodsclient_types.CreateIRODSSSLConfig(config.CACertificateFile, config.EncryptionKeySize,
				config.EncryptionAlgorithm, config.SaltSize, config.HashRounds)
			if err != nil {
				logger.WithError(err).Error("failed to create IRODS SSL Config")
				return nil, fmt.Errorf("failed to create IRODS SSL Config - %v", err)
			}

			account.SetSSLConfiguration(sslConfig)
			account.SetCSNegotiation(config.ClientServerNegotiation, irodsclient_types.CSNegotiationRequire(config.CSNegotiationPolicy))
		}
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
	var fsClient irodsfs_common_irods.IRODSFSClient = nil
	if len(config.PoolEndpoint) > 0 {
		// use pool driver
		logger.Info("Initializing irodsfs-pool fs client")
		poolClient := irodspoolclient.NewPoolServiceClient(config.PoolEndpoint, time.Duration(config.OperationTimeout), config.InstanceID)
		err = poolClient.Connect()
		if err != nil {
			logger.WithError(err).Error("failed to connect to irodsfs-pool server %s", config.PoolEndpoint)
			return nil, fmt.Errorf("failed to connect to irodsfs-pool server %s - %v", config.PoolEndpoint, err)
		}

		fsClient, err = poolClient.NewSession(account, FSName)
		if err != nil {
			logger.WithError(err).Error("failed to create a new irodsfs-pool fs client")
			return nil, fmt.Errorf("failed to create a new irodsfs-pool fs client - %v", err)
		}
	} else {
		// use go-irodsclient driver
		logger.Info("Initializing an iRODS native file system client")
		fsClient, err = irodsfs_common_irods.NewIRODSFSClientDirect(account, fsConfig)
		if err != nil {
			logger.WithError(err).Error("failed to create a new go-irodsclient fs client")
			return nil, fmt.Errorf("failed to create a new go-irodsclient fs client - %v", err)
		}
	}

	logger.Info("Initializing virtual path mappings")
	vpathManager, err := irodsfs_common_vpath.NewVPathManager(fsClient, config.PathMappings)
	if err != nil {
		logger.WithError(err).Error("failed to create Virtual Path Manager")
		return nil, fmt.Errorf("failed to create Virtual Path Manager - %v", err)
	}

	logger.Info("Initializing File Handle Map")
	fileHandleMap := NewFileHandleMap()

	var reportClient irodsfs_common_report.IRODSFSReportClient
	var instanceReportClient irodsfs_common_report.IRODSFSInstanceReportClient
	if len(config.MonitorURL) > 0 {
		logger.Info("Initializing Monitoring Reporter")
		reportClient = irodsfs_common_report.NewIRODSFSRestReporter(config.MonitorURL, true, 100, 10)

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
			BufferSizeMax:            0,

			PoolAddress: config.PoolEndpoint,

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
		config:        config,
		fuseServer:    nil,
		vpathManager:  vpathManager,
		fsClient:      fsClient,
		fileHandleMap: fileHandleMap,
		userGroupsMap: userGroupsMap,

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

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	logger.Infof("Connecting to FUSE, mount on %s", fs.config.MountPath)

	rootDir, err := fs.Root()
	if err != nil {
		logger.WithError(err).Error("failed to create a root directory")
		return err
	}

	fuseServer, err := fusefs.Mount(fs.config.MountPath, rootDir, GetFuseOptions(fs.config))
	if err != nil {
		logger.WithError(err).Error("failed to connect to FUSE")
		return err
	}

	fs.fuseServer = fuseServer

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

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	if fs.fuseServer == nil {
		logger.Error("failed to start FUSE server")
		return fmt.Errorf("failed to start FUSE server")
	}

	fs.fuseServer.Wait()
	return nil
}

func (fs *IRODSFS) StopFuse() {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "IRODSFS",
		"function": "StopFuse",
	})

	logger.Info("Stopping FileSystem")

	// forcefully close the fuse connection
	fs.killFUSE = true

	logger.Info("Closing fuse connection")
	fs.fuseServer.Unmount()
	fs.fuseServer = nil
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

	logger.Info("Destroyed FileSystem")
}

// Root returns root directory node
func (fs *IRODSFS) Root() (*Dir, error) {
	if fs.terminated {
		return nil, syscall.ECONNABORTED
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "IRODSFS",
		"function": "Root",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	vpathEntry := fs.vpathManager.GetEntry("/")
	if vpathEntry == nil {
		logger.Errorf("failed to get Root VPath Entry")
		return nil, syscall.EREMOTEIO
	}

	if vpathEntry.Type == irodsfs_common_vpath.VPathVirtualDir {
		return NewDir(fs, vpathEntry.VirtualDirEntry.ID, "/"), nil
	} else if vpathEntry.Type == irodsfs_common_vpath.VPathIRODS {
		if vpathEntry.IRODSEntry.Type != irodsclient_fs.DirectoryEntry {
			logger.Errorf("failed to mount a data object as a root")
			return nil, syscall.EREMOTEIO
		}

		return NewDir(fs, vpathEntry.IRODSEntry.ID, "/"), nil
	} else {
		logger.Errorf("unknown VPath Entry type : %s", vpathEntry.Type)
		return nil, syscall.EREMOTEIO
	}
}

// GetNextOperationID returns next operation ID
func (fs *IRODSFS) GetNextOperationID() uint64 {
	fs.operationIDCurrent++
	return fs.operationIDCurrent
}
