package irodsfs

import (
	"syscall"
	"time"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	irodsfs_common_inode "github.com/cyverse/irodsfs-common/inode"
	irodsfs_common_irods "github.com/cyverse/irodsfs-common/irods"
	irodsfs_common_report "github.com/cyverse/irodsfs-common/report"
	irodsfs_common_utils "github.com/cyverse/irodsfs-common/utils"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	monitor_types "github.com/cyverse/irodsfs-monitor/types"
	irodspoolclient "github.com/cyverse/irodsfs-pool/client"
	"golang.org/x/xerrors"

	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"

	"github.com/cyverse/irodsfs/commons"
	"github.com/cyverse/irodsfs/utils"
	log "github.com/sirupsen/logrus"
)

const (
	FSName  string = "irodsfs"
	Subtype string = "irodsfs"
)

// GetFuseOptions returns fuse options
func GetFuseOptions(config *commons.Config) *fusefs.Options {
	options := &fusefs.Options{}

	// TODO: handle fuse specific options in config.FuseOptions
	options.AllowOther = config.AllowOther
	if config.Debug && config.Foreground {
		options.Debug = true
	}

	options.AttrTimeout = nil
	options.EntryTimeout = nil
	options.NegativeTimeout = nil
	options.UID = uint32(config.UID)
	options.GID = uint32(config.GID)
	options.MaxReadAhead = config.ReadAheadMax
	options.FsName = FSName
	options.Name = Subtype
	options.SingleThreaded = false
	options.IgnoreSecurityLabels = true
	options.EnableLocks = true
	options.DisableReadDirPlus = true
	return options
}

// IRODSFS is a file system object
type IRODSFS struct {
	config *commons.Config

	fuseServer    *fuse.Server
	inodeManager  *irodsfs_common_inode.InodeManager
	vpathManager  *irodsfs_common_vpath.VPathManager
	fsClient      irodsfs_common_irods.IRODSFSClient
	fileHandleMap *FileHandleMap
	userGroupsMap map[string]*irodsclient_types.IRODSUser

	uid uint32
	gid uint32

	reportClient         irodsfs_common_report.IRODSFSReportClient
	instanceReportClient irodsfs_common_report.IRODSFSInstanceReportClient

	operationIDCurrent uint64

	terminated bool
}

// NewFileSystem creates a new file system
func NewFileSystem(config *commons.Config) (*IRODSFS, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "NewFileSystem",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	authScheme := irodsclient_types.GetAuthScheme(config.AuthScheme)
	if authScheme == irodsclient_types.AuthSchemeUnknown {
		authScheme = irodsclient_types.AuthSchemeNative
	}

	csNegotiation, err := irodsclient_types.GetCSNegotiationRequire(config.CSNegotiationPolicy)
	if err != nil {
		return nil, err
	}

	account, err := irodsclient_types.CreateIRODSProxyAccount(config.Host, config.Port,
		config.ClientUser, config.Zone, config.ProxyUser, config.Zone,
		authScheme, config.Password, config.Resource)
	if err != nil {
		accountErr := xerrors.Errorf("failed to create IRODS Account: %w", err)
		logger.Errorf("%+v", accountErr)
		return nil, accountErr
	}

	logger.Infof("Connect to IRODS server using %q auth scheme", string(authScheme))

	// optional for ssl,
	// no harm if it is not ssl
	sslConfig, err := irodsclient_types.CreateIRODSSSLConfig(config.CACertificateFile, config.CACertificatePath, config.EncryptionKeySize,
		config.EncryptionAlgorithm, config.SaltSize, config.HashRounds)
	if err != nil {
		sslErr := xerrors.Errorf("failed to create IRODS SSL Config: %w", err)
		logger.Errorf("%+v", sslErr)
		return nil, sslErr
	}

	account.SkipVerifyTLS = config.VerifyServer == "hostname"

	if authScheme.IsPAM() {
		logger.Info("PAM requires SSL, enabling CS negotiation")

		account.SetSSLConfiguration(sslConfig)
		account.SetCSNegotiation(true, irodsclient_types.CSNegotiationRequireSSL)
	} else if config.ClientServerNegotiation {
		logger.Info("Enabling CS negotiation to turn on SSL")

		account.SetSSLConfiguration(sslConfig)
		account.SetCSNegotiation(config.ClientServerNegotiation, csNegotiation)
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

	fsConfig := irodsclient_fs.NewFileSystemConfig(FSName)

	fsConfig.IOConnection.MaxNumber = config.ConnectionMax
	fsConfig.IOConnection.TCPBufferSize = commons.TCPBufferSizeDefault
	fsConfig.IOConnection.OperationTimeout = time.Duration(config.OperationTimeout)
	fsConfig.IOConnection.IdleTimeout = time.Duration(config.ConnectionIdleTimeout)
	fsConfig.IOConnection.Lifespan = time.Duration(config.ConnectionLifespan)
	fsConfig.IOConnection.CreationTimeout = commons.ConnectionErrorTimeout
	fsConfig.MetadataConnection.TCPBufferSize = commons.TCPBufferSizeDefault
	fsConfig.MetadataConnection.OperationTimeout = time.Duration(config.OperationTimeout)
	fsConfig.MetadataConnection.IdleTimeout = time.Duration(config.ConnectionIdleTimeout)
	fsConfig.MetadataConnection.Lifespan = time.Duration(config.ConnectionLifespan)
	fsConfig.MetadataConnection.CreationTimeout = commons.ConnectionErrorTimeout

	fsConfig.Cache.Timeout = time.Duration(config.MetadataCacheTimeout)
	fsConfig.Cache.CleanupTime = time.Duration(config.MetadataCacheCleanupTime)
	fsConfig.Cache.MetadataTimeoutSettings = cacheTimeoutSettings
	fsConfig.Cache.StartNewTransaction = config.StartNewTransaction
	fsConfig.Cache.InvalidateParentEntryCacheImmediately = config.InvalidateParentEntryCacheImmediately

	logger.Info("Initializing an iRODS file system client")
	var fsClient irodsfs_common_irods.IRODSFSClient = nil
	if len(config.PoolEndpoint) > 0 {
		// use pool driver
		logger.Info("Initializing irodsfs-pool fs client")
		poolClient := irodspoolclient.NewPoolServiceClient(config.PoolEndpoint, time.Duration(config.OperationTimeout), config.InstanceID)
		err = poolClient.Connect()
		if err != nil {
			clientErr := xerrors.Errorf("failed to connect to irodsfs-pool server %q: %w", config.PoolEndpoint, err)
			logger.Errorf("%+v", clientErr)
			return nil, clientErr
		}

		fsClient, err = poolClient.NewSession(account, FSName)
		if err != nil {
			sessionErr := xerrors.Errorf("failed to create a new irodsfs-pool fs client: %w", err)
			logger.Errorf("%+v", sessionErr)
			return nil, sessionErr
		}
	} else {
		// use go-irodsclient driver
		logger.Info("Initializing an iRODS native file system client")
		fsClient, err = irodsfs_common_irods.NewIRODSFSClientDirect(account, fsConfig)
		if err != nil {
			clientErr := xerrors.Errorf("failed to create a new go-irodsclient fs client: %w", err)
			logger.Errorf("%+v", clientErr)
			return nil, clientErr
		}
	}

	inodeManager := irodsfs_common_inode.NewInodeManager()

	logger.Info("Initializing virtual path mappings")
	// fix readonly
	if config.Readonly {
		for idx := range config.PathMappings {
			config.PathMappings[idx].ReadOnly = true
		}
	}

	vpathManager, err := irodsfs_common_vpath.NewVPathManager(fsClient, inodeManager, config.PathMappings)
	if err != nil {
		vpathErr := xerrors.Errorf("failed to create Virtual Path Manager: %w", err)
		logger.Errorf("%+v", vpathErr)
		return nil, vpathErr
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
			AuthScheme:               string(authScheme),
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
			logger.Errorf("%+v", err)
			// keep going.
		}
	}

	userGroups, err := fsClient.ListUserGroups(account.ClientUser)
	if err != nil {
		ugErr := xerrors.Errorf("failed to list groups for a user %q: %w", account.ClientUser, err)
		logger.Errorf("%+v", ugErr)
		return nil, ugErr
	}

	userGroupsMap := map[string]*irodsclient_types.IRODSUser{}
	for _, userGroup := range userGroups {
		userGroupsMap[userGroup.Name] = userGroup
	}

	return &IRODSFS{
		config:        config,
		fuseServer:    nil,
		inodeManager:  inodeManager,
		vpathManager:  vpathManager,
		fsClient:      fsClient,
		fileHandleMap: fileHandleMap,
		userGroupsMap: userGroupsMap,

		uid: uint32(config.UID),
		gid: uint32(config.GID),

		reportClient:         reportClient,
		instanceReportClient: instanceReportClient,

		operationIDCurrent: 0,
	}, nil
}

// Release destroys the file system
func (fs *IRODSFS) Release() {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "IRODSFS",
		"function": "Release",
	})

	logger.Info("Releasing the iRODS FUSE Lite")

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

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

	if fs.fsClient != nil {
		fs.fsClient.Release()
		fs.fsClient = nil
	}
}

// Start starts FUSE
func (fs *IRODSFS) Start() error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "IRODSFS",
		"function": "Start",
	})

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	// mount
	logger.Infof("Starting iRODS FUSE Lite, connecting to FUSE on %q", fs.config.MountPath)

	rootDir, err := fs.Root()
	if err != nil {
		logger.Errorf("%+v", err)
		return err
	}

	fuseServer, err := fusefs.Mount(fs.config.MountPath, rootDir, GetFuseOptions(fs.config))
	if err != nil {
		logger.Errorf("%+v", err)
		return err
	}

	fs.fuseServer = fuseServer

	logger.Infof("Connected to FUSE, mount on %q", fs.config.MountPath)

	return nil
}

func (fs *IRODSFS) Stop() {
	if fs.terminated {
		return
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "IRODSFS",
		"function": "Stop",
	})

	logger.Info("Stopping FUSE")

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	fs.terminated = true

	//fs.fuseServer.Unmount()
	err := utils.UnmountFuse(fs.config.MountPath)
	if err != nil {
		logger.Error(err)
	}
	fs.fuseServer = nil
}

func (fs *IRODSFS) Wait() {
	fs.fuseServer.Wait()
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

	if vpathEntry.IsVirtualDirEntry() {
		inodeID := fs.inodeManager.GetInodeIDForVPathEntryID(vpathEntry.VirtualDirEntry.ID)
		return NewDir(fs, inodeID, "/"), nil
	}

	return NewIRODSRoot(fs, vpathEntry)
}

// GetNextOperationID returns next operation ID
func (fs *IRODSFS) GetNextOperationID() uint64 {
	fs.operationIDCurrent++
	return fs.operationIDCurrent
}
