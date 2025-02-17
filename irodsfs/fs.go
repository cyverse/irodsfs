package irodsfs

import (
	"syscall"
	"time"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	irodsfs_common_inode "github.com/cyverse/irodsfs-common/inode"
	irodsfs_common_irods "github.com/cyverse/irodsfs-common/irods"
	irodsfs_common_utils "github.com/cyverse/irodsfs-common/utils"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	irodspoolclient "github.com/cyverse/irodsfs-pool/client"
	"golang.org/x/xerrors"

	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"

	"github.com/cyverse/irodsfs/commons"
	"github.com/cyverse/irodsfs/utils"
	log "github.com/sirupsen/logrus"
)

// GetFuseOptions returns fuse options
func GetFuseOptions(config *commons.Config) *fusefs.Options {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"function": "GetFuseOptions",
	})

	options := &fusefs.Options{}

	// TODO: handle fuse specific options in config.FuseOptions
	options.AllowOther = config.AllowOther
	if config.Debug && config.Foreground {
		options.Debug = true
		logger.Debugf("Debug and foreground mode enabled")
	}

	options.AttrTimeout = nil
	options.EntryTimeout = nil
	options.NegativeTimeout = nil
	options.UID = uint32(config.UID)
	logger.Infof("UID %d is set", config.UID)
	options.GID = uint32(config.GID)
	logger.Infof("GID %d is set", config.GID)
	options.MaxReadAhead = config.ReadAheadMax
	options.MaxWrite = config.ReadWriteMax
	options.FsName = commons.FuseFSName
	options.Name = commons.FuseFSName
	options.SingleThreaded = false
	options.IgnoreSecurityLabels = true
	options.EnableLocks = true
	options.DisableReadDirPlus = true
	options.ExplicitDataCacheControl = true // experimental
	options.DirectMount = true              // experimental
	return options
}

// IRODSFS is a file system object
type IRODSFS struct {
	config *commons.Config

	fuseServer    *fuse.Server
	inodeManager  *irodsfs_common_inode.InodeManager
	vpathManager  *irodsfs_common_vpath.VPathManager
	fsClient      irodsfs_common_irods.IRODSFSClient
	usePoolServer bool
	fileHandleMap *FileHandleMap
	userGroupsMap map[string]*irodsclient_types.IRODSUser

	uid uint32
	gid uint32

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

	account := config.ToIRODSAccount()

	logger.Infof("Connect to IRODS server using %q auth scheme", string(account.AuthenticationScheme))

	logger.Info("Initializing an iRODS file system client")
	var fsClient irodsfs_common_irods.IRODSFSClient
	var err error

	usePoolServer := false
	if len(config.PoolEndpoint) > 0 {
		// use pool driver
		logger.Info("Initializing irodsfs-pool fs client")
		poolClient := irodspoolclient.NewPoolServiceClient(config.PoolEndpoint, time.Duration(config.MetadataConnection.OperationTimeout), config.InstanceID)
		err = poolClient.Connect()
		if err != nil {
			clientErr := xerrors.Errorf("failed to connect to irodsfs-pool server %q: %w", config.PoolEndpoint, err)
			logger.Errorf("%+v", clientErr)
			return nil, clientErr
		}

		fsClient, err = poolClient.NewSession(account, commons.FuseFSName)
		if err != nil {
			sessionErr := xerrors.Errorf("failed to create a new irodsfs-pool fs client: %w", err)
			logger.Errorf("%+v", sessionErr)
			return nil, sessionErr
		}

		usePoolServer = true
	} else {
		// use go-irodsclient driver
		logger.Info("Initializing an iRODS native file system client")
		fsConfig := irodsclient_fs.NewFileSystemConfig(commons.FuseFSName)
		fsConfig.MetadataConnection = config.MetadataConnection
		fsConfig.IOConnection = config.IOConnection
		fsConfig.Cache = config.Cache

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

	userGroups, err := fsClient.ListUserGroups(account.ClientZone, account.ClientUser)
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
		usePoolServer: usePoolServer,
		fileHandleMap: fileHandleMap,
		userGroupsMap: userGroupsMap,

		uid: uint32(config.UID),
		gid: uint32(config.GID),

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

func (fs *IRODSFS) Stop(silentUnmount bool) {
	if fs.terminated {
		return
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "IRODSFS",
		"function": "Stop",
	})

	logger.Infof("Stopping FUSE (silentUnmount=%t)", silentUnmount)

	defer irodsfs_common_utils.StackTraceFromPanic(logger)

	fs.terminated = true

	//fs.fuseServer.Unmount()
	err := utils.UnmountFuse(fs.config.MountPath)
	if err != nil {
		if silentUnmount {
			logger.Info(err)
		} else {
			logger.Error(err)
		}
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
