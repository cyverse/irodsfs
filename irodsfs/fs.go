package irodsfs

import (
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cockroachdb/errors"
	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsfs_common_inode "github.com/cyverse/irodsfs-common/inode"
	irodsfs_common_irods "github.com/cyverse/irodsfs-common/irods"
	irodsfs_common_util "github.com/cyverse/irodsfs-common/util"
	irodsfs_common_vpath "github.com/cyverse/irodsfs-common/vpath"
	irodsfs_pool_client "github.com/cyverse/irodsfs-pool/client"

	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"

	"github.com/cyverse/irodsfs/commons"
	log "github.com/sirupsen/logrus"
)

// IRODSFS is a file system object
type IRODSFS struct {
	config *commons.Config

	fuseServer    *fuse.Server
	inodeManager  *irodsfs_common_inode.InodeManager
	vpathManager  *irodsfs_common_vpath.VPathManager
	fsClient      irodsfs_common_irods.IRODSFSClient
	usePoolServer bool
	fileHandleMap *FileHandleMap

	uid uint32
	gid uint32

	currentOperationCounter atomic.Uint64
	logger                  *log.Entry
	startTime               time.Time
	terminated              atomic.Bool
}

// NewFileSystem creates a new file system
func NewFileSystem(config *commons.Config) (*IRODSFS, error) {
	logger := log.WithFields(log.Fields{})

	defer irodsfs_common_util.StackTraceFromPanic(logger)

	account := config.ToIRODSAccount()
	logger.Infof("Connect to IRODS server using %v", account.GetRedacted())

	logger.Info("Initializing an iRODS file system client")
	var fsClient irodsfs_common_irods.IRODSFSClient
	var err error

	if len(config.Description) > 0 {
		logger.Infof("%s: %s", commons.FuseFSName, config.Description)
	}

	usePoolServer := false
	if len(config.PoolEndpoint) > 0 {
		// use pool driver
		logger.Info("Initializing irodsfs-pool client")
		poolClient := irodsfs_pool_client.NewPoolServiceClient(config.PoolEndpoint, time.Duration(config.MetadataConnection.LongOperationTimeout), logger)
		err = poolClient.Connect()
		if err != nil {
			clientErr := errors.Wrapf(err, "failed to connect to irodsfs-pool server %q", config.PoolEndpoint)
			logger.Error(clientErr)
			return nil, clientErr
		}

		fsClient, err = poolClient.NewSession(account, commons.FuseFSName, config.Description)
		if err != nil {
			sessionErr := errors.Wrapf(err, "failed to create a irodsfs-pool fs client")
			logger.Error(sessionErr)
			return nil, sessionErr
		}

		usePoolServer = true
	} else {
		// use go-irodsclient driver
		logger.Info("Initializing go-irodsclient fs client")
		fsConfig := irodsclient_fs.NewFileSystemConfig(commons.FuseFSName)
		fsConfig.MetadataConnection = config.MetadataConnection
		fsConfig.IOConnection = config.IOConnection
		fsConfig.Cache = config.Cache

		irodsfsClient, err := irodsclient_fs.NewFileSystem(account, fsConfig)
		if err != nil {
			clientErr := errors.Wrapf(err, "failed to create a go-irodsclient fs client")
			logger.Error(clientErr)
			return nil, clientErr
		}

		fsClient, err = irodsfs_common_irods.NewIRODSFSClientDirect(irodsfsClient)
		if err != nil {
			clientErr := errors.Wrapf(err, "failed to wrap go-irodsclient as irods fs client")
			logger.Error(clientErr)
			return nil, clientErr
		}
	}

	inodeManager := irodsfs_common_inode.NewInodeManager()

	logger.Info("Initializing virtual path mappings")
	vpathManager, err := irodsfs_common_vpath.NewVPathManager(fsClient, inodeManager, config.PathMappings)
	if err != nil {
		vpathErr := errors.Wrapf(err, "failed to create Virtual Path Manager")
		logger.Error(vpathErr)
		return nil, vpathErr
	}

	logger.Info("Initializing File Handle Map")
	fileHandleMap := NewFileHandleMap()

	fs := &IRODSFS{
		config: config,

		inodeManager:  inodeManager,
		vpathManager:  vpathManager,
		fsClient:      fsClient,
		usePoolServer: usePoolServer,
		fileHandleMap: fileHandleMap,

		uid: uint32(config.UID),
		gid: uint32(config.GID),

		startTime: time.Now(),
		logger:    logger,
	}

	return fs, nil
}

// Release releases the file system
func (fs *IRODSFS) Release() {
	defer irodsfs_common_util.StackTraceFromPanic(fs.logger)

	fs.logger.Info("Releasing the iRODS FUSE")
	defer fs.logger.Info("Released the iRODS FUSE")

	if fs.fileHandleMap != nil {
		fs.fileHandleMap.Clear()
		fs.fileHandleMap = nil
	}

	if fs.fsClient != nil {
		fs.fsClient.Release()
		fs.fsClient = nil
	}
}

// Mount mounts FUSE
func (fs *IRODSFS) Mount() error {
	defer irodsfs_common_util.StackTraceFromPanic(fs.logger)

	// mount
	fs.logger.Infof("Mounting iRODS FUSE on %q", fs.config.MountPath)

	rootDir, err := fs.GetRoot()
	if err != nil {
		fs.logger.Error(err)
		return err
	}

	fuseServer, err := fusefs.Mount(fs.config.MountPath, rootDir, fs.GetFuseOptions())
	if err != nil {
		fs.logger.Error(err)
		return err
	}

	fs.fuseServer = fuseServer

	fs.logger.Infof("Connected to FUSE, mount on %q", fs.config.MountPath)

	return nil
}

func (fs *IRODSFS) Unmount() {
	if fs.terminated.Load() {
		return
	}

	defer irodsfs_common_util.StackTraceFromPanic(fs.logger)

	fs.logger.Info("Stopping FUSE")

	fs.terminated.Store(true)

	if fs.fuseServer == nil {
		return
	}

	err := fs.fuseServer.Unmount()
	if err != nil {
		// may return error
		fs.logger.Info(err)
		fs.logger.Info("Scheduled stopping FUSE")
	} else {
		fs.logger.Info("Stopped FUSE")
	}
}

// GetRoot returns root directory node
func (fs *IRODSFS) GetRoot() (*Dir, error) {
	if fs.terminated.Load() {
		return nil, syscall.ECONNABORTED
	}

	defer irodsfs_common_util.StackTraceFromPanic(fs.logger)

	vpathEntry := fs.vpathManager.GetEntry("/")
	if vpathEntry == nil {
		fs.logger.Error("failed to get root VPath Entry")
		return nil, syscall.EREMOTEIO
	}

	if vpathEntry.IsVirtualDirEntry() {
		inodeID, inodeErr := fs.inodeManager.GetInodeIDForVirtualEntry("/")
		if inodeErr != nil {
			fs.logger.WithError(inodeErr).Error("failed to get inode ID for root")
			return nil, syscall.EREMOTEIO
		}
		return NewDir(fs, inodeID, "/"), nil
	}

	// irods
	err := ensureVPathEntryIsIRODSDir(fs.fsClient, vpathEntry)
	if err != nil {
		fs.logger.WithError(err).Error("failed to ensure VPathEntry for root is irods dir")
		return nil, syscall.EREMOTEIO
	}

	inodeID, inodeErr := fs.inodeManager.GetInodeIDForIRODSEntryID(uint64(vpathEntry.IRODSEntry.ID))
	if inodeErr != nil {
		fs.logger.WithError(inodeErr).Errorf("failed to get inode ID for %s", vpathEntry.IRODSPath)
		return nil, syscall.EREMOTEIO
	}

	return NewDir(fs, inodeID, "/"), nil
}

// GetNextOperationID returns next operation ID
func (fs *IRODSFS) GetNextOperationID() uint64 {
	return fs.currentOperationCounter.Add(1)
}

// GetFuseOptions returns fuse options
func (fs *IRODSFS) GetFuseOptions() *fusefs.Options {
	options := &fusefs.Options{}

	if fs.config.Debug && fs.config.Foreground {
		options.Debug = true
		fs.logger.Debugf("Debug and foreground mode enabled")
	}

	options.AttrTimeout = nil
	options.EntryTimeout = nil
	options.NegativeTimeout = nil

	options.UID = uint32(fs.config.UID)
	fs.logger.Infof("UID %d is set", fs.config.UID)
	options.GID = uint32(fs.config.GID)
	fs.logger.Infof("GID %d is set", fs.config.GID)

	options.MaxReadAhead = fs.config.ReadAheadMax
	options.MaxWrite = fs.config.ReadWriteMax
	options.FsName = commons.FuseFSName
	options.Name = commons.FuseFSName
	options.SingleThreaded = false
	options.IgnoreSecurityLabels = true
	options.EnableLocks = true
	options.DisableReadDirPlus = true
	options.ExplicitDataCacheControl = true // experimental
	//options.DirectMount = true              // experimental

	if fs.config.Readonly {
		options.MountOptions.Options = append(options.MountOptions.Options, "ro")
	}
	return options
}
