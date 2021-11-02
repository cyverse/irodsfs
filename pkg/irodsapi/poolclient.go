package irodsapi

import (
	"fmt"
	"runtime/debug"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	irodsfs_pool_client "github.com/cyverse/irodsfs-pool/client"
	log "github.com/sirupsen/logrus"
)

// pool access
// implements interfaces defined in interface.go

func convPoolClientError(err error) error {
	if err == nil {
		return nil
	}

	if irodsclient_types.IsFileNotFoundError(err) {
		return NewFileNotFoundError(err.Error())
	}
	return err
}

// PoolClient implements IRODSClient interface with iRODS FUSE Lite Pool
type PoolClient struct {
	Config             *irodsclient_fs.FileSystemConfig
	PoolHost           string
	Account            *irodsclient_types.IRODSAccount
	PoolServiceClient  *irodsfs_pool_client.PoolServiceClient
	PoolServiceSession *irodsfs_pool_client.PoolServiceSession
}

func NewPoolClientDriver(poolHost string, poolPort int, account *irodsclient_types.IRODSAccount, config *irodsclient_fs.FileSystemConfig, clientID string) (IRODSClient, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"function": "NewPoolClientDriver",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	poolHostPort := fmt.Sprintf("%s:%d", poolHost, poolPort)
	poolServiceClient := irodsfs_pool_client.NewPoolServiceClient(poolHostPort, config.OperationTimeout)

	logger.Infof("Connect to pool service - %s", poolHostPort)
	err := poolServiceClient.Connect()
	if err != nil {
		return nil, err
	}

	logger.Infof("Login to pool service - user %s", account.ClientUser)
	poolServiceSession, err := poolServiceClient.Login(account, config.ApplicationName, clientID)
	if err != nil {
		return nil, err
	}

	logger.Info("Logged in to pool service")
	return &PoolClient{
		Config:             config,
		PoolHost:           poolHostPort,
		Account:            account,
		PoolServiceClient:  poolServiceClient,
		PoolServiceSession: poolServiceSession,
	}, nil
}

func (client *PoolClient) GetAccount() *irodsclient_types.IRODSAccount {
	return client.Account
}

func (client *PoolClient) GetApplicationName() string {
	return client.Config.ApplicationName
}

func (client *PoolClient) Release() {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "Release",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	client.PoolServiceClient.Logout(client.PoolServiceSession)
	client.PoolServiceClient.Disconnect()
}

func (client *PoolClient) List(path string) ([]*IRODSEntry, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "List",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	entries, err := client.PoolServiceClient.List(client.PoolServiceSession, path)
	if err != nil {
		return nil, convPoolClientError(err)
	}

	resultEntries := []*IRODSEntry{}
	for _, entry := range entries {
		resultEntry := &IRODSEntry{
			ID:         entry.ID,
			Type:       EntryType(entry.Type),
			Name:       entry.Name,
			Path:       entry.Path,
			Owner:      entry.Owner,
			Size:       entry.Size,
			CreateTime: entry.CreateTime,
			ModifyTime: entry.ModifyTime,
			CheckSum:   entry.CheckSum,
		}
		resultEntries = append(resultEntries, resultEntry)
	}

	return resultEntries, nil
}

func (client *PoolClient) Stat(path string) (*IRODSEntry, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "Stat",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	entry, err := client.PoolServiceClient.Stat(client.PoolServiceSession, path)
	if err != nil {
		return nil, convPoolClientError(err)
	}

	return &IRODSEntry{
		ID:         entry.ID,
		Type:       EntryType(entry.Type),
		Name:       entry.Name,
		Path:       entry.Path,
		Owner:      entry.Owner,
		Size:       entry.Size,
		CreateTime: entry.CreateTime,
		ModifyTime: entry.ModifyTime,
		CheckSum:   entry.CheckSum,
	}, nil
}

func (client *PoolClient) ExistsDir(path string) bool {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "ExistsDir",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	return client.PoolServiceClient.ExistsDir(client.PoolServiceSession, path)
}

func (client *PoolClient) ListUserGroups(user string) ([]*IRODSUser, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "ListUserGroups",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	groups, err := client.PoolServiceClient.ListUserGroups(client.PoolServiceSession, user)
	if err != nil {
		return nil, convPoolClientError(err)
	}

	resultGroups := []*IRODSUser{}
	for _, group := range groups {
		resultGroup := &IRODSUser{
			Name: group.Name,
			Zone: group.Zone,
			Type: IRODSUserType(group.Type),
		}
		resultGroups = append(resultGroups, resultGroup)
	}

	return resultGroups, nil
}

func (client *PoolClient) ListDirACLs(path string) ([]*IRODSAccess, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "ListDirACLs",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	accesses, err := client.PoolServiceClient.ListDirACLs(client.PoolServiceSession, path)
	if err != nil {
		return nil, convPoolClientError(err)
	}

	resultAccesses := []*IRODSAccess{}

	for _, access := range accesses {
		resultAccess := &IRODSAccess{
			UserName:    access.UserName,
			UserType:    IRODSUserType(access.UserType),
			AccessLevel: IRODSAccessLevelType(access.AccessLevel),
		}
		resultAccesses = append(resultAccesses, resultAccess)
	}

	return resultAccesses, nil
}

func (client *PoolClient) ListFileACLs(path string) ([]*IRODSAccess, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "ListFileACLs",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	accesses, err := client.PoolServiceClient.ListFileACLs(client.PoolServiceSession, path)
	if err != nil {
		return nil, convPoolClientError(err)
	}

	resultAccesses := []*IRODSAccess{}
	for _, access := range accesses {
		resultAccess := &IRODSAccess{
			UserName:    access.UserName,
			UserType:    IRODSUserType(access.UserType),
			AccessLevel: IRODSAccessLevelType(access.AccessLevel),
		}
		resultAccesses = append(resultAccesses, resultAccess)
	}

	return resultAccesses, nil
}

func (client *PoolClient) RemoveFile(path string, force bool) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "RemoveFile",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	err := client.PoolServiceClient.RemoveFile(client.PoolServiceSession, path, force)
	return convPoolClientError(err)
}

func (client *PoolClient) RemoveDir(path string, recurse bool, force bool) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "RemoveDir",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	err := client.PoolServiceClient.RemoveDir(client.PoolServiceSession, path, recurse, force)
	return convPoolClientError(err)
}

func (client *PoolClient) MakeDir(path string, recurse bool) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "MakeDir",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	err := client.PoolServiceClient.MakeDir(client.PoolServiceSession, path, recurse)
	return convPoolClientError(err)
}

func (client *PoolClient) RenameDirToDir(srcPath string, destPath string) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "RenameDirToDir",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	err := client.PoolServiceClient.RenameDirToDir(client.PoolServiceSession, srcPath, destPath)
	return convPoolClientError(err)
}

func (client *PoolClient) RenameFileToFile(srcPath string, destPath string) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "RenameFileToFile",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	err := client.PoolServiceClient.RenameFileToFile(client.PoolServiceSession, srcPath, destPath)
	return convPoolClientError(err)
}

func (client *PoolClient) CreateFile(path string, resource string) (IRODSFileHandle, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "CreateFile",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	handle, err := client.PoolServiceClient.CreateFile(client.PoolServiceSession, path, resource)
	if err != nil {
		return nil, convPoolClientError(err)
	}

	fileHandle := &PoolClientFileHandle{
		ID:         handle.FileHandleID,
		PoolClient: client,
		Handle:     handle,
	}

	return fileHandle, nil
}

func (client *PoolClient) OpenFile(path string, resource string, mode string) (IRODSFileHandle, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "OpenFile",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	handle, err := client.PoolServiceClient.OpenFile(client.PoolServiceSession, path, resource, mode)
	if err != nil {
		return nil, convPoolClientError(err)
	}

	fileHandle := &PoolClientFileHandle{
		ID:         handle.FileHandleID,
		PoolClient: client,
		Handle:     handle,
	}

	return fileHandle, nil
}

func (client *PoolClient) TruncateFile(path string, size int64) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClient",
		"function": "TruncateFile",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	err := client.PoolServiceClient.TruncateFile(client.PoolServiceSession, path, size)
	return convPoolClientError(err)
}

// PoolClientFileHandle implements IRODSFileHandle
type PoolClientFileHandle struct {
	ID         string
	PoolClient *PoolClient
	Handle     *irodsfs_pool_client.PoolServiceFileHandle
}

func (handle *PoolClientFileHandle) GetID() string {
	return handle.ID
}

func (handle *PoolClientFileHandle) GetEntry() *IRODSEntry {
	return &IRODSEntry{
		ID:         handle.Handle.Entry.ID,
		Type:       EntryType(handle.Handle.Entry.Type),
		Name:       handle.Handle.Entry.Name,
		Path:       handle.Handle.Entry.Path,
		Owner:      handle.Handle.Entry.Owner,
		Size:       handle.Handle.Entry.Size,
		CreateTime: handle.Handle.Entry.CreateTime,
		ModifyTime: handle.Handle.Entry.ModifyTime,
		CheckSum:   handle.Handle.Entry.CheckSum,
	}
}

func (handle *PoolClientFileHandle) GetOpenMode() FileOpenMode {
	return FileOpenMode(handle.Handle.OpenMode)
}

func (handle *PoolClientFileHandle) GetOffset() int64 {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClientFileHandle",
		"function": "GetOffset",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	return handle.PoolClient.PoolServiceClient.GetOffset(handle.Handle)
}

func (handle *PoolClientFileHandle) IsReadMode() bool {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClientFileHandle",
		"function": "IsReadMode",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	return handle.Handle.IsReadMode()
}

func (handle *PoolClientFileHandle) IsWriteMode() bool {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClientFileHandle",
		"function": "IsWriteMode",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	return handle.Handle.IsWriteMode()
}

func (handle *PoolClientFileHandle) ReadAt(offset int64, length int) ([]byte, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClientFileHandle",
		"function": "ReadAt",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	return handle.PoolClient.PoolServiceClient.ReadAt(handle.Handle, offset, int32(length))
}

func (handle *PoolClientFileHandle) WriteAt(offset int64, data []byte) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClientFileHandle",
		"function": "WriteAt",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	return handle.PoolClient.PoolServiceClient.WriteAt(handle.Handle, offset, data)
}

func (handle *PoolClientFileHandle) Flush() error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClientFileHandle",
		"function": "Flush",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	return handle.PoolClient.PoolServiceClient.Flush(handle.Handle)
}

func (handle *PoolClientFileHandle) Close() error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "PoolClientFileHandle",
		"function": "Close",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	return handle.PoolClient.PoolServiceClient.Close(handle.Handle)
}
