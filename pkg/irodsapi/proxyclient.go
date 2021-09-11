package irodsapi

import (
	"fmt"

	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	irodsfs_clienttype "github.com/cyverse/go-irodsclient/irods/types"
	"github.com/cyverse/go-irodsclient/irods/util"
	irodsfs_proxy_client "github.com/cyverse/irodsfs-proxy/client"
	"github.com/silenceper/pool"
)

// proxy access
// implements interfaces defined in interface.go

func convProxyClientError(err error) error {
	if err == nil {
		return nil
	}

	if irodsfs_clienttype.IsFileNotFoundError(err) {
		return NewFileNotFoundError(err.Error())
	}
	return err
}

// ProxyClient implements IRODSClient interface with iRODS FUSE Lite Proxy
type ProxyClient struct {
	Config         *irodsfs_client.FileSystemConfig
	ProxyHost      string
	Account        *irodsfs_clienttype.IRODSAccount
	ConnectionPool pool.Pool
}

type ProxySession struct {
	ProxyServiceClient  *irodsfs_proxy_client.ProxyServiceClient
	ProxyServiceSession *irodsfs_proxy_client.ProxyServiceSession
}

func NewProxyClientDriver(proxyHost string, proxyPort int, account *irodsfs_clienttype.IRODSAccount, config *irodsfs_client.FileSystemConfig) (IRODSClient, error) {
	proxyClient := &ProxyClient{
		Config:    config,
		ProxyHost: fmt.Sprintf("%s:%d", proxyHost, proxyPort),
		Account:   account,
	}

	poolConfig := pool.Config{
		InitialCap:  1,
		MaxIdle:     1,
		MaxCap:      config.ConnectionMax,
		Factory:     proxyClient.connOpen,
		Close:       proxyClient.connClose,
		IdleTimeout: config.ConnectionIdleTimeout,
	}

	p, err := pool.NewChannelPool(&poolConfig)
	if err != nil {
		util.LogErrorf("cannot create a new connection pool - %v", err)
		return nil, err
	}

	proxyClient.ConnectionPool = p

	return proxyClient, nil
}

func (client *ProxyClient) connOpen() (interface{}, error) {
	// create a conenction
	proxy := irodsfs_proxy_client.NewProxyServiceClient(client.ProxyHost)
	err := proxy.Connect()
	if err != nil {
		return nil, err
	}

	proxySession, err := proxy.Login(client.Account, client.Config.ApplicationName)
	if err != nil {
		return nil, err
	}

	return &ProxySession{
		ProxyServiceClient:  proxy,
		ProxyServiceSession: proxySession,
	}, nil
}

func (client *ProxyClient) connClose(v interface{}) error {
	// close a conenction
	proxySession := v.(*ProxySession)
	err := proxySession.ProxyServiceClient.Logout(proxySession.ProxyServiceSession)
	proxySession.ProxyServiceClient.Disconnect()
	return err
}

func (client *ProxyClient) GetAccount() *irodsfs_clienttype.IRODSAccount {
	return client.Account
}

func (client *ProxyClient) GetApplicationName() string {
	return client.Config.ApplicationName
}

func (client *ProxyClient) Release() {
	client.ConnectionPool.Release()
}

func (client *ProxyClient) List(path string) ([]*IRODSEntry, error) {
	v, err := client.ConnectionPool.Get()
	if err != nil {
		return nil, err
	}

	defer client.ConnectionPool.Put(v)

	conn := v.(*ProxySession)
	entries, err := conn.ProxyServiceClient.List(conn.ProxyServiceSession, path)
	if err != nil {
		return nil, convProxyClientError(err)
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

func (client *ProxyClient) Stat(path string) (*IRODSEntry, error) {
	v, err := client.ConnectionPool.Get()
	if err != nil {
		return nil, err
	}

	defer client.ConnectionPool.Put(v)

	conn := v.(*ProxySession)
	entry, err := conn.ProxyServiceClient.Stat(conn.ProxyServiceSession, path)
	if err != nil {
		return nil, convProxyClientError(err)
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

func (client *ProxyClient) ExistsDir(path string) bool {
	v, err := client.ConnectionPool.Get()
	if err != nil {
		return false
	}

	defer client.ConnectionPool.Put(v)

	conn := v.(*ProxySession)
	return conn.ProxyServiceClient.ExistsDir(conn.ProxyServiceSession, path)
}

func (client *ProxyClient) ListDirACLsWithGroupUsers(path string) ([]*IRODSAccess, error) {
	v, err := client.ConnectionPool.Get()
	if err != nil {
		return nil, err
	}

	defer client.ConnectionPool.Put(v)

	conn := v.(*ProxySession)

	accesses, err := conn.ProxyServiceClient.ListDirACLsWithGroupUsers(conn.ProxyServiceSession, path)
	if err != nil {
		return nil, convProxyClientError(err)
	}

	resultAccesses := []*IRODSAccess{}

	for _, access := range accesses {
		resultAccess := &IRODSAccess{
			UserName:    access.UserName,
			AccessLevel: IRODSAccessLevelType(access.AccessLevel),
		}
		resultAccesses = append(resultAccesses, resultAccess)
	}

	return resultAccesses, nil
}

func (client *ProxyClient) ListFileACLsWithGroupUsers(path string) ([]*IRODSAccess, error) {
	v, err := client.ConnectionPool.Get()
	if err != nil {
		return nil, err
	}

	defer client.ConnectionPool.Put(v)

	conn := v.(*ProxySession)

	accesses, err := conn.ProxyServiceClient.ListFileACLsWithGroupUsers(conn.ProxyServiceSession, path)
	if err != nil {
		return nil, convProxyClientError(err)
	}

	resultAccesses := []*IRODSAccess{}
	for _, access := range accesses {
		resultAccess := &IRODSAccess{
			UserName:    access.UserName,
			AccessLevel: IRODSAccessLevelType(access.AccessLevel),
		}
		resultAccesses = append(resultAccesses, resultAccess)
	}

	return resultAccesses, nil
}

func (client *ProxyClient) RemoveFile(path string, force bool) error {
	v, err := client.ConnectionPool.Get()
	if err != nil {
		return err
	}

	defer client.ConnectionPool.Put(v)

	conn := v.(*ProxySession)

	err = conn.ProxyServiceClient.RemoveFile(conn.ProxyServiceSession, path, force)
	return convProxyClientError(err)
}

func (client *ProxyClient) RemoveDir(path string, recurse bool, force bool) error {
	v, err := client.ConnectionPool.Get()
	if err != nil {
		return err
	}

	defer client.ConnectionPool.Put(v)

	conn := v.(*ProxySession)

	err = conn.ProxyServiceClient.RemoveDir(conn.ProxyServiceSession, path, recurse, force)
	return convProxyClientError(err)
}

func (client *ProxyClient) MakeDir(path string, recurse bool) error {
	v, err := client.ConnectionPool.Get()
	if err != nil {
		return err
	}

	defer client.ConnectionPool.Put(v)

	conn := v.(*ProxySession)

	err = conn.ProxyServiceClient.MakeDir(conn.ProxyServiceSession, path, recurse)
	return convProxyClientError(err)
}

func (client *ProxyClient) RenameDirToDir(srcPath string, destPath string) error {
	v, err := client.ConnectionPool.Get()
	if err != nil {
		return err
	}

	defer client.ConnectionPool.Put(v)

	conn := v.(*ProxySession)

	err = conn.ProxyServiceClient.RenameDirToDir(conn.ProxyServiceSession, srcPath, destPath)
	return convProxyClientError(err)
}

func (client *ProxyClient) RenameFileToFile(srcPath string, destPath string) error {
	v, err := client.ConnectionPool.Get()
	if err != nil {
		return err
	}

	defer client.ConnectionPool.Put(v)

	conn := v.(*ProxySession)

	err = conn.ProxyServiceClient.RenameFileToFile(conn.ProxyServiceSession, srcPath, destPath)
	return convProxyClientError(err)
}

func (client *ProxyClient) CreateFile(path string, resource string) (IRODSFileHandle, error) {
	v, err := client.ConnectionPool.Get()
	if err != nil {
		return nil, err
	}

	conn := v.(*ProxySession)

	handle, err := conn.ProxyServiceClient.CreateFile(conn.ProxyServiceSession, path, resource)
	if err != nil {
		return nil, convProxyClientError(err)
	}

	fileHandle := &ProxyClientFileHandle{
		ID:           handle.FileHandleID,
		Client:       client,
		ProxySession: conn,
		Handle:       handle,
	}

	return fileHandle, nil
}

func (client *ProxyClient) OpenFile(path string, resource string, mode string) (IRODSFileHandle, error) {
	v, err := client.ConnectionPool.Get()
	if err != nil {
		return nil, err
	}

	conn := v.(*ProxySession)

	handle, err := conn.ProxyServiceClient.OpenFile(conn.ProxyServiceSession, path, resource, mode)
	if err != nil {
		return nil, convProxyClientError(err)
	}

	fileHandle := &ProxyClientFileHandle{
		ID:           handle.FileHandleID,
		Client:       client,
		ProxySession: conn,
		Handle:       handle,
	}

	return fileHandle, nil
}

func (client *ProxyClient) TruncateFile(path string, size int64) error {
	v, err := client.ConnectionPool.Get()
	if err != nil {
		return err
	}

	defer client.ConnectionPool.Put(v)

	conn := v.(*ProxySession)

	err = conn.ProxyServiceClient.TruncateFile(conn.ProxyServiceSession, path, size)
	return convProxyClientError(err)
}

// ProxyClientFileHandle implements IRODSFileHandle
type ProxyClientFileHandle struct {
	ID           string
	Client       *ProxyClient
	ProxySession *ProxySession
	Handle       *irodsfs_proxy_client.ProxyServiceFileHandle
}

func (handle *ProxyClientFileHandle) GetID() string {
	return handle.ID
}

func (handle *ProxyClientFileHandle) GetEntry() *IRODSEntry {
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

func (handle *ProxyClientFileHandle) GetOpenMode() FileOpenMode {
	return FileOpenMode(handle.Handle.OpenMode)
}

func (handle *ProxyClientFileHandle) GetOffset() int64 {
	return handle.ProxySession.ProxyServiceClient.GetOffset(handle.Handle)
}

func (handle *ProxyClientFileHandle) IsReadMode() bool {
	return handle.Handle.IsReadMode()
}

func (handle *ProxyClientFileHandle) IsWriteMode() bool {
	return handle.Handle.IsWriteMode()
}

func (handle *ProxyClientFileHandle) ReadAt(offset int64, length int) ([]byte, error) {
	return handle.ProxySession.ProxyServiceClient.ReadAt(handle.Handle, offset, int32(length))
}

func (handle *ProxyClientFileHandle) WriteAt(offset int64, data []byte) error {
	return handle.ProxySession.ProxyServiceClient.WriteAt(handle.Handle, offset, data)
}

func (handle *ProxyClientFileHandle) Close() error {
	return handle.ProxySession.ProxyServiceClient.Close(handle.Handle)
}
