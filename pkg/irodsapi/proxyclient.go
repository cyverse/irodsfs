package irodsapi

import (
	"fmt"

	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	irodsfs_clienttype "github.com/cyverse/go-irodsclient/irods/types"
	irodsfs_proxy_client "github.com/cyverse/irodsfs-proxy/client"
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
	Config              *irodsfs_client.FileSystemConfig
	ProxyHost           string
	Account             *irodsfs_clienttype.IRODSAccount
	ProxyServiceClient  *irodsfs_proxy_client.ProxyServiceClient
	ProxyServiceSession *irodsfs_proxy_client.ProxyServiceSession
}

func NewProxyClientDriver(proxyHost string, proxyPort int, account *irodsfs_clienttype.IRODSAccount, config *irodsfs_client.FileSystemConfig) (IRODSClient, error) {
	proxyHostPort := fmt.Sprintf("%s:%d", proxyHost, proxyPort)
	proxyServiceClient := irodsfs_proxy_client.NewProxyServiceClient(proxyHostPort)
	err := proxyServiceClient.Connect()
	if err != nil {
		return nil, err
	}

	proxyServiceSession, err := proxyServiceClient.Login(account, config.ApplicationName)
	if err != nil {
		return nil, err
	}

	return &ProxyClient{
		Config:              config,
		ProxyHost:           proxyHostPort,
		Account:             account,
		ProxyServiceClient:  proxyServiceClient,
		ProxyServiceSession: proxyServiceSession,
	}, nil
}

func (client *ProxyClient) GetAccount() *irodsfs_clienttype.IRODSAccount {
	return client.Account
}

func (client *ProxyClient) GetApplicationName() string {
	return client.Config.ApplicationName
}

func (client *ProxyClient) Release() {
	client.ProxyServiceClient.Logout(client.ProxyServiceSession)
	client.ProxyServiceClient.Disconnect()
}

func (client *ProxyClient) List(path string) ([]*IRODSEntry, error) {
	entries, err := client.ProxyServiceClient.List(client.ProxyServiceSession, path)
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
	entry, err := client.ProxyServiceClient.Stat(client.ProxyServiceSession, path)
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
	return client.ProxyServiceClient.ExistsDir(client.ProxyServiceSession, path)
}

func (client *ProxyClient) ListDirACLsWithGroupUsers(path string) ([]*IRODSAccess, error) {
	accesses, err := client.ProxyServiceClient.ListDirACLsWithGroupUsers(client.ProxyServiceSession, path)
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
	accesses, err := client.ProxyServiceClient.ListFileACLsWithGroupUsers(client.ProxyServiceSession, path)
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
	err := client.ProxyServiceClient.RemoveFile(client.ProxyServiceSession, path, force)
	return convProxyClientError(err)
}

func (client *ProxyClient) RemoveDir(path string, recurse bool, force bool) error {
	err := client.ProxyServiceClient.RemoveDir(client.ProxyServiceSession, path, recurse, force)
	return convProxyClientError(err)
}

func (client *ProxyClient) MakeDir(path string, recurse bool) error {
	err := client.ProxyServiceClient.MakeDir(client.ProxyServiceSession, path, recurse)
	return convProxyClientError(err)
}

func (client *ProxyClient) RenameDirToDir(srcPath string, destPath string) error {
	err := client.ProxyServiceClient.RenameDirToDir(client.ProxyServiceSession, srcPath, destPath)
	return convProxyClientError(err)
}

func (client *ProxyClient) RenameFileToFile(srcPath string, destPath string) error {
	err := client.ProxyServiceClient.RenameFileToFile(client.ProxyServiceSession, srcPath, destPath)
	return convProxyClientError(err)
}

func (client *ProxyClient) CreateFile(path string, resource string) (IRODSFileHandle, error) {
	handle, err := client.ProxyServiceClient.CreateFile(client.ProxyServiceSession, path, resource)
	if err != nil {
		return nil, convProxyClientError(err)
	}

	fileHandle := &ProxyClientFileHandle{
		ID:          handle.FileHandleID,
		ProxyClient: client,
		Handle:      handle,
	}

	return fileHandle, nil
}

func (client *ProxyClient) OpenFile(path string, resource string, mode string) (IRODSFileHandle, error) {
	handle, err := client.ProxyServiceClient.OpenFile(client.ProxyServiceSession, path, resource, mode)
	if err != nil {
		return nil, convProxyClientError(err)
	}

	fileHandle := &ProxyClientFileHandle{
		ID:          handle.FileHandleID,
		ProxyClient: client,
		Handle:      handle,
	}

	return fileHandle, nil
}

func (client *ProxyClient) TruncateFile(path string, size int64) error {
	err := client.ProxyServiceClient.TruncateFile(client.ProxyServiceSession, path, size)
	return convProxyClientError(err)
}

// ProxyClientFileHandle implements IRODSFileHandle
type ProxyClientFileHandle struct {
	ID          string
	ProxyClient *ProxyClient
	Handle      *irodsfs_proxy_client.ProxyServiceFileHandle
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
	return handle.ProxyClient.ProxyServiceClient.GetOffset(handle.Handle)
}

func (handle *ProxyClientFileHandle) IsReadMode() bool {
	return handle.Handle.IsReadMode()
}

func (handle *ProxyClientFileHandle) IsWriteMode() bool {
	return handle.Handle.IsWriteMode()
}

func (handle *ProxyClientFileHandle) ReadAt(offset int64, length int) ([]byte, error) {
	return handle.ProxyClient.ProxyServiceClient.ReadAt(handle.Handle, offset, int32(length))
}

func (handle *ProxyClientFileHandle) WriteAt(offset int64, data []byte) error {
	return handle.ProxyClient.ProxyServiceClient.WriteAt(handle.Handle, offset, data)
}

func (handle *ProxyClientFileHandle) Close() error {
	return handle.ProxyClient.ProxyServiceClient.Close(handle.Handle)
}
