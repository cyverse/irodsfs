package irodsapi

import (
	"fmt"

	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	irodsfs_clienttype "github.com/cyverse/go-irodsclient/irods/types"
)

// direct access to iRODS server
// implements interfaces defined in interface.go

func convGoIRODSClientError(err error) error {
	if err == nil {
		return nil
	}

	if irodsfs_clienttype.IsFileNotFoundError(err) {
		return NewFileNotFoundError(err.Error())
	}
	return err
}

// GoIRODSClient implements IRODSClient interface with go-irodsclient
type GoIRODSClient struct {
	Config    *irodsfs_client.FileSystemConfig
	Account   *irodsfs_clienttype.IRODSAccount
	GoIRODSFS *irodsfs_client.FileSystem
}

func NewGoIRODSClientDriver(account *irodsfs_clienttype.IRODSAccount, config *irodsfs_client.FileSystemConfig) (IRODSClient, error) {
	goirodsfs, err := irodsfs_client.NewFileSystem(account, config)
	if err != nil {
		return nil, err
	}

	return &GoIRODSClient{
		Config:    config,
		Account:   account,
		GoIRODSFS: goirodsfs,
	}, nil
}

func (client *GoIRODSClient) GetAccount() *irodsfs_clienttype.IRODSAccount {
	return client.Account
}

func (client *GoIRODSClient) GetApplicationName() string {
	return client.Config.ApplicationName
}

func (client *GoIRODSClient) Release() {
	if client.GoIRODSFS != nil {
		client.GoIRODSFS.Release()
		client.GoIRODSFS = nil
	}
}

func (client *GoIRODSClient) List(path string) ([]*IRODSEntry, error) {
	if client.GoIRODSFS == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	entries, err := client.GoIRODSFS.List(path)
	if err != nil {
		return nil, convGoIRODSClientError(err)
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

func (client *GoIRODSClient) Stat(path string) (*IRODSEntry, error) {
	if client.GoIRODSFS == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	entry, err := client.GoIRODSFS.Stat(path)
	if err != nil {
		return nil, convGoIRODSClientError(err)
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

func (client *GoIRODSClient) ExistsDir(path string) bool {
	if client.GoIRODSFS == nil {
		return false
	}

	return client.GoIRODSFS.ExistsDir(path)
}

func (client *GoIRODSClient) ListDirACLsWithGroupUsers(path string) ([]*IRODSAccess, error) {
	if client.GoIRODSFS == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	accesses, err := client.GoIRODSFS.ListDirACLsWithGroupUsers(path)
	if err != nil {
		return nil, convGoIRODSClientError(err)
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

func (client *GoIRODSClient) ListFileACLsWithGroupUsers(path string) ([]*IRODSAccess, error) {
	if client.GoIRODSFS == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	accesses, err := client.GoIRODSFS.ListFileACLsWithGroupUsers(path)
	if err != nil {
		return nil, convGoIRODSClientError(err)
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

func (client *GoIRODSClient) RemoveFile(path string, force bool) error {
	if client.GoIRODSFS == nil {
		return fmt.Errorf("FSClient is nil")
	}

	err := client.GoIRODSFS.RemoveFile(path, force)
	return convGoIRODSClientError(err)
}

func (client *GoIRODSClient) RemoveDir(path string, recurse bool, force bool) error {
	if client.GoIRODSFS == nil {
		return fmt.Errorf("FSClient is nil")
	}

	err := client.GoIRODSFS.RemoveDir(path, recurse, force)
	return convGoIRODSClientError(err)
}

func (client *GoIRODSClient) MakeDir(path string, recurse bool) error {
	if client.GoIRODSFS == nil {
		return fmt.Errorf("FSClient is nil")
	}

	err := client.GoIRODSFS.MakeDir(path, recurse)
	return convGoIRODSClientError(err)
}

func (client *GoIRODSClient) RenameDirToDir(srcPath string, destPath string) error {
	if client.GoIRODSFS == nil {
		return fmt.Errorf("FSClient is nil")
	}

	err := client.GoIRODSFS.RenameDirToDir(srcPath, destPath)
	return convGoIRODSClientError(err)
}

func (client *GoIRODSClient) RenameFileToFile(srcPath string, destPath string) error {
	if client.GoIRODSFS == nil {
		return fmt.Errorf("FSClient is nil")
	}

	err := client.GoIRODSFS.RenameFileToFile(srcPath, destPath)
	return convGoIRODSClientError(err)
}

func (client *GoIRODSClient) CreateFile(path string, resource string) (IRODSFileHandle, error) {
	if client.GoIRODSFS == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	handle, err := client.GoIRODSFS.CreateFile(path, resource)
	if err != nil {
		return nil, convGoIRODSClientError(err)
	}

	fileHandle := &GoIRODSClientFileHandle{
		ID:     handle.ID,
		Client: client,
		Handle: handle,
	}

	return fileHandle, nil
}

func (client *GoIRODSClient) OpenFile(path string, resource string, mode string) (IRODSFileHandle, error) {
	if client.GoIRODSFS == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	handle, err := client.GoIRODSFS.OpenFile(path, resource, mode)
	if err != nil {
		return nil, convGoIRODSClientError(err)
	}

	fileHandle := &GoIRODSClientFileHandle{
		ID:     handle.ID,
		Client: client,
		Handle: handle,
	}

	return fileHandle, nil
}

func (client *GoIRODSClient) TruncateFile(path string, size int64) error {
	if client.GoIRODSFS == nil {
		return fmt.Errorf("FSClient is nil")
	}

	err := client.GoIRODSFS.TruncateFile(path, size)
	return convGoIRODSClientError(err)
}

// GoIRODSClientFileHandle implements IRODSFileHandle
type GoIRODSClientFileHandle struct {
	ID     string
	Client *GoIRODSClient
	Handle *irodsfs_client.FileHandle
}

func (handle *GoIRODSClientFileHandle) GetID() string {
	return handle.ID
}

func (handle *GoIRODSClientFileHandle) GetEntry() *IRODSEntry {
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

func (handle *GoIRODSClientFileHandle) GetOpenMode() FileOpenMode {
	return FileOpenMode(handle.Handle.OpenMode)
}

func (handle *GoIRODSClientFileHandle) GetOffset() int64 {
	return handle.Handle.GetOffset()
}

func (handle *GoIRODSClientFileHandle) IsReadMode() bool {
	return handle.Handle.IsReadMode()
}

func (handle *GoIRODSClientFileHandle) IsWriteMode() bool {
	return handle.Handle.IsWriteMode()
}

func (handle *GoIRODSClientFileHandle) ReadAt(offset int64, length int) ([]byte, error) {
	return handle.Handle.ReadAt(offset, length)
}

func (handle *GoIRODSClientFileHandle) WriteAt(offset int64, data []byte) error {
	return handle.Handle.WriteAt(offset, data)
}

func (handle *GoIRODSClientFileHandle) Close() error {
	return handle.Handle.Close()
}
