package irodsapi

import (
	"fmt"
	"sync"

	irodsfs_client "github.com/cyverse/go-irodsclient/fs"
	irodsfs_clienttype "github.com/cyverse/go-irodsclient/irods/types"
	"github.com/rs/xid"
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
	Config   *irodsfs_client.FileSystemConfig
	Sessions map[string]*GoIRODSClientSession
	Mutex    sync.Mutex
}

func NewGoIRODSClientDriver(config *irodsfs_client.FileSystemConfig) IRODSClient {
	return &GoIRODSClient{
		Config:   config,
		Sessions: map[string]*GoIRODSClientSession{},
	}
}

func (client *GoIRODSClient) NewClientSession(account *irodsfs_clienttype.IRODSAccount) (IRODSClientSession, error) {
	goirodsfs, err := irodsfs_client.NewFileSystem(account, client.Config)
	if err != nil {
		return nil, err
	}

	session := &GoIRODSClientSession{
		ID:          xid.New().String(),
		Client:      client,
		Account:     account,
		Config:      client.Config,
		GoIRODSFS:   goirodsfs,
		OpenHandles: map[string]*GoIRODSClientFileHandle{},
	}

	client.Mutex.Lock()
	defer client.Mutex.Unlock()

	client.Sessions[session.ID] = session

	return session, nil
}

func (client *GoIRODSClient) Release() {
	client.Mutex.Lock()
	defer client.Mutex.Unlock()

	if len(client.Sessions) > 0 {
		for _, session := range client.Sessions {
			session.releaseWithoutClientLock()
		}
	}
}

// GoIRODSClientSession implements IRODSClientSession
type GoIRODSClientSession struct {
	ID          string
	Client      *GoIRODSClient
	Account     *irodsfs_clienttype.IRODSAccount
	Config      *irodsfs_client.FileSystemConfig
	GoIRODSFS   *irodsfs_client.FileSystem
	OpenHandles map[string]*GoIRODSClientFileHandle
	Mutex       sync.Mutex
}

func (session *GoIRODSClientSession) GetID() string {
	return session.ID
}

func (session *GoIRODSClientSession) GetAccount() *irodsfs_clienttype.IRODSAccount {
	return session.Account
}

func (session *GoIRODSClientSession) GetApplicationName() string {
	return session.Config.ApplicationName
}

func (session *GoIRODSClientSession) Release() {
	session.Client.Mutex.Lock()
	defer session.Client.Mutex.Unlock()

	session.Mutex.Lock()
	defer session.Mutex.Unlock()

	if len(session.OpenHandles) > 0 {
		for _, handle := range session.OpenHandles {
			handle.closeWithoutSessionLock()
		}
	}

	delete(session.Client.Sessions, session.ID)

	if session.GoIRODSFS != nil {
		session.GoIRODSFS.Release()
		session.GoIRODSFS = nil
	}
}

func (session *GoIRODSClientSession) releaseWithoutClientLock() {
	session.Mutex.Lock()
	defer session.Mutex.Unlock()

	if len(session.OpenHandles) > 0 {
		for _, handle := range session.OpenHandles {
			handle.closeWithoutSessionLock()
		}
	}

	delete(session.Client.Sessions, session.ID)

	if session.GoIRODSFS != nil {
		session.GoIRODSFS.Release()
		session.GoIRODSFS = nil
	}
}

func (session *GoIRODSClientSession) List(path string) ([]*IRODSEntry, error) {
	if session.GoIRODSFS == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	entries, err := session.GoIRODSFS.List(path)
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

func (session *GoIRODSClientSession) Stat(path string) (*IRODSEntry, error) {
	if session.GoIRODSFS == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	entry, err := session.GoIRODSFS.Stat(path)
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

func (session *GoIRODSClientSession) ExistsDir(path string) bool {
	if session.GoIRODSFS == nil {
		return false
	}

	return session.GoIRODSFS.ExistsDir(path)
}

func (session *GoIRODSClientSession) ListDirACLsWithGroupUsers(path string) ([]*IRODSAccess, error) {
	if session.GoIRODSFS == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	accesses, err := session.GoIRODSFS.ListDirACLsWithGroupUsers(path)
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

func (session *GoIRODSClientSession) ListFileACLsWithGroupUsers(path string) ([]*IRODSAccess, error) {
	if session.GoIRODSFS == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	accesses, err := session.GoIRODSFS.ListFileACLsWithGroupUsers(path)
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

func (session *GoIRODSClientSession) RemoveFile(path string, force bool) error {
	if session.GoIRODSFS == nil {
		return fmt.Errorf("FSClient is nil")
	}

	err := session.GoIRODSFS.RemoveFile(path, force)
	return convGoIRODSClientError(err)
}

func (session *GoIRODSClientSession) RemoveDir(path string, recurse bool, force bool) error {
	if session.GoIRODSFS == nil {
		return fmt.Errorf("FSClient is nil")
	}

	err := session.GoIRODSFS.RemoveDir(path, recurse, force)
	return convGoIRODSClientError(err)
}

func (session *GoIRODSClientSession) MakeDir(path string, recurse bool) error {
	if session.GoIRODSFS == nil {
		return fmt.Errorf("FSClient is nil")
	}

	err := session.GoIRODSFS.MakeDir(path, recurse)
	return convGoIRODSClientError(err)
}

func (session *GoIRODSClientSession) RenameDirToDir(srcPath string, destPath string) error {
	if session.GoIRODSFS == nil {
		return fmt.Errorf("FSClient is nil")
	}

	err := session.GoIRODSFS.RenameDirToDir(srcPath, destPath)
	return convGoIRODSClientError(err)
}

func (session *GoIRODSClientSession) RenameFileToFile(srcPath string, destPath string) error {
	if session.GoIRODSFS == nil {
		return fmt.Errorf("FSClient is nil")
	}

	err := session.GoIRODSFS.RenameFileToFile(srcPath, destPath)
	return convGoIRODSClientError(err)
}

func (session *GoIRODSClientSession) CreateFile(path string, resource string) (IRODSFileHandle, error) {
	if session.GoIRODSFS == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	handle, err := session.GoIRODSFS.CreateFile(path, resource)
	if err != nil {
		return nil, convGoIRODSClientError(err)
	}

	fileHandle := &GoIRODSClientFileHandle{
		ID:      xid.New().String(),
		Session: session,
		Handle:  handle,
	}

	session.Mutex.Lock()
	defer session.Mutex.Unlock()

	session.OpenHandles[fileHandle.ID] = fileHandle
	return fileHandle, nil
}

func (session *GoIRODSClientSession) OpenFile(path string, resource string, mode string) (IRODSFileHandle, error) {
	if session.GoIRODSFS == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	handle, err := session.GoIRODSFS.OpenFile(path, resource, mode)
	if err != nil {
		return nil, convGoIRODSClientError(err)
	}

	fileHandle := &GoIRODSClientFileHandle{
		ID:      xid.New().String(),
		Session: session,
		Handle:  handle,
	}

	session.Mutex.Lock()
	defer session.Mutex.Unlock()

	session.OpenHandles[fileHandle.ID] = fileHandle
	return fileHandle, nil
}

func (session *GoIRODSClientSession) TruncateFile(path string, size int64) error {
	if session.GoIRODSFS == nil {
		return fmt.Errorf("FSClient is nil")
	}

	err := session.GoIRODSFS.TruncateFile(path, size)
	return convGoIRODSClientError(err)
}

// GoIRODSClientFileHandle implements IRODSFileHandle
type GoIRODSClientFileHandle struct {
	ID      string
	Session *GoIRODSClientSession
	Handle  *irodsfs_client.FileHandle
	Mutex   sync.Mutex
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
	handle.Mutex.Lock()
	defer handle.Mutex.Unlock()

	return FileOpenMode(handle.Handle.OpenMode)
}

func (handle *GoIRODSClientFileHandle) GetOffset() int64 {
	handle.Mutex.Lock()
	defer handle.Mutex.Unlock()

	return handle.Handle.Offset
}

func (handle *GoIRODSClientFileHandle) IsReadMode() bool {
	handle.Mutex.Lock()
	defer handle.Mutex.Unlock()

	return handle.Handle.IsReadMode()
}

func (handle *GoIRODSClientFileHandle) IsWriteMode() bool {
	handle.Mutex.Lock()
	defer handle.Mutex.Unlock()

	return handle.Handle.IsWriteMode()
}

func (handle *GoIRODSClientFileHandle) Seek(offset int64, whence Whence) (int64, error) {
	handle.Mutex.Lock()
	defer handle.Mutex.Unlock()

	return handle.Handle.Seek(offset, irodsfs_clienttype.Whence(whence))
}

func (handle *GoIRODSClientFileHandle) Read(length int) ([]byte, error) {
	handle.Mutex.Lock()
	defer handle.Mutex.Unlock()

	return handle.Handle.Read(length)
}

func (handle *GoIRODSClientFileHandle) Write(data []byte) error {
	handle.Mutex.Lock()
	defer handle.Mutex.Unlock()

	return handle.Handle.Write(data)
}

func (handle *GoIRODSClientFileHandle) Close() error {
	handle.Session.Mutex.Lock()
	defer handle.Session.Mutex.Unlock()

	handle.Mutex.Lock()
	defer handle.Mutex.Unlock()

	delete(handle.Session.OpenHandles, handle.ID)
	err := handle.Handle.Close()

	return err
}

func (handle *GoIRODSClientFileHandle) closeWithoutSessionLock() error {
	handle.Mutex.Lock()
	defer handle.Mutex.Unlock()

	delete(handle.Session.OpenHandles, handle.ID)
	err := handle.Handle.Close()

	return err
}
