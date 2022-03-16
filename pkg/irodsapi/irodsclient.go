package irodsapi

import (
	"fmt"
	"runtime/debug"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	irodsclient_types "github.com/cyverse/go-irodsclient/irods/types"
	log "github.com/sirupsen/logrus"
)

// direct access to iRODS server
// implements interfaces defined in interface.go

func convGoIRODSClientError(err error) error {
	if err == nil {
		return nil
	}

	if irodsclient_types.IsFileNotFoundError(err) {
		return NewFileNotFoundError(err.Error())
	} else if irodsclient_types.IsCollectionNotEmptyError(err) {
		return NewCollectionNotEmptyError(err.Error())
	}

	return err
}

// GoIRODSClient implements IRODSClient interface with go-irodsclient
type GoIRODSClient struct {
	config  *irodsclient_fs.FileSystemConfig
	account *irodsclient_types.IRODSAccount
	fs      *irodsclient_fs.FileSystem
}

func NewGoIRODSClientDriver(account *irodsclient_types.IRODSAccount, config *irodsclient_fs.FileSystemConfig) (IRODSClient, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"function": "NewGoIRODSClientDriver",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	goirodsfs, err := irodsclient_fs.NewFileSystem(account, config)
	if err != nil {
		return nil, err
	}

	return &GoIRODSClient{
		config:  config,
		account: account,
		fs:      goirodsfs,
	}, nil
}

func (client *GoIRODSClient) GetAccount() *irodsclient_types.IRODSAccount {
	return client.account
}

func (client *GoIRODSClient) GetApplicationName() string {
	return client.config.ApplicationName
}

func (client *GoIRODSClient) Release() {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "Release",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	if client.fs != nil {
		client.fs.Release()
		client.fs = nil
	}
}

func (client *GoIRODSClient) List(path string) ([]*IRODSEntry, error) {
	if client.fs == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "List",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	entries, err := client.fs.List(path)
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
	if client.fs == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "Stat",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	entry, err := client.fs.Stat(path)
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
	if client.fs == nil {
		return false
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "ExistsDir",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	return client.fs.ExistsDir(path)
}

func (client *GoIRODSClient) ListUserGroups(user string) ([]*IRODSUser, error) {
	if client.fs == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "ListUserGroups",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	groups, err := client.fs.ListUserGroups(user)
	if err != nil {
		return nil, convGoIRODSClientError(err)
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

func (client *GoIRODSClient) ListDirACLs(path string) ([]*IRODSAccess, error) {
	if client.fs == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "ListDirACLs",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	accesses, err := client.fs.ListDirACLs(path)
	if err != nil {
		return nil, convGoIRODSClientError(err)
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

func (client *GoIRODSClient) ListFileACLs(path string) ([]*IRODSAccess, error) {
	if client.fs == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "ListFileACLs",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	accesses, err := client.fs.ListFileACLs(path)
	if err != nil {
		return nil, convGoIRODSClientError(err)
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

func (client *GoIRODSClient) RemoveFile(path string, force bool) error {
	if client.fs == nil {
		return fmt.Errorf("FSClient is nil")
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "RemoveFile",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	err := client.fs.RemoveFile(path, force)
	return convGoIRODSClientError(err)
}

func (client *GoIRODSClient) RemoveDir(path string, recurse bool, force bool) error {
	if client.fs == nil {
		return fmt.Errorf("FSClient is nil")
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "RemoveDir",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	err := client.fs.RemoveDir(path, recurse, force)
	return convGoIRODSClientError(err)
}

func (client *GoIRODSClient) MakeDir(path string, recurse bool) error {
	if client.fs == nil {
		return fmt.Errorf("FSClient is nil")
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "MakeDir",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	err := client.fs.MakeDir(path, recurse)
	return convGoIRODSClientError(err)
}

func (client *GoIRODSClient) RenameDirToDir(srcPath string, destPath string) error {
	if client.fs == nil {
		return fmt.Errorf("FSClient is nil")
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "RenameDirToDir",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	err := client.fs.RenameDirToDir(srcPath, destPath)
	return convGoIRODSClientError(err)
}

func (client *GoIRODSClient) RenameFileToFile(srcPath string, destPath string) error {
	if client.fs == nil {
		return fmt.Errorf("FSClient is nil")
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "RenameFileToFile",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	err := client.fs.RenameFileToFile(srcPath, destPath)
	return convGoIRODSClientError(err)
}

func (client *GoIRODSClient) CreateFile(path string, resource string, mode string) (IRODSFileHandle, error) {
	if client.fs == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "CreateFile",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	handle, err := client.fs.CreateFile(path, resource, mode)
	if err != nil {
		return nil, convGoIRODSClientError(err)
	}

	fileHandle := &GoIRODSClientFileHandle{
		ID:     handle.GetID(),
		Client: client,
		Handle: handle,
	}

	return fileHandle, nil
}

func (client *GoIRODSClient) OpenFile(path string, resource string, mode string) (IRODSFileHandle, error) {
	if client.fs == nil {
		return nil, fmt.Errorf("FSClient is nil")
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "OpenFile",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	handle, err := client.fs.OpenFile(path, resource, mode)
	if err != nil {
		return nil, convGoIRODSClientError(err)
	}

	fileHandle := &GoIRODSClientFileHandle{
		ID:     handle.GetID(),
		Client: client,
		Handle: handle,
	}

	return fileHandle, nil
}

func (client *GoIRODSClient) TruncateFile(path string, size int64) error {
	if client.fs == nil {
		return fmt.Errorf("FSClient is nil")
	}

	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClient",
		"function": "TruncateFile",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	err := client.fs.TruncateFile(path, size)
	return convGoIRODSClientError(err)
}

// GoIRODSClientFileHandle implements IRODSFileHandle
type GoIRODSClientFileHandle struct {
	ID     string
	Client *GoIRODSClient
	Handle *irodsclient_fs.FileHandle
}

func (handle *GoIRODSClientFileHandle) GetID() string {
	return handle.ID
}

func (handle *GoIRODSClientFileHandle) GetEntry() *IRODSEntry {

	entry := handle.Handle.GetEntry()

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
	}
}

func (handle *GoIRODSClientFileHandle) GetOpenMode() FileOpenMode {
	return FileOpenMode(handle.Handle.GetOpenMode())
}

func (handle *GoIRODSClientFileHandle) GetOffset() int64 {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClientFileHandle",
		"function": "GetOffset",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	return handle.Handle.GetOffset()
}

func (handle *GoIRODSClientFileHandle) IsReadMode() bool {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClientFileHandle",
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

func (handle *GoIRODSClientFileHandle) IsWriteMode() bool {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClientFileHandle",
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

func (handle *GoIRODSClientFileHandle) ReadAt(offset int64, length int) ([]byte, error) {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClientFileHandle",
		"function": "ReadAt",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	return handle.Handle.ReadAt(offset, length)
}

func (handle *GoIRODSClientFileHandle) WriteAt(offset int64, data []byte) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClientFileHandle",
		"function": "WriteAt",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	return handle.Handle.WriteAt(offset, data)
}

func (handle *GoIRODSClientFileHandle) Flush() error {
	return nil
}

func (handle *GoIRODSClientFileHandle) Close() error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsapi",
		"struct":   "GoIRODSClientFileHandle",
		"function": "Close",
	})

	defer func() {
		if r := recover(); r != nil {
			logger.Errorf("stacktrace from panic: %s", string(debug.Stack()))
			logger.Panic(r)
		}
	}()

	return handle.Handle.Close()
}
