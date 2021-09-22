package irodsapi

import (
	irodsfs_clienttype "github.com/cyverse/go-irodsclient/irods/types"
)

type IRODSClient interface {
	Release()

	GetAccount() *irodsfs_clienttype.IRODSAccount
	GetApplicationName() string

	// API
	List(path string) ([]*IRODSEntry, error)
	Stat(path string) (*IRODSEntry, error)
	ExistsDir(path string) bool
	ListDirACLsWithGroupUsers(path string) ([]*IRODSAccess, error)
	ListFileACLsWithGroupUsers(path string) ([]*IRODSAccess, error)
	RemoveFile(path string, force bool) error
	RemoveDir(path string, recurse bool, force bool) error
	MakeDir(path string, recurse bool) error
	RenameDirToDir(srcPath string, destPath string) error
	RenameFileToFile(srcPath string, destPath string) error
	CreateFile(path string, resource string) (IRODSFileHandle, error)
	OpenFile(path string, resource string, mode string) (IRODSFileHandle, error)
	TruncateFile(path string, size int64) error
}

type IRODSFileHandle interface {
	GetID() string
	GetEntry() *IRODSEntry
	GetOpenMode() FileOpenMode
	GetOffset() int64
	IsReadMode() bool
	IsWriteMode() bool
	ReadAt(offset int64, length int) ([]byte, error)
	WriteAt(offset int64, data []byte) error
	Close() error
}