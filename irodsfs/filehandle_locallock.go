package irodsfs

import (
	"sync"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

// FileHandleLocalLockManager is a manager that manages FileHandleLocalLocks
type FileHandleLocalLockManager struct {
	lock            sync.RWMutex
	fileHandleLocks map[string]*FileHandleLocalLock // key is ID
}

// NewFileHandleLocalLockManager creates a new FileHandleLocalLockManager
func NewFileHandleLocalLockManager() *FileHandleLocalLockManager {
	return &FileHandleLocalLockManager{
		lock:            sync.RWMutex{},
		fileHandleLocks: map[string]*FileHandleLocalLock{},
	}
}

func (manager *FileHandleLocalLockManager) overlapRange(s1 uint64, e1 uint64, s2 uint64, e2 uint64) bool {
	if s2 < s1 {
		// s2-e2-s1-e1
		if e2 < s1 {
			return false
		}
	} else {
		// s1-e1-s2-e2
		if e1 < s2 {
			return false
		}
	}
	return true
}

func (manager *FileHandleLocalLockManager) combineRange(s1 uint64, e1 uint64, s2 uint64, e2 uint64) (uint64, uint64) {
	cs := s1
	if s2 < s1 {
		cs = s2
	}

	ce := e1
	if e2 > e1 {
		ce = e2
	}
	return cs, ce
}

// Get returns lock
func (manager *FileHandleLocalLockManager) Get(start uint64, end uint64) *FileHandleLocalLock {
	manager.lock.RLock()
	defer manager.lock.RUnlock()

	for _, fileHandlelock := range manager.fileHandleLocks {
		if manager.overlapRange(fileHandlelock.Start, fileHandlelock.End, start, end) {
			return fileHandlelock
		}
	}
	return nil
}

// Lock locks, return error if it errors
func (manager *FileHandleLocalLockManager) Lock(lock *FileHandleLocalLock) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandleLocalLockManager",
		"function": "Lock",
	})

	manager.lock.RLock()
	defer manager.lock.RUnlock()

	for _, fileHandlelock := range manager.fileHandleLocks {
		if manager.overlapRange(fileHandlelock.Start, fileHandlelock.End, lock.Start, lock.End) {
			// overlapping
			if fileHandlelock.Pid != lock.Pid {
				logger.Debugf("found other process's lock")

				if fileHandlelock.LockType == syscall.F_WRLCK {
					// we found wlock - always conflict
					return xerrors.Errorf("found conflict wlock")
				}

				if lock.LockType == syscall.F_WRLCK {
					// our lock is wlock - always conflict
					return xerrors.Errorf("there is a lock")
				}

				// read lock - add
				logger.Debugf("found other process's read lock - ok")
				manager.fileHandleLocks[lock.ID] = lock
			} else {
				// same pid
				// update?
				logger.Debugf("found my process's lock - update")
				s, e := manager.combineRange(fileHandlelock.Start, fileHandlelock.End, lock.Start, lock.End)
				lock.Start = s
				lock.End = e
				delete(manager.fileHandleLocks, fileHandlelock.ID)
				manager.fileHandleLocks[lock.ID] = lock
				break
			}
		}
	}

	manager.fileHandleLocks[lock.ID] = lock
	return nil
}

// Unlock unlocks
func (manager *FileHandleLocalLockManager) Unlock(lock *FileHandleLocalLock) error {
	logger := log.WithFields(log.Fields{
		"package":  "irodsfs",
		"struct":   "FileHandleLocalLockManager",
		"function": "Unlock",
	})

	manager.lock.RLock()
	defer manager.lock.RUnlock()

	found := false

	for _, fileHandlelock := range manager.fileHandleLocks {
		if manager.overlapRange(fileHandlelock.Start, fileHandlelock.End, lock.Start, lock.End) {
			// found - remove
			logger.Debugf("delete lock - start %d, end %d", fileHandlelock.Start, fileHandlelock.End)
			delete(manager.fileHandleLocks, fileHandlelock.ID)
			found = true
		}
	}

	if found {
		return nil
	}
	return xerrors.Errorf("failed to find a lock")
}

// FileHandleLocalLock is a struct for locally managed file lock
type FileHandleLocalLock struct {
	ID       string
	LockType uint32 // syscall.F_RDLCK or syscall.F_WRLCK
	Pid      uint32
	Start    uint64
	End      uint64
}
