package irodsfs

import (
	"sync"
	"syscall"

	"github.com/cockroachdb/errors"
)

// FileHandleLocalLockManager manages in-memory byte-range locks per file handle
type FileHandleLocalLockManager struct {
	mu    sync.Mutex
	locks map[string]*FileHandleLocalLock // key is ID
}

// NewFileHandleLocalLockManager creates a new FileHandleLocalLockManager
func NewFileHandleLocalLockManager() *FileHandleLocalLockManager {
	return &FileHandleLocalLockManager{
		locks: map[string]*FileHandleLocalLock{},
	}
}

func overlapsRange(s1, e1, s2, e2 uint64) bool {
	// [s1,e1] and [s2,e2] overlap unless one ends before the other starts
	if e2 < s1 || e1 < s2 {
		return false
	}
	return true
}

func combineRange(s1, e1, s2, e2 uint64) (uint64, uint64) {
	return min(s1, s2), max(e1, e2)
}

// Get returns an existing lock overlapping [start, end], or nil
func (manager *FileHandleLocalLockManager) Get(start, end uint64) *FileHandleLocalLock {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	for _, l := range manager.locks {
		if overlapsRange(l.Start, l.End, start, end) {
			return l
		}
	}
	return nil
}

// Lock adds a lock. Returns an error if a conflicting lock exists.
func (manager *FileHandleLocalLockManager) Lock(lock *FileHandleLocalLock) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	// First pass: check for conflicts and collect same-PID overlaps to merge
	var toMerge []string
	for _, existing := range manager.locks {
		if !overlapsRange(existing.Start, existing.End, lock.Start, lock.End) {
			continue
		}

		if existing.Pid != lock.Pid {
			// different PID: conflict if either side is a write lock
			if existing.LockType == syscall.F_WRLCK || lock.LockType == syscall.F_WRLCK {
				return errors.New("lock conflict")
			}
			// both read locks: compatible, continue
		} else {
			// same PID: will merge range
			toMerge = append(toMerge, existing.ID)
		}
	}

	// Merge same-PID overlapping locks into the new lock's range
	for _, id := range toMerge {
		existing := manager.locks[id]
		lock.Start, lock.End = combineRange(existing.Start, existing.End, lock.Start, lock.End)
		delete(manager.locks, id)
	}

	manager.locks[lock.ID] = lock
	return nil
}

// Unlock removes all locks overlapping [lock.Start, lock.End].
func (manager *FileHandleLocalLockManager) Unlock(lock *FileHandleLocalLock) error {
	manager.mu.Lock()
	defer manager.mu.Unlock()

	var toDelete []string
	for _, existing := range manager.locks {
		if overlapsRange(existing.Start, existing.End, lock.Start, lock.End) {
			toDelete = append(toDelete, existing.ID)
		}
	}

	if len(toDelete) == 0 {
		return errors.New("failed to find a lock")
	}

	for _, id := range toDelete {
		delete(manager.locks, id)
	}
	return nil
}

// FileHandleLocalLock represents a byte-range lock
type FileHandleLocalLock struct {
	ID       string
	LockType uint32 // syscall.F_RDLCK or syscall.F_WRLCK
	Pid      uint32
	Start    uint64
	End      uint64
}
