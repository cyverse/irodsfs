package irodsfs

import (
	"context"
	"math"
	"syscall"

	"github.com/cockroachdb/errors"
	irodsfscommon_irods "github.com/cyverse/irodsfs-common/irods"
	fusefs "github.com/hanwen/go-fuse/v2/fs"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
)

// toFileLock converts a lock request the kernel sent to the one the backend
// takes. flock() and fcntl() requests arrive through the same calls and are
// told apart by the LK_FLOCK flag, which decides who owns the lock: an open
// file description for flock(), the process for fcntl().
func toFileLock(owner uint64, lk *fuse.FileLock, flags uint32) (*irodsfscommon_irods.FileLock, error) {
	var lockType irodsfscommon_irods.FileLockType
	switch lk.Typ {
	case syscall.F_RDLCK:
		lockType = irodsfscommon_irods.FileLockTypeRead
	case syscall.F_WRLCK:
		lockType = irodsfscommon_irods.FileLockTypeWrite
	case syscall.F_UNLCK:
		lockType = irodsfscommon_irods.FileLockTypeUnlock
	default:
		return nil, errors.Errorf("unknown file lock type %d", lk.Typ)
	}

	end := lk.End
	if end >= uint64(math.MaxInt64) {
		// a lock that runs to the end of the file (l_len == 0) reaches the
		// kernel as OFFSET_MAX, and so does a whole-file flock()
		end = irodsfscommon_irods.FileLockEndOfFile
	}

	return &irodsfscommon_irods.FileLock{
		Type: lockType,
		Owner: irodsfscommon_irods.FileLockOwner{
			Owner: owner,
			Flock: flags&fuse.LK_FLOCK != 0,
		},
		Pid:   lk.Pid,
		Start: lk.Start,
		End:   end,
	}, nil
}

// fillFuseFileLock reports a held lock back to the kernel
func fillFuseFileLock(out *fuse.FileLock, lock *irodsfscommon_irods.FileLock) {
	out.Start = lock.Start
	out.End = lock.End
	out.Pid = lock.Pid

	switch lock.Type {
	case irodsfscommon_irods.FileLockTypeRead:
		out.Typ = syscall.F_RDLCK
	case irodsfscommon_irods.FileLockTypeWrite:
		out.Typ = syscall.F_WRLCK
	default:
		out.Typ = syscall.F_UNLCK
	}
}

// fileLockErrno turns a lock error into the errno the caller of fcntl() or
// flock() expects
func fileLockErrno(err error) syscall.Errno {
	switch {
	case err == nil:
		return fusefs.OK
	case errors.Is(err, irodsfscommon_irods.ErrFileLockConflict):
		// the lock is held by someone else and the request does not wait
		return syscall.EAGAIN
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		// the kernel interrupted the waiting request
		return syscall.EINTR
	case errors.Is(err, irodsfscommon_irods.ErrFileLockManagerUnavailable):
		return syscall.ENOTSUP
	default:
		return syscall.EIO
	}
}
