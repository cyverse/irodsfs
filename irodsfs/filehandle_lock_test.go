package irodsfs

import (
	"context"
	"math"
	"syscall"
	"testing"

	"github.com/cockroachdb/errors"
	irodsfscommon_irods "github.com/cyverse/irodsfs-common/irods"
	fuse "github.com/hanwen/go-fuse/v2/fuse"
)

func TestToFileLockConvertsLockTypes(t *testing.T) {
	tests := []struct {
		fuseType uint32
		expected irodsfscommon_irods.FileLockType
	}{
		{syscall.F_RDLCK, irodsfscommon_irods.FileLockTypeRead},
		{syscall.F_WRLCK, irodsfscommon_irods.FileLockTypeWrite},
		{syscall.F_UNLCK, irodsfscommon_irods.FileLockTypeUnlock},
	}

	for _, test := range tests {
		lock, err := toFileLock(7, &fuse.FileLock{Typ: test.fuseType, Start: 10, End: 20, Pid: 4242}, 0)
		if err != nil {
			t.Fatalf("failed to convert lock type %d: %v", test.fuseType, err)
		}
		if lock.Type != test.expected {
			t.Fatalf("lock type %d became %s, want %s", test.fuseType, lock.Type.String(), test.expected.String())
		}
		if lock.Start != 10 || lock.End != 20 || lock.Pid != 4242 || lock.Owner.Owner != 7 {
			t.Fatalf("unexpected lock %+v", lock)
		}
	}

	if _, err := toFileLock(7, &fuse.FileLock{Typ: 0xFF}, 0); err == nil {
		t.Fatal("expected an unknown lock type to fail")
	}
}

// The kernel sends a lock that runs to the end of the file as OFFSET_MAX, and a
// whole-file flock() the same way, so both have to become the end-of-file mark
// the lock manager compares against.
func TestToFileLockNormalizesTheEndOfFile(t *testing.T) {
	lock, err := toFileLock(7, &fuse.FileLock{Typ: syscall.F_WRLCK, Start: 0, End: math.MaxInt64}, 0)
	if err != nil {
		t.Fatalf("failed to convert: %v", err)
	}

	if lock.End != irodsfscommon_irods.FileLockEndOfFile {
		t.Fatalf("end = %d, want the end-of-file mark %d", lock.End, uint64(irodsfscommon_irods.FileLockEndOfFile))
	}

	// a bounded range is left alone
	bounded, err := toFileLock(7, &fuse.FileLock{Typ: syscall.F_WRLCK, Start: 0, End: 4095}, 0)
	if err != nil {
		t.Fatalf("failed to convert: %v", err)
	}
	if bounded.End != 4095 {
		t.Fatalf("end = %d, want 4095", bounded.End)
	}
}

// flock() and fcntl() requests arrive through the same calls and are told apart
// only by this flag, which decides whether the owner is an open file
// description or the whole process.
func TestToFileLockCarriesTheFlockFlag(t *testing.T) {
	fcntlLock, err := toFileLock(7, &fuse.FileLock{Typ: syscall.F_WRLCK}, 0)
	if err != nil {
		t.Fatalf("failed to convert: %v", err)
	}
	if fcntlLock.Owner.Flock {
		t.Fatal("an fcntl request was marked as flock")
	}

	flockLock, err := toFileLock(7, &fuse.FileLock{Typ: syscall.F_WRLCK}, fuse.LK_FLOCK)
	if err != nil {
		t.Fatalf("failed to convert: %v", err)
	}
	if !flockLock.Owner.Flock {
		t.Fatal("a flock request was not marked as flock")
	}
}

func TestFillFuseFileLockReportsTheHolder(t *testing.T) {
	out := &fuse.FileLock{}
	fillFuseFileLock(out, &irodsfscommon_irods.FileLock{
		Type:  irodsfscommon_irods.FileLockTypeWrite,
		Pid:   4242,
		Start: 10,
		End:   20,
	})

	if out.Typ != syscall.F_WRLCK || out.Pid != 4242 || out.Start != 10 || out.End != 20 {
		t.Fatalf("unexpected lock reported back: %+v", out)
	}

	fillFuseFileLock(out, &irodsfscommon_irods.FileLock{Type: irodsfscommon_irods.FileLockTypeRead})
	if out.Typ != syscall.F_RDLCK {
		t.Fatalf("read lock reported as %d", out.Typ)
	}
}

func TestFileLockErrno(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected syscall.Errno
	}{
		{"granted", nil, 0},
		{"held by another owner", errors.Wrap(irodsfscommon_irods.ErrFileLockConflict, "denied"), syscall.EAGAIN},
		{"interrupted wait", errors.Wrap(context.Canceled, "gave up"), syscall.EINTR},
		{"timed out wait", errors.Wrap(context.DeadlineExceeded, "gave up"), syscall.EINTR},
		{"backend without locks", errors.Wrap(irodsfscommon_irods.ErrFileLockManagerUnavailable, "no manager"), syscall.ENOTSUP},
		{"anything else", errors.New("connection reset"), syscall.EIO},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if errno := fileLockErrno(test.err); errno != test.expected {
				t.Fatalf("errno = %d, want %d", errno, test.expected)
			}
		})
	}
}
