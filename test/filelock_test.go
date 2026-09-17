package test

import (
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Open file description locks. They are what cmd/go takes on go.mod, and the
// syscall package does not name them.
const (
	fOFDSetlk  = 0x25
	fOFDSetlkw = 0x26
)

// openLockFile opens the same file on the mount twice, as two processes racing
// for a lock would. The file is planted through iRODS rather than written
// through the mount, so that no staging of its own is in flight while the
// handles are open.
//
// The second handle is read-only on purpose: the mount serves one writable
// handle per file at a time, so a second O_RDWR open fails with EREMOTEIO.
// flock() does not care about the open mode, and a read lock is all the second
// handle needs to collide with the first one's write lock.
func openLockFile(t *testing.T, fixture *mountFixture, name string) (*os.File, *os.File) {
	t.Helper()

	writeIRODSFile(t, fixture.fsc, fixture.remote(name), "locked content")

	reader, err := os.OpenFile(fixture.local(name), os.O_RDONLY, 0o600)
	require.NoError(t, err)
	t.Cleanup(func() { _ = reader.Close() })

	writer, err := os.OpenFile(fixture.local(name), os.O_RDWR, 0o600)
	require.NoError(t, err)
	t.Cleanup(func() { _ = writer.Close() })

	return writer, reader
}

// openLockFileReaders opens the same file twice read-only, which the mount
// allows any number of
func openLockFileReaders(t *testing.T, fixture *mountFixture, name string) (*os.File, *os.File) {
	t.Helper()

	writeIRODSFile(t, fixture.fsc, fixture.remote(name), "locked content")

	first, err := os.OpenFile(fixture.local(name), os.O_RDONLY, 0o600)
	require.NoError(t, err)
	t.Cleanup(func() { _ = first.Close() })

	second, err := os.OpenFile(fixture.local(name), os.O_RDONLY, 0o600)
	require.NoError(t, err)
	t.Cleanup(func() { _ = second.Close() })

	return first, second
}

func wholeFileLock(lockType int16) *syscall.Flock_t {
	// Len 0 means "to the end of the file", which the kernel sends as OFFSET_MAX
	return &syscall.Flock_t{
		Type:   lockType,
		Whence: int16(os.SEEK_SET),
		Start:  0,
		Len:    0,
	}
}

// A blocking lock on a mounted file used to fail outright with ENOTSUP, which
// is what made go build fail inside a mount.
func TestBlockingLockIsSupported(t *testing.T) {
	fixture := newMountFixture(t)
	file, _ := openLockFile(t, fixture, "blocking.txt")

	lock := wholeFileLock(syscall.F_WRLCK)
	require.NoError(t, syscall.FcntlFlock(file.Fd(), syscall.F_SETLKW, lock),
		"a blocking whole-file lock must be granted")

	// the holder asking about its own lock is told the range is free
	query := wholeFileLock(syscall.F_WRLCK)
	require.NoError(t, syscall.FcntlFlock(file.Fd(), syscall.F_GETLK, query))
	assert.Equal(t, int16(syscall.F_UNLCK), query.Type, "an owner must not conflict with itself")

	require.NoError(t, syscall.FcntlFlock(file.Fd(), syscall.F_SETLK, wholeFileLock(syscall.F_UNLCK)))
}

// flock() owners are open file descriptions, so two opens of one file exclude
// each other even within a process
func TestFlockExcludesTheOtherOpenFile(t *testing.T) {
	fixture := newMountFixture(t)
	first, second := openLockFileReaders(t, fixture, "flock.txt")

	require.NoError(t, syscall.Flock(int(first.Fd()), syscall.LOCK_EX))

	err := syscall.Flock(int(second.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	require.Error(t, err, "a second exclusive flock must not be granted")
	assert.ErrorIs(t, err, syscall.EWOULDBLOCK)

	// a waiting lock is granted once the holder lets go
	acquired := make(chan error, 1)
	go func() {
		acquired <- syscall.Flock(int(second.Fd()), syscall.LOCK_EX)
	}()

	select {
	case <-acquired:
		t.Fatal("the waiting flock was granted while the lock was held")
	case <-time.After(200 * time.Millisecond):
	}

	require.NoError(t, syscall.Flock(int(first.Fd()), syscall.LOCK_UN))

	select {
	case err := <-acquired:
		require.NoError(t, err, "the waiting flock must be granted after the holder unlocks")
	case <-time.After(10 * time.Second):
		t.Fatal("the waiting flock was never granted")
	}

	require.NoError(t, syscall.Flock(int(second.Fd()), syscall.LOCK_UN))
}

// Open file description locks are owned per open, like flock, and are what
// cmd/go uses to serialize access to the module cache and go.mod
func TestOFDLockExcludesTheOtherOpenFile(t *testing.T) {
	fixture := newMountFixture(t)
	writer, reader := openLockFile(t, fixture, "ofd.txt")

	require.NoError(t, syscall.FcntlFlock(writer.Fd(), fOFDSetlk, wholeFileLock(syscall.F_WRLCK)))

	err := syscall.FcntlFlock(reader.Fd(), fOFDSetlk, wholeFileLock(syscall.F_RDLCK))
	require.Error(t, err, "a read lock must not be granted while another open file holds a write lock")
	assert.True(t, err == syscall.EAGAIN || err == syscall.EACCES, "unexpected error %v", err)

	acquired := make(chan error, 1)
	go func() {
		acquired <- syscall.FcntlFlock(reader.Fd(), fOFDSetlkw, wholeFileLock(syscall.F_RDLCK))
	}()

	select {
	case <-acquired:
		t.Fatal("the waiting lock was granted while the write lock was held")
	case <-time.After(200 * time.Millisecond):
	}

	require.NoError(t, syscall.FcntlFlock(writer.Fd(), fOFDSetlk, wholeFileLock(syscall.F_UNLCK)))

	select {
	case err := <-acquired:
		require.NoError(t, err, "the waiting lock must be granted after the holder unlocks")
	case <-time.After(10 * time.Second):
		t.Fatal("the waiting lock was never granted")
	}

	require.NoError(t, syscall.FcntlFlock(reader.Fd(), fOFDSetlk, wholeFileLock(syscall.F_UNLCK)))
}

// Read locks are shared, and a write lock waits for them
func TestReadLocksAreShared(t *testing.T) {
	fixture := newMountFixture(t)
	first, second := openLockFileReaders(t, fixture, "shared.txt")

	require.NoError(t, syscall.FcntlFlock(first.Fd(), fOFDSetlk, wholeFileLock(syscall.F_RDLCK)))
	require.NoError(t, syscall.FcntlFlock(second.Fd(), fOFDSetlk, wholeFileLock(syscall.F_RDLCK)),
		"two read locks on one file must both be granted")

	require.NoError(t, syscall.FcntlFlock(first.Fd(), fOFDSetlk, wholeFileLock(syscall.F_UNLCK)))
	require.NoError(t, syscall.FcntlFlock(second.Fd(), fOFDSetlk, wholeFileLock(syscall.F_UNLCK)))
}

// Byte ranges that do not overlap are independent
func TestByteRangeLocksDoNotCollide(t *testing.T) {
	fixture := newMountFixture(t)
	writer, reader := openLockFile(t, fixture, "ranges.txt")

	head := &syscall.Flock_t{Type: syscall.F_WRLCK, Whence: int16(os.SEEK_SET), Start: 0, Len: 4}
	tail := &syscall.Flock_t{Type: syscall.F_RDLCK, Whence: int16(os.SEEK_SET), Start: 4, Len: 4}
	overlapping := &syscall.Flock_t{Type: syscall.F_RDLCK, Whence: int16(os.SEEK_SET), Start: 2, Len: 4}

	require.NoError(t, syscall.FcntlFlock(writer.Fd(), fOFDSetlk, head))
	require.NoError(t, syscall.FcntlFlock(reader.Fd(), fOFDSetlk, tail),
		"a range that does not overlap must be grantable")
	require.Error(t, syscall.FcntlFlock(reader.Fd(), fOFDSetlk, overlapping),
		"a range that overlaps the other lock must not be grantable")
}

// A lock is released when the file that holds it is closed
func TestLocksAreReleasedOnClose(t *testing.T) {
	fixture := newMountFixture(t)
	first, second := openLockFileReaders(t, fixture, "closing.txt")

	require.NoError(t, syscall.Flock(int(first.Fd()), syscall.LOCK_EX))
	require.Error(t, syscall.Flock(int(second.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))

	require.NoError(t, first.Close())

	require.Eventually(t, func() bool {
		return syscall.Flock(int(second.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) == nil
	}, 10*time.Second, 100*time.Millisecond, "the lock must go away with the file that held it")
}
