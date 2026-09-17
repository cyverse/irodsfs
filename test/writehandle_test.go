package test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// iRODS refuses a second write open of a data object, but POSIX callers open a
// file for writing as many times as they like. The mount serves those opens
// from the one iRODS handle it is allowed to hold.
func TestSeveralWriteHandlesOnOneFile(t *testing.T) {
	fixture := newMountFixture(t)
	writeIRODSFile(t, fixture.fsc, fixture.remote("shared.txt"), "0123456789")

	first, err := os.OpenFile(fixture.local("shared.txt"), os.O_RDWR, 0o600)
	require.NoError(t, err)
	defer first.Close()

	second, err := os.OpenFile(fixture.local("shared.txt"), os.O_RDWR, 0o600)
	require.NoError(t, err, "a second write handle must be served")
	defer second.Close()

	t.Run("BothWrite", func(t *testing.T) {
		_, err := first.WriteAt([]byte("AA"), 0)
		require.NoError(t, err)
		_, err = second.WriteAt([]byte("BB"), 4)
		require.NoError(t, err)

		buffer := make([]byte, 10)
		_, err = second.ReadAt(buffer, 0)
		require.NoError(t, err)
		assert.Equal(t, "AA23BB6789", string(buffer), "each handle must see what the other wrote")
	})

	t.Run("ClosingOneKeepsTheOther", func(t *testing.T) {
		require.NoError(t, first.Close())

		_, err := second.WriteAt([]byte("CC"), 8)
		require.NoError(t, err, "the surviving handle must keep writing")

		buffer := make([]byte, 10)
		_, err = second.ReadAt(buffer, 0)
		require.NoError(t, err)
		assert.Equal(t, "AA23BB67CC", string(buffer))
	})

	t.Run("ContentReachesIRODSAfterTheLastClose", func(t *testing.T) {
		require.NoError(t, second.Close())
		assert.Equal(t, "AA23BB67CC", readIRODSFile(t, fixture.fsc, fixture.remote("shared.txt")))
	})
}

// A read-only handle is opened on its own, and is unaffected by the write
// handles coming and going
func TestReadHandleAlongsideWriteHandles(t *testing.T) {
	fixture := newMountFixture(t)
	writeIRODSFile(t, fixture.fsc, fixture.remote("mixed.txt"), "0123456789")

	reader, err := os.Open(fixture.local("mixed.txt"))
	require.NoError(t, err)
	defer reader.Close()

	writer, err := os.OpenFile(fixture.local("mixed.txt"), os.O_RDWR, 0o600)
	require.NoError(t, err)

	_, err = writer.WriteAt([]byte("XY"), 0)
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	buffer := make([]byte, 10)
	_, err = reader.ReadAt(buffer, 0)
	require.NoError(t, err, "the read handle must outlive the write handle")
	assert.Equal(t, "XY23456789", string(buffer))
}
