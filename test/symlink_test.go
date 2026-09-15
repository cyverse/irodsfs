package test

import (
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
	"testing"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
	"github.com/cyverse/irodsfs-common/irods/vpath"
	"github.com/cyverse/irodsfs/commons"
	"github.com/cyverse/irodsfs/irodsfs"
	"github.com/cyverse/irodsfs/test/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testServerName  = "iRODS 4.3.3"
	symlinkSuffix   = ".irodssymlink"
	testCollections = "irodsfs_symlink_test"
)

// newTestConfig builds an irodsfs config that mounts irodsPath on mountPath in
// direct mode. Pool mode is out of scope here; see symlink_design.md §10.
func newTestConfig(t *testing.T, info server.IRODSServerInfo, irodsPath string, mountPath string) *commons.Config {
	t.Helper()

	config := commons.NewDefaultConfig()
	config.Host = info.Host
	config.Port = info.Port
	config.Username = info.User
	config.ClientUsername = info.User
	config.ZoneName = info.Zone
	config.ClientZoneName = info.Zone
	config.Password = info.Password
	config.AuthenticationScheme = string(info.AuthScheme)
	config.DefaultResource = info.Resource

	config.MountPath = mountPath
	config.DataRootPath = t.TempDir()
	config.UID = os.Getuid()
	config.GID = os.Getgid()
	config.PathMappings = []vpath.VPathMapping{
		{
			IRODSPath:    irodsPath,
			MappingPath:  "/",
			ResourceType: vpath.VPathMappingDirectory,
		},
	}

	require.NoError(t, config.MakeWorkDirs())
	require.NoError(t, config.Validate())

	return config
}

// writeIRODSFile writes content to an iRODS data object, bypassing the mount. It is
// how the tests plant objects the mount is not allowed to create, and how they read
// back what another client would see.
func writeIRODSFile(t *testing.T, fsc *irodsclient_fs.FileSystem, irodsPath string, content string) {
	t.Helper()

	handle, err := fsc.CreateFile(irodsPath, "", "w")
	require.NoError(t, err)

	_, err = handle.Write([]byte(content))
	require.NoError(t, err)
	require.NoError(t, handle.Close())
}

func readIRODSFile(t *testing.T, fsc *irodsclient_fs.FileSystem, irodsPath string) string {
	t.Helper()

	entry, err := fsc.StatFresh(irodsPath)
	require.NoError(t, err)

	handle, err := fsc.OpenFile(irodsPath, "", "r")
	require.NoError(t, err)
	defer handle.Close()

	buffer := make([]byte, entry.Size)
	read, err := handle.Read(buffer)
	require.NoError(t, err)

	return string(buffer[:read])
}

func irodsNames(t *testing.T, fsc *irodsclient_fs.FileSystem, irodsPath string) []string {
	t.Helper()

	entries, err := fsc.ListFresh(irodsPath)
	require.NoError(t, err)

	names := []string{}
	for _, entry := range entries {
		names = append(names, entry.Name)
	}

	return names
}

// mountFixture is a local iRODS server with an irodsfs mount on top of a scratch
// collection.
type mountFixture struct {
	fsc       *irodsclient_fs.FileSystem
	irodsRoot string
	mountPath string
}

// testServer is started once for the package; starting a zone per test would cost
// more than the tests themselves.
var (
	testServer     *server.IRODSServer
	testServerInfo server.IRODSServerInfo
)

func TestMain(m *testing.M) {
	for _, info := range server.GetTestIRODSServerInfos() {
		if info.Name == testServerName {
			testServerInfo = info
		}
	}

	if testServerInfo.Name == "" {
		panic("no test server info named " + testServerName)
	}

	testServer = server.NewIRODSServer(testServerInfo)
	if err := testServer.Start(); err != nil {
		panic(err)
	}

	code := m.Run()

	_ = testServer.Stop()
	os.Exit(code)
}

func newMountFixture(t *testing.T) *mountFixture {
	t.Helper()

	info := testServerInfo
	irodsServer := testServer

	fsc, err := irodsServer.GetFileSystem()
	require.NoError(t, err)
	t.Cleanup(fsc.Release)

	homeDir, err := irodsServer.GetHomeDir()
	require.NoError(t, err)

	irodsRoot := path.Join(homeDir, testCollections)
	_ = fsc.RemoveDir(irodsRoot, true, true)
	require.NoError(t, fsc.MakeDir(irodsRoot, true))
	t.Cleanup(func() {
		_ = fsc.RemoveDir(irodsRoot, true, true)
	})

	mountPath := t.TempDir()
	config := newTestConfig(t, info, irodsRoot, mountPath)

	mountedFS, err := irodsfs.NewFileSystem(config)
	require.NoError(t, err)
	require.NoError(t, mountedFS.Mount())
	t.Cleanup(func() {
		mountedFS.Unmount()
		mountedFS.Release()
	})

	return &mountFixture{
		fsc:       fsc,
		irodsRoot: irodsRoot,
		mountPath: mountPath,
	}
}

func (fixture *mountFixture) local(elements ...string) string {
	return filepath.Join(append([]string{fixture.mountPath}, elements...)...)
}

func (fixture *mountFixture) remote(elements ...string) string {
	return path.Join(append([]string{fixture.irodsRoot}, elements...)...)
}

func TestSymlink(t *testing.T) {
	fixture := newMountFixture(t)

	t.Run("CreateReadlinkTraverse", func(t *testing.T) {
		require.NoError(t, os.Mkdir(fixture.local("lib"), 0o700))
		require.NoError(t, os.WriteFile(fixture.local("lib", "marker.txt"), []byte("hello from lib"), 0o600))

		require.NoError(t, os.Symlink("lib", fixture.local("lib64")))

		target, err := os.Readlink(fixture.local("lib64"))
		require.NoError(t, err)
		assert.Equal(t, "lib", target)

		info, err := os.Lstat(fixture.local("lib64"))
		require.NoError(t, err)
		assert.Equal(t, os.ModeSymlink, info.Mode()&os.ModeSymlink, "entry must be a symbolic link")
		assert.Equal(t, int64(len("lib")), info.Size(), "size must be the target length")

		// the kernel resolves the link
		content, err := os.ReadFile(fixture.local("lib64", "marker.txt"))
		require.NoError(t, err)
		assert.Equal(t, "hello from lib", string(content))
	})

	t.Run("StoredNameAndContentVisibleToOtherClients", func(t *testing.T) {
		assert.Contains(t, irodsNames(t, fixture.fsc, fixture.irodsRoot), "lib64"+symlinkSuffix)
		assert.Equal(t, "lib", readIRODSFile(t, fixture.fsc, fixture.remote("lib64"+symlinkSuffix)))

		// the visible name must not exist as an object of its own
		_, err := fixture.fsc.StatFresh(fixture.remote("lib64"))
		assert.Error(t, err)
	})

	t.Run("AbsoluteAndDanglingTarget", func(t *testing.T) {
		require.NoError(t, os.Symlink("/usr/bin/python3", fixture.local("abslink")))
		target, err := os.Readlink(fixture.local("abslink"))
		require.NoError(t, err)
		assert.Equal(t, "/usr/bin/python3", target)

		require.NoError(t, os.Symlink("nowhere", fixture.local("dangling")))
		target, err = os.Readlink(fixture.local("dangling"))
		require.NoError(t, err)
		assert.Equal(t, "nowhere", target)

		// a dangling link stats as a link but cannot be followed
		_, err = os.Stat(fixture.local("dangling"))
		assert.True(t, os.IsNotExist(err), "following a dangling link must fail with ENOENT, got %v", err)
	})

	t.Run("RealEntryWinsOverSymlink", func(t *testing.T) {
		// plant both names directly in iRODS; the mount refuses to create the suffixed one
		writeIRODSFile(t, fixture.fsc, fixture.remote("shadowed"), "real entry")
		writeIRODSFile(t, fixture.fsc, fixture.remote("shadowed"+symlinkSuffix), "lib")

		info, err := os.Lstat(fixture.local("shadowed"))
		require.NoError(t, err)
		assert.Zero(t, info.Mode()&os.ModeSymlink, "the real entry must win")
		assert.Equal(t, int64(len("real entry")), info.Size())

		names, err := os.ReadDir(fixture.mountPath)
		require.NoError(t, err)

		shown := 0
		for _, name := range names {
			assert.False(t, strings.HasSuffix(name.Name(), symlinkSuffix), "stored names must not be listed")
			if name.Name() == "shadowed" {
				shown++
			}
		}
		assert.Equal(t, 1, shown, "the shadowed link must not produce a duplicate entry")
	})

	t.Run("ReservedSuffixRejected", func(t *testing.T) {
		err := os.WriteFile(fixture.local("reserved"+symlinkSuffix), []byte("x"), 0o600)
		assert.ErrorIs(t, err, os.ErrPermission)

		err = os.Mkdir(fixture.local("reserveddir"+symlinkSuffix), 0o700)
		assert.ErrorIs(t, err, os.ErrPermission)

		require.NoError(t, os.Symlink("lib", fixture.local("renamesrc")))
		err = os.Rename(fixture.local("renamesrc"), fixture.local("renamedst"+symlinkSuffix))
		assert.ErrorIs(t, err, os.ErrPermission)
		require.NoError(t, os.Remove(fixture.local("renamesrc")))
	})

	t.Run("RenameSymlink", func(t *testing.T) {
		require.NoError(t, os.Symlink("lib", fixture.local("movable")))

		require.NoError(t, os.Rename(fixture.local("movable"), fixture.local("moved")))
		target, err := os.Readlink(fixture.local("moved"))
		require.NoError(t, err)
		assert.Equal(t, "lib", target)

		// the stored object moved with it
		names := irodsNames(t, fixture.fsc, fixture.irodsRoot)
		assert.Contains(t, names, "moved"+symlinkSuffix)
		assert.NotContains(t, names, "movable"+symlinkSuffix)

		// across directories
		require.NoError(t, os.Rename(fixture.local("moved"), fixture.local("lib", "moved")))
		target, err = os.Readlink(fixture.local("lib", "moved"))
		require.NoError(t, err)
		assert.Equal(t, "lib", target)
		assert.Contains(t, irodsNames(t, fixture.fsc, fixture.remote("lib")), "moved"+symlinkSuffix)

		require.NoError(t, os.Remove(fixture.local("lib", "moved")))
	})

	t.Run("UnlinkSymlink", func(t *testing.T) {
		require.NoError(t, os.Symlink("lib", fixture.local("removable")))
		require.NoError(t, os.Remove(fixture.local("removable")))

		assert.NotContains(t, irodsNames(t, fixture.fsc, fixture.irodsRoot), "removable"+symlinkSuffix)

		// removing a link must not touch its target
		_, err := os.Stat(fixture.local("lib"))
		assert.NoError(t, err)
	})

	t.Run("TargetTooLong", func(t *testing.T) {
		err := os.Symlink("/"+strings.Repeat("a", 5000), fixture.local("toolong"))
		assert.Error(t, err)
	})

	t.Run("RegressionPlainEntries", func(t *testing.T) {
		require.NoError(t, os.Mkdir(fixture.local("plain"), 0o700))
		require.NoError(t, os.WriteFile(fixture.local("plain", "a.txt"), []byte("aaa"), 0o600))
		require.NoError(t, os.Mkdir(fixture.local("plain", "sub"), 0o700))

		entries, err := os.ReadDir(fixture.local("plain"))
		require.NoError(t, err)
		require.Len(t, entries, 2)

		content, err := os.ReadFile(fixture.local("plain", "a.txt"))
		require.NoError(t, err)
		assert.Equal(t, "aaa", string(content))

		require.NoError(t, os.Rename(fixture.local("plain", "a.txt"), fixture.local("plain", "b.txt")))
		content, err = os.ReadFile(fixture.local("plain", "b.txt"))
		require.NoError(t, err)
		assert.Equal(t, "aaa", string(content))

		require.NoError(t, os.Remove(fixture.local("plain", "b.txt")))
		require.NoError(t, os.Remove(fixture.local("plain", "sub")))
		require.NoError(t, os.Remove(fixture.local("plain")))
	})
}

// TestVenv is the acceptance test of symlink_design.md §10: the case that motivated
// symbolic link support in the first place.
func TestVenv(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping venv acceptance test in short mode")
	}

	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}

	fixture := newMountFixture(t)

	venvPath := fixture.local("venv")
	output, err := exec.Command("python3", "-m", "venv", venvPath).CombinedOutput()
	require.NoError(t, err, "venv creation failed: %s", output)

	// the symbolic links venv relies on
	for _, link := range []string{"lib64", filepath.Join("bin", "python3")} {
		info, lstatErr := os.Lstat(filepath.Join(venvPath, link))
		require.NoError(t, lstatErr, "%s must exist", link)
		assert.NotZero(t, info.Mode()&os.ModeSymlink, "%s must be a symbolic link", link)
	}

	// and the interpreter must actually run out of the venv
	output, err = exec.Command(filepath.Join(venvPath, "bin", "python3"), "-c", "import sys; print(sys.prefix)").CombinedOutput()
	require.NoError(t, err, "venv python failed: %s", output)
	assert.Contains(t, string(output), venvPath)
}
