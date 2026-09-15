package irodsfs

import (
	"testing"

	irodsclient_fs "github.com/cyverse/go-irodsclient/fs"
)

func newTestFileEntry(id int64, name string) *irodsclient_fs.Entry {
	return &irodsclient_fs.Entry{
		ID:   id,
		Type: irodsclient_fs.FileEntry,
		Name: name,
		Path: "/zone/home/user/" + name,
	}
}

func newTestDirEntry(id int64, name string) *irodsclient_fs.Entry {
	return &irodsclient_fs.Entry{
		ID:   id,
		Type: irodsclient_fs.DirectoryEntry,
		Name: name,
		Path: "/zone/home/user/" + name,
	}
}

func TestSymlinkVisibleName(t *testing.T) {
	tests := []struct {
		storedName  string
		visibleName string
		isSymlink   bool
	}{
		{"lib64" + SymlinkSuffix, "lib64", true},
		{"a.b.c" + SymlinkSuffix, "a.b.c", true},
		{"lib64", "", false},
		{"", "", false},
		{SymlinkSuffix, "", false},                    // the suffix alone leaves no name
		{SymlinkSuffix + ".txt", "", false},           // the suffix must be trailing
		{"lib64" + SymlinkSuffix + ".bak", "", false}, // ditto
		{"lib64" + SymlinkSuffix + SymlinkSuffix, "lib64" + SymlinkSuffix, true},
	}

	for _, test := range tests {
		visibleName, isSymlink := SymlinkVisibleName(test.storedName)
		if isSymlink != test.isSymlink || visibleName != test.visibleName {
			t.Errorf("SymlinkVisibleName(%q) = (%q, %v), want (%q, %v)", test.storedName, visibleName, isSymlink, test.visibleName, test.isSymlink)
		}

		if got := IsSymlinkStoredName(test.storedName); got != test.isSymlink {
			t.Errorf("IsSymlinkStoredName(%q) = %v, want %v", test.storedName, got, test.isSymlink)
		}
	}
}

func TestSymlinkStoredNameRoundTrip(t *testing.T) {
	for _, visibleName := range []string{"lib64", "a.b.c", "이름", SymlinkSuffix} {
		storedName := SymlinkStoredName(visibleName)

		got, isSymlink := SymlinkVisibleName(storedName)
		if !isSymlink {
			t.Errorf("SymlinkVisibleName(SymlinkStoredName(%q)) reports no symbolic link", visibleName)
			continue
		}

		if got != visibleName {
			t.Errorf("SymlinkVisibleName(SymlinkStoredName(%q)) = %q, want %q", visibleName, got, visibleName)
		}
	}
}

func TestResolveDirEntriesMapsSymlinks(t *testing.T) {
	entries := []*irodsclient_fs.Entry{
		newTestDirEntry(1, "lib"),
		newTestFileEntry(2, "pyvenv.cfg"),
		newTestFileEntry(3, "lib64"+SymlinkSuffix),
	}

	resolvedEntries, shadowedNames := ResolveDirEntries(entries)

	if len(shadowedNames) != 0 {
		t.Errorf("ResolveDirEntries reported shadowed names %v, want none", shadowedNames)
	}

	want := map[string]bool{"lib": false, "pyvenv.cfg": false, "lib64": true}
	if len(resolvedEntries) != len(want) {
		t.Fatalf("ResolveDirEntries returned %d entries, want %d", len(resolvedEntries), len(want))
	}

	for _, resolvedEntry := range resolvedEntries {
		isSymlink, ok := want[resolvedEntry.VisibleName]
		if !ok {
			t.Errorf("ResolveDirEntries returned unexpected name %q", resolvedEntry.VisibleName)
			continue
		}

		if resolvedEntry.IsSymlink != isSymlink {
			t.Errorf("entry %q has IsSymlink = %v, want %v", resolvedEntry.VisibleName, resolvedEntry.IsSymlink, isSymlink)
		}
	}
}

func TestResolveDirEntriesRealEntryWinsOverSymlink(t *testing.T) {
	// the same visible name is claimed by a real entry and by a symbolic link,
	// in an order that puts the link first
	entries := []*irodsclient_fs.Entry{
		newTestFileEntry(1, "lib64"+SymlinkSuffix),
		newTestDirEntry(2, "lib64"),
	}

	resolvedEntries, shadowedNames := ResolveDirEntries(entries)

	if len(resolvedEntries) != 1 {
		t.Fatalf("ResolveDirEntries returned %d entries, want 1", len(resolvedEntries))
	}

	resolvedEntry := resolvedEntries[0]
	if resolvedEntry.VisibleName != "lib64" || resolvedEntry.IsSymlink || resolvedEntry.Entry.ID != 2 {
		t.Errorf("ResolveDirEntries returned (%q, symlink=%v, id=%d), want the real entry (%q, symlink=false, id=2)", resolvedEntry.VisibleName, resolvedEntry.IsSymlink, resolvedEntry.Entry.ID, "lib64")
	}

	if len(shadowedNames) != 1 || shadowedNames[0] != "lib64"+SymlinkSuffix {
		t.Errorf("ResolveDirEntries reported shadowed names %v, want [%q]", shadowedNames, "lib64"+SymlinkSuffix)
	}
}

func TestResolveDirEntriesKeepsCollectionWithSuffix(t *testing.T) {
	// a symbolic link is always a data object, so a collection keeps its own name
	entries := []*irodsclient_fs.Entry{
		newTestDirEntry(1, "lib64"+SymlinkSuffix),
	}

	resolvedEntries, shadowedNames := ResolveDirEntries(entries)

	if len(shadowedNames) != 0 {
		t.Errorf("ResolveDirEntries reported shadowed names %v, want none", shadowedNames)
	}

	if len(resolvedEntries) != 1 {
		t.Fatalf("ResolveDirEntries returned %d entries, want 1", len(resolvedEntries))
	}

	if resolvedEntries[0].VisibleName != "lib64"+SymlinkSuffix || resolvedEntries[0].IsSymlink {
		t.Errorf("ResolveDirEntries returned (%q, symlink=%v), want (%q, symlink=false)", resolvedEntries[0].VisibleName, resolvedEntries[0].IsSymlink, "lib64"+SymlinkSuffix)
	}
}

func TestResolveDirEntriesKeepsSuffixOnlyName(t *testing.T) {
	entries := []*irodsclient_fs.Entry{
		newTestFileEntry(1, SymlinkSuffix),
	}

	resolvedEntries, _ := ResolveDirEntries(entries)

	if len(resolvedEntries) != 1 {
		t.Fatalf("ResolveDirEntries returned %d entries, want 1", len(resolvedEntries))
	}

	if resolvedEntries[0].VisibleName != SymlinkSuffix || resolvedEntries[0].IsSymlink {
		t.Errorf("ResolveDirEntries returned (%q, symlink=%v), want (%q, symlink=false)", resolvedEntries[0].VisibleName, resolvedEntries[0].IsSymlink, SymlinkSuffix)
	}
}

func TestResolveDirEntriesEmpty(t *testing.T) {
	resolvedEntries, shadowedNames := ResolveDirEntries(nil)

	if len(resolvedEntries) != 0 || len(shadowedNames) != 0 {
		t.Errorf("ResolveDirEntries(nil) = (%v, %v), want empty", resolvedEntries, shadowedNames)
	}
}
