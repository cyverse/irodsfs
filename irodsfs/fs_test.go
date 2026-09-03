package irodsfs

import (
	"reflect"
	"testing"

	"github.com/cyverse/irodsfs/commons"
	log "github.com/sirupsen/logrus"
)

func newTestIRODSFS(config *commons.Config) *IRODSFS {
	return &IRODSFS{
		config: config,
		logger: log.WithFields(log.Fields{}),
	}
}

func TestGetFuseOptionsAppliesConfiguredFuseOptions(t *testing.T) {
	config := &commons.Config{
		UID:         1002,
		GID:         1002,
		FuseOptions: []string{"allow_other", "default_permissions"},
	}
	fs := newTestIRODSFS(config)

	options := fs.GetFuseOptions()

	if options.UID != 1002 || options.GID != 1002 {
		t.Errorf("UID/GID = %d/%d, want 1002/1002", options.UID, options.GID)
	}
	want := []string{"allow_other", "default_permissions"}
	if !reflect.DeepEqual(options.MountOptions.Options, want) {
		t.Errorf("MountOptions.Options = %v, want %v (FuseOptions must actually reach the mount)", options.MountOptions.Options, want)
	}
}

func TestGetFuseOptionsCombinesReadonlyAndFuseOptions(t *testing.T) {
	config := &commons.Config{
		Readonly:    true,
		FuseOptions: []string{"allow_other"},
	}
	fs := newTestIRODSFS(config)

	options := fs.GetFuseOptions()

	want := []string{"ro", "allow_other"}
	if !reflect.DeepEqual(options.MountOptions.Options, want) {
		t.Errorf("MountOptions.Options = %v, want %v", options.MountOptions.Options, want)
	}
}

func TestGetFuseOptionsWithNoFuseOptionsConfigured(t *testing.T) {
	fs := newTestIRODSFS(&commons.Config{})

	options := fs.GetFuseOptions()

	if len(options.MountOptions.Options) != 0 {
		t.Errorf("MountOptions.Options = %v, want empty when none are configured", options.MountOptions.Options)
	}
}
