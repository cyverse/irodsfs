package commons

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParsePoolServiceEndpoint(t *testing.T) {
	tests := []struct {
		endpoint       string
		expectedScheme string
		expectedAddr   string
		expectError    bool
	}{
		{"tcp://localhost:1247", "tcp", "localhost:1247", false},
		{"unix:///tmp/socket", "unix", "/tmp/socket", false},
		{"localhost:1247", "tcp", "localhost:1247", false},
		{"127.0.0.1:1247", "tcp", "127.0.0.1:1247", false},
		{"tcp://:1247", "tcp", ":1247", false},
		{"unix:/tmp/socket", "unix", "/tmp/socket", false},
		{"invalid://localhost:1247", "", "", true},
		{"", "", "", true},
	}

	for _, test := range tests {
		scheme, addr, err := ParsePoolServiceEndpoint(test.endpoint)
		t.Logf("Testing endpoint: %s -> scheme %q, addr %q", test.endpoint, scheme, addr)
		if test.expectError {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
			assert.Equal(t, test.expectedScheme, scheme)
			assert.Equal(t, test.expectedAddr, addr)
		}
	}
}

// The log file name carries the instance id, which is how a running mount is
// matched to its log - and, once it reaches the pool server, to the client id
// the server reports. Each config makes an id of its own, so the process that
// opens the log has to be the one that runs the config, not one that built a
// config of its own from the same flags.
func TestLogFileIsNamedAfterTheInstanceID(t *testing.T) {
	for _, test := range []struct {
		name       string
		foreground bool
		expected   string
	}{
		{"daemon", false, "irodsfs-instance-a.log"},
		{"foreground", true, "irodsfs-instance-a.log.fg"},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := NewDefaultConfig()
			config.DataRootPath = t.TempDir()
			config.InstanceID = "instance-a"

			writer, err := config.GetLogWriter(test.foreground)
			if err != nil {
				t.Fatalf("failed to open the log writer: %v", err)
			}

			if _, err := writer.Write([]byte("log line\n")); err != nil {
				t.Fatalf("failed to write to the log: %v", err)
			}
			if err := writer.Close(); err != nil {
				t.Fatalf("failed to close the log: %v", err)
			}

			if _, err := os.Stat(filepath.Join(config.DataRootPath, test.expected)); err != nil {
				t.Fatalf("expected the log at %q: %v", test.expected, err)
			}
		})
	}
}

// Two configs built the same way get two different instance ids, which is why
// the daemon process cannot name its log from a config of its own making
func TestEachDefaultConfigGetsItsOwnInstanceID(t *testing.T) {
	first := NewDefaultConfig()
	second := NewDefaultConfig()

	if first.InstanceID == "" {
		t.Fatal("a default config must have an instance id")
	}
	if first.InstanceID == second.InstanceID {
		t.Fatalf("two default configs share the instance id %q", first.InstanceID)
	}
}
