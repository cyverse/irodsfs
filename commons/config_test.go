package commons

import (
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
