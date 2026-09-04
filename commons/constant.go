package commons

import "time"

const (
	DataRootPathFallback string = "/var/lib/irodsfs"

	ReadAheadMaxDefault int = 1024 * 128      // 128KB
	ReadWriteMaxDefault int = 1 * 1024 * 1024 // 1MB

	// not in-use
	FilesystemTimeout          time.Duration = 10 * time.Minute
	TCPBufferSizeDefault       int           = 4 * 1024 * 1024 // 4MB
	TCPBufferSizeStringDefault string        = "4MB"
	ConnectionMaxDefault       int           = 10

	ClientProgramName string = "irodsfs"
	FuseFSName        string = "irodsfs"
)
