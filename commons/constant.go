package commons

import "time"

const (
	ClientProgramName string = "irodsfs"
	FuseFSName        string = "irodsfs"

	IRODSEnvironmentFileEnvKey string = "IRODS_ENVIRONMENT_FILE"

	ReadAheadMaxDefault        int           = 1024 * 128 // 128KB
	FilesystemTimeout          time.Duration = 10 * time.Minute
	ConnectionMaxDefault       int           = 10
	TCPBufferSizeDefault       int           = 4 * 1024 * 1024 // 4MB
	TCPBufferSizeStringDefault string        = "4MB"
	ProfileServicePortDefault  int           = 11021
)
