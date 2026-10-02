package commons

const (
	DataRootPathFallback string = "/var/lib/irodsfs"

	ReadAheadMaxDefault int = 1024 * 128      // 128KB
	ReadWriteMaxDefault int = 1 * 1024 * 1024 // 1MB

	ClientProgramName string = "irodsfs"
	FuseFSName        string = "irodsfs"
)
