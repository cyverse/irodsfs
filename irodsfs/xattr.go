package irodsfs

func IsUnhandledAttr(attr string) bool {
	switch attr {
	// we suppress attr "system.posix_acl_access" as it may cause wrong permission check
	case "system.posix_acl_access":
		return true
	case "security.selinux":
		return true
	default:
		return false
	}
}
