package irodsfs

import "strings"

// IsUnhandledAttr checks if given attr is ignored
func IsUnhandledAttr(attr string) bool {
	// overlay fs related attributes
	if strings.HasPrefix(attr, "trusted.overlay.") {
		return true
	}

	switch attr {
	// we suppress attr "system.posix_acl_access" as it may cause wrong permission check
	case "system.posix_acl_access", "system.posix_acl_default", "system.dos_attrib":
		return true
	case "security.selinux", "security.apparmor":
		return true
	case "user.xdg.origin.url", "user.xdg.referrer.url":
		return true
	default:
		return false
	}
}
