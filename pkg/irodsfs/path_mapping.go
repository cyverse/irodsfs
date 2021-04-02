package irodsfs

import (
	"fmt"
)

type PathMappingResourceType string

const (
	PathMappingFile      PathMappingResourceType = "file"
	PathMappingDirectory PathMappingResourceType = "dir"
)

// PathMapping ...
type PathMapping struct {
	IRODSPath      string                  `yaml:"irods_path"`
	MappingPath    string                  `yaml:"mapping_path"`
	ResourceType   PathMappingResourceType `yaml:"resource_type"`
	CreateDir      bool                    `yaml:"create_dir"`
	IgnoreNotExist bool                    `yaml:"ignore_not_exist"`
}

// NewPathMapping create a new PathMapping
func NewPathMapping(irodsPath string, mappingPath string, resourceType PathMappingResourceType, createDir bool, ignoreNotExist bool) *PathMapping {
	return &PathMapping{
		IRODSPath:      irodsPath,
		MappingPath:    mappingPath,
		ResourceType:   resourceType,
		CreateDir:      createDir,
		IgnoreNotExist: ignoreNotExist,
	}
}

// NewPathMappingForDir create a new PathMapping for mounting a directory
func NewPathMappingForDir(dirPath string, mountPath string, createDir bool) PathMapping {
	mapping := PathMapping{
		IRODSPath:      dirPath,
		MappingPath:    mountPath,
		ResourceType:   PathMappingDirectory,
		CreateDir:      createDir,
		IgnoreNotExist: false,
	}

	return mapping
}

// NewPathMappingForFile create a new PathMapping for mounting a file
func NewPathMappingForFile(filePath string, mountPath string, ignoreNotExist bool) PathMapping {
	mapping := PathMapping{
		IRODSPath:      filePath,
		MappingPath:    mountPath,
		ResourceType:   PathMappingFile,
		CreateDir:      false,
		IgnoreNotExist: ignoreNotExist,
	}

	return mapping
}

// ValidatePathMappings validates the path mappings given
func ValidatePathMappings(mappings []PathMapping) error {
	mappingDict := map[string]string{}

	for _, mapping := range mappings {
		if !IsAbsolutePath(mapping.IRODSPath) {
			return fmt.Errorf("IRODSPath given (%s) is not absolute path", mapping.IRODSPath)
		}

		if !IsAbsolutePath(mapping.MappingPath) {
			return fmt.Errorf("MappingPath given (%s) is not absolute path", mapping.MappingPath)
		}

		depth := GetPathDepth(mapping.MappingPath)
		if depth < 0 || depth > 1 {
			return fmt.Errorf("MappingPath given (%s) is too deep", mapping.MappingPath)
		}

		if _, ok := mappingDict[mapping.MappingPath]; ok {
			// exists
			return fmt.Errorf("MappingPath given (%s) cannot be used for multiple mappings", mapping.MappingPath)
		}

		mappingDict[mapping.MappingPath] = mapping.IRODSPath
	}

	if len(mappings) == 0 {
		return fmt.Errorf("No mapping is given")
	}
	return nil
}
