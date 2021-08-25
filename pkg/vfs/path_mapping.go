package vfs

import (
	"fmt"

	"github.com/cyverse/irodsfs/pkg/utils"
)

// PathMappingResourceType determines the type of Path Mapping Entry
type PathMappingResourceType string

const (
	// PathMappingFile is for file entry
	PathMappingFile PathMappingResourceType = "file"
	// PathMappingDirectory is for directory entry
	PathMappingDirectory PathMappingResourceType = "dir"
)

// PathMapping defines a path mapping between iRODS DataObject/Collection and local file/directory
type PathMapping struct {
	IRODSPath      string                  `yaml:"irods_path"`
	MappingPath    string                  `yaml:"mapping_path"`
	ResourceType   PathMappingResourceType `yaml:"resource_type"`
	CreateDir      bool                    `yaml:"create_dir"`
	IgnoreNotExist bool                    `yaml:"ignore_not_exist"`
}

// Validate validates PathMapping
func (mapping *PathMapping) Validate() error {
	if !utils.IsAbsolutePath(mapping.IRODSPath) {
		return fmt.Errorf("IRODSPath given (%s) is not absolute path", mapping.IRODSPath)
	}

	if !utils.IsAbsolutePath(mapping.MappingPath) {
		return fmt.Errorf("MappingPath given (%s) is not absolute path", mapping.MappingPath)
	}

	depth := utils.GetPathDepth(mapping.MappingPath)
	if depth < 0 || depth > 1 {
		return fmt.Errorf("MappingPath given (%s) is too deep", mapping.MappingPath)
	}

	return nil
}

// ValidatePathMappings validates the path mappings given
func ValidatePathMappings(mappings []PathMapping) error {
	mappingDict := map[string]string{}

	for _, mapping := range mappings {
		err := mapping.Validate()
		if err != nil {
			return err
		}

		// check duplicated path mappings
		if _, ok := mappingDict[mapping.MappingPath]; ok {
			// exists
			return fmt.Errorf("MappingPath given (%s) cannot be used for multiple mappings", mapping.MappingPath)
		}

		mappingDict[mapping.MappingPath] = mapping.IRODSPath
	}

	if len(mappings) == 0 {
		return fmt.Errorf("no path mapping is given")
	}
	return nil
}
