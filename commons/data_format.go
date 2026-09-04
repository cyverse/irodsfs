package commons

import (
	"bytes"
	"encoding/json"

	"gopkg.in/yaml.v3"
)

type DataFormat string

const (
	FormatJSON    DataFormat = "JSON"
	FormatYAML    DataFormat = "YAML"
	FormatUnknown DataFormat = "Unknown"
)

// DetectFormat checks format
func DetectFormat(data []byte) DataFormat {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return FormatUnknown
	}

	// 1. JSON
	if json.Valid(trimmed) {
		return FormatJSON
	}

	// 2. YAML
	var node yaml.Node
	if err := yaml.Unmarshal(trimmed, &node); err == nil {
		if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
			rootKind := node.Content[0].Kind
			if rootKind == yaml.MappingNode || rootKind == yaml.SequenceNode {
				return FormatYAML
			}
		}
	}

	return FormatUnknown
}
