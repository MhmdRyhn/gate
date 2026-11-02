package configkit

import (
	"fmt"
	"path/filepath"
	"strings"
)

type Format string

const (
	JSON Format = "json"
	YAML Format = "yaml"
	TOML Format = "toml"
)

func (f Format) String() string {
	return string(f)
}

func (f Format) valid() bool {
	return f == JSON || f == YAML || f == TOML
}

// FormatFromPath infers the format from a file extension
func FormatFromPath(path string) (Format, error) {
	switch ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), ".")); ext {
	case "json":
		return JSON, nil
	case "yaml", "yml":
		return YAML, nil
	case "toml":
		return TOML, nil
	// NOTE: Add more supported extentions here.
	default:
		return "", fmt.Errorf("cannot infer config format from %q: unsupported extension %q", path, ext)
	}
}
