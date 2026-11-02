package configkit

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	_ "github.com/spf13/viper/remote"
)

// Source is a file, Consul key or AWS parameter/configuration/secret that
// produces a (possibly nested) map of settings.
type Source interface {
	// String describes the source. It is used in error messages.
	String() string
	// Load reads the source and returns its settings.
	Load() (map[string]any, error)
}

// decode parses raw bytes of the given format into a settings map.
func decode(data []byte, format Format) (map[string]any, error) {
	if !format.valid() {
		return nil, fmt.Errorf("unsupported config format %q", format)
	}
	v := viper.New()
	v.SetConfigType(format.String())
	if err := v.ReadConfig(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	return v.AllSettings(), nil
}

// ---- File ----

type fileSource struct {
	path   string
	format Format
	err    error
}

// NewFile reads a local file. The format is inferred from its extension.
func NewFile(path string) Source {
	format, err := FormatFromPath(path)
	return &fileSource{path: path, format: format, err: err}
}

// NewFileAs reads a local file with an explicit format, regardless of its
// extension.
func NewFileAs(path string, format Format) Source {
	return &fileSource{path: path, format: format}
}

// NewFiles is a shorthand for several File sources in the same directory.
// Each name must include its extension, e.g. "config.yaml".
func NewFiles(dir string, names ...string) []Source {
	sources := make([]Source, 0, len(names))
	for _, name := range names {
		sources = append(sources, NewFile(filepath.Join(dir, name)))
	}
	return sources
}

func (s *fileSource) String() string {
	return "file " + s.path
}

func (s *fileSource) Load() (map[string]any, error) {
	if s.err != nil {
		return nil, s.err
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	return decode(data, s.format)
}

// ---- Optional ----

type optionalSource struct {
	src Source
}

// NewOptional wraps a source whose absence is not an error: when it fails
// because its file (or key) does not exist, it contributes no settings and
// the remaining sources still load, e.g. a local override file that is only
// present on some machines.
func NewOptional(src Source) Source {
	return &optionalSource{src: src}
}

func (s *optionalSource) String() string {
	return "optional " + s.src.String()
}

func (s *optionalSource) Load() (map[string]any, error) {
	values, err := s.src.Load()
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil // the Loader skips nil settings
	}
	return values, err
}

// ---- Consul ----

type consulSource struct {
	endpoint string
	key      string
	format   Format
}

// NewConsul reads a single key from Consul KV, e.g.
// NewConsul("http://consul:8500", "gate/config.yaml", configkit.YAML).
func NewConsul(endpoint, key string, format Format) Source {
	return &consulSource{endpoint: endpoint, key: key, format: format}
}

func (s *consulSource) String() string {
	return fmt.Sprintf("consul %s/%s", s.endpoint, s.key)
}

func (s *consulSource) Load() (map[string]any, error) {
	if s.endpoint == "" || s.key == "" {
		return nil, errors.New("consul endpoint and key must not be empty")
	}
	if !s.format.valid() {
		return nil, fmt.Errorf("unsupported config format %q", s.format)
	}
	v := viper.New()
	v.SetConfigType(s.format.String())
	if err := v.AddRemoteProvider("consul", s.endpoint, s.key); err != nil {
		return nil, err
	}
	if err := v.ReadRemoteConfig(); err != nil {
		return nil, err
	}
	return v.AllSettings(), nil
}
