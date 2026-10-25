package config

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxFileValueBytes caps a single value read from disk, to fail fast on a
// mis-mounted volume instead of loading huge files into memory.
const maxFileValueBytes = 1 << 20

// EnvSource reads the process environment. With a Prefix, only variables
// starting with it are used and the prefix is stripped ("RBAC_HTTP_ADDR"
// with prefix "RBAC_" yields "HTTP_ADDR").
type EnvSource struct {
	Prefix string
}

func (s EnvSource) Name() string { return "env" }

func (s EnvSource) Load(context.Context) (map[string]string, error) {
	out := map[string]string{}
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if s.Prefix != "" {
			var ok bool
			if k, ok = strings.CutPrefix(k, s.Prefix); !ok {
				continue
			}
		}
		out[NormalizeKey(k)] = v
	}
	return out, nil
}

// DirSource reads one value per file, the file name being the key. This is
// the layout of Kubernetes ConfigMap and Secret volumes and Docker/Compose
// secrets (/run/secrets). Hidden entries (Kubernetes' "..data" bookkeeping)
// are skipped, symlinks are followed and one trailing newline is trimmed.
// A missing directory yields no values so optional mounts can be listed.
type DirSource struct {
	Path string
}

func (s DirSource) Name() string { return "dir:" + s.Path }

func (s DirSource) Load(context.Context) (map[string]string, error) {
	entries, err := os.ReadDir(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		p := filepath.Join(s.Path, e.Name())
		info, err := os.Stat(p) // follows symlinks
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			continue
		}
		if info.Size() > maxFileValueBytes {
			return nil, fmt.Errorf("%s: value larger than %d bytes", p, maxFileValueBytes)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		v := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
		out[NormalizeKey(e.Name())] = v
	}
	return out, nil
}

// DotenvSource reads KEY=VALUE lines from a file, typically for local
// development. Blank lines, "#" comments and an "export " prefix are
// ignored; values may be wrapped in single or double quotes. A missing file
// yields no values.
type DotenvSource struct {
	Path string
}

func (s DotenvSource) Name() string { return "file:" + s.Path }

func (s DotenvSource) Load(context.Context) (map[string]string, error) {
	f, err := os.Open(s.Path)
	if errors.Is(err, fs.ErrNotExist) {
		return map[string]string{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseDotenv(io.LimitReader(f, maxFileValueBytes))
}

func parseDotenv(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected KEY=VALUE", n)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		out[NormalizeKey(k)] = v
	}
	return out, sc.Err()
}
