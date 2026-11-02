package config

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/MhmdRyhn/gate/internal/configkit"
)

// documentTimeout bounds a document read. It exceeds configkit's own AWS
// timeout, so AWS errors are reported rather than cut short.
const documentTimeout = 20 * time.Second

// DocumentSource reads structured configuration documents (YAML, JSON or
// TOML, each in its own format) through internal/configkit: local files,
// Consul keys, SSM parameters, AppConfig profiles or Secrets Manager
// secrets. The documents are merged in order by configkit (later ones
// override keys of earlier ones). Nested keys are flattened into the
// canonical flat keys, joined with "_":
//
//	database:                       DATABASE_URL=postgres://...
//	  url: postgres://...      ->   HTTP_ADDR=:8080
//	http:                           HTTP_TRUSTED_PROXIES=10.0.0.0/8,172.16.0.1
//	  addr: ":8080"
//	  trusted_proxies: [10.0.0.0/8, 172.16.0.1]
//
// so a document, environment variables and secret files configure the same
// settings and can be layered in any order. Flat keys (DATABASE_URL: ...)
// work as well. Lists become comma-separated values.
type DocumentSource struct {
	Sources []configkit.Source
}

func (s DocumentSource) Name() string {
	names := make([]string, len(s.Sources))
	for i, src := range s.Sources {
		names[i] = src.String()
	}
	return strings.Join(names, " + ")
}

// Every key in a config document must be a known setting (see strictSource).
func (DocumentSource) strictKeys() {}

func (s DocumentSource) Load(ctx context.Context) (map[string]string, error) {
	type result struct {
		cfg *configkit.Config
		err error
	}
	// configkit has no context support; bound the (possibly remote) read
	// so startup cannot hang.
	done := make(chan result, 1)
	go func() {
		cfg, err := configkit.New(s.Sources...).Load()
		done <- result{cfg, err}
	}()
	var r result
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(documentTimeout):
		return nil, fmt.Errorf("no response within %s", documentTimeout)
	case r = <-done:
	}
	if r.err != nil {
		return nil, r.err
	}
	out := map[string]string{}
	if err := flatten("", r.cfg.AllSettings(), out); err != nil {
		return nil, err
	}
	return out, nil
}

// flatten writes every leaf of m into out under its canonical key. Two
// spellings of the same key (e.g. nested database.url and flat
// DATABASE_URL) in one document are rejected rather than resolved at random.
func flatten(prefix string, m map[string]any, out map[string]string) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		path := k
		if prefix != "" {
			path = prefix + "_" + k
		}
		if nested, ok := m[k].(map[string]any); ok {
			if err := flatten(path, nested, out); err != nil {
				return err
			}
			continue
		}
		value, ok, err := leafString(m[k])
		if err != nil {
			return fmt.Errorf("key %s: %w", path, err)
		}
		if !ok {
			continue
		}
		key := NormalizeKey(path)
		if _, dup := out[key]; dup {
			return fmt.Errorf("key %s is set twice in the same document", key)
		}
		out[key] = value
	}
	return nil
}

// leafString converts a document value to the string form the decoder
// parses. ok is false for null values, which are skipped.
func leafString(v any) (s string, ok bool, err error) {
	if items, isList := v.([]any); isList {
		parts := make([]string, 0, len(items))
		for _, item := range items {
			p, ok, err := scalarString(item)
			if err != nil || !ok {
				return "", false, errors.New("lists may only contain scalar values")
			}
			parts = append(parts, p)
		}
		return strings.Join(parts, ","), true, nil
	}
	return scalarString(v)
}

// scalarString formats a decoded YAML/JSON scalar. Floats use plain
// notation: JSON numbers decode as float64, and fmt.Sprint(1048576.0) would
// give "1.048576e+06", which integer settings cannot parse.
func scalarString(v any) (string, bool, error) {
	switch v := v.(type) {
	case nil:
		return "", false, nil
	case string:
		return v, true, nil
	case bool:
		return strconv.FormatBool(v), true, nil
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64), true, nil
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32), true, nil
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprint(v), true, nil
	case time.Time: // YAML timestamps
		return v.Format(time.RFC3339Nano), true, nil
	default:
		return "", false, fmt.Errorf("unsupported value of type %T", v)
	}
}
