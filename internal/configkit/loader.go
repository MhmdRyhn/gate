package configkit

import (
	"fmt"

	"github.com/spf13/viper"
)

func New(sources ...Source) *Loader {
	return &Loader{
		sources:  sources,
		defaults: map[string]any{},
	}
}

// Loader collects sources and merges them into a Config.
// Sources are merged in the order they were added. Later sources
// override keys of earlier ones (nested maps are merged deeply).
type Loader struct {
	sources  []Source
	defaults map[string]any
}

func (l *Loader) Add(sources ...Source) *Loader {
	l.sources = append(l.sources, sources...)
	return l
}

// Default sets a fallback value for a key (dot notation, e.g. "redis.port")
func (l *Loader) Default(key string, value any) *Loader {
	l.defaults[key] = value
	return l
}

// Load reads every source and returns the merged Config. It stops at the
// first failing source and reports which one failed.
func (l *Loader) Load() (*Config, error) {
	v := viper.New()
	for key, value := range l.defaults {
		v.SetDefault(key, value)
	}

	for i, src := range l.sources {
		values, err := src.Load()
		if err != nil {
			return nil, fmt.Errorf("configkit: source #%d (%s): %w", i+1, src, err)
		}
		if values == nil {
			continue
		}
		if err := v.MergeConfigMap(values); err != nil {
			return nil, fmt.Errorf("configkit: merge source #%d (%s): %w", i+1, src, err)
		}
	}

	return &Config{v: v}, nil
}

// MustLoad is like Load but panics on error. Intended for program start-up.
func (l *Loader) MustLoad() *Config {
	cfg, err := l.Load()
	if err != nil {
		panic(err)
	}
	return cfg
}
