package configkit

import (
	"errors"
	"fmt"

	"github.com/spf13/viper"
)

// ErrKeyNotFound is returned when a requested key is absent from the config.
var ErrKeyNotFound = errors.New("config key not found")

// Validator can be implemented by config structs. Validate is called right
// after a successful decode.
type Validator interface {
	Validate() error
}

// Config is the merged result of a Loader. It is independent of the global
// viper instance.
type Config struct {
	v      *viper.Viper
	strict bool
}

// Has reports whether the key is set by any source, default or env var.
func (c *Config) Has(key string) bool {
	return c.v.IsSet(key)
}

// Get returns the raw value of a key, or nil.
func (c *Config) Get(key string) any {
	return c.v.Get(key)
}

// AllSettings returns the whole merged config as a nested map.
func (c *Config) AllSettings() map[string]any {
	return c.v.AllSettings()
}

// Viper exposes the underlying viper instance for anything not covered here
// (GetString, GetDuration, ...).
func (c *Config) Viper() *viper.Viper {
	return c.v
}

// Unmarshal decodes the whole config into target (a pointer to a struct
// with `mapstructure` tags).
func (c *Config) Unmarshal(target any) error {
	if err := c.v.Unmarshal(target, c.decoderOptions()...); err != nil {
		return fmt.Errorf("configkit: decode config: %w", err)
	}
	return validate("", target)
}

// UnmarshalKey decodes one section into target. Unlike viper.UnmarshalKey
// it returns ErrKeyNotFound when the section is missing instead of silently
// leaving target zero-valued. This must be defined by `decoderOptions`.
func (c *Config) UnmarshalKey(key string, target any) error {
	if !c.v.IsSet(key) {
		return fmt.Errorf("configkit: %q: %w", key, ErrKeyNotFound)
	}
	// viper.UnmarshalKey reads the raw nested map, which skips env overrides
	// and defaults of nested keys. AllSettings resolves every leaf, so decode
	// from a snapshot of it instead.
	resolved := viper.New()
	if err := resolved.MergeConfigMap(c.v.AllSettings()); err != nil {
		return fmt.Errorf("configkit: resolve %q: %w", key, err)
	}
	if err := resolved.UnmarshalKey(key, target, c.decoderOptions()...); err != nil {
		return fmt.Errorf("configkit: decode %q: %w", key, err)
	}
	return validate(key, target)
}

// MergeIntoGlobal copies the merged settings into the global viper
// instance, for code that still reads config via viper.Get* / viper.UnmarshalKey.
func (c *Config) MergeIntoGlobal() error {
	return viper.MergeConfigMap(c.v.AllSettings())
}

func (c *Config) decoderOptions() []viper.DecoderConfigOption {
	if !c.strict {
		return nil
	}
	return []viper.DecoderConfigOption{
		// func(dc *mapstructure.DecoderConfig) { dc.ErrorUnused = true },
	}
}

// validate runs target's Validate method, if it has one.
func validate(key string, target any) error {
	validator, ok := target.(Validator)
	if !ok {
		return nil
	}
	if err := validator.Validate(); err != nil {
		if key == "" {
			return fmt.Errorf("configkit: invalid config: %w", err)
		}
		return fmt.Errorf("configkit: invalid %q: %w", key, err)
	}
	return nil
}

// Bind decodes a section into a new value of type T.
//
//	redis, err := configkit.Bind[config.Redis](cfg, "redis")
func Bind[T any](c *Config, key string) (*T, error) {
	target := new(T)
	if err := c.UnmarshalKey(key, target); err != nil {
		return nil, err
	}
	return target, nil
}

// MustBind is like Bind but panics on error. Intended for program start-up.
func MustBind[T any](c *Config, key string) *T {
	target, err := Bind[T](c, key)
	if err != nil {
		panic(err)
	}
	return target
}
