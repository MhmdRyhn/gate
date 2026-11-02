package configkit

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type redisConf struct {
	Host string `mapstructure:"host"`
	Port int    `mapstructure:"port"`
}

func (r *redisConf) Validate() error {
	if r.Host == "" {
		return errors.New("host is required")
	}
	return nil
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestMergeOrderAndBind(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "base.yaml", "redis:\n  host: localhost\n  port: 6379\n")
	writeFile(t, dir, "override.json", `{"redis": {"port": 6380}}`)

	cfg, err := New(NewFiles(dir, "base.yaml", "override.json")...).Load()
	if err != nil {
		t.Fatal(err)
	}
	r, err := Bind[redisConf](cfg, "redis")
	if err != nil {
		t.Fatal(err)
	}
	if r.Host != "localhost" || r.Port != 6380 {
		t.Fatalf("unexpected merge result: %+v", r)
	}
}

func TestNewFileAs(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.conf", "redis:\n  host: h\n")

	cfg := New(NewFileAs(filepath.Join(dir, "config.conf"), YAML)).MustLoad()
	if r := MustBind[redisConf](cfg, "redis"); r.Host != "h" {
		t.Fatalf("unexpected result: %+v", r)
	}
}

func TestMissingKeyAndValidation(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.yaml", "redis:\n  port: 1\n")
	cfg := New(NewFile(filepath.Join(dir, "config.yaml"))).MustLoad()

	if _, err := Bind[redisConf](cfg, "cache"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("expected ErrKeyNotFound, got %v", err)
	}
	if _, err := Bind[redisConf](cfg, "redis"); err == nil {
		t.Fatal("expected validation error")
	}
}

func TestFileErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := New(NewFile(filepath.Join(dir, "missing.yaml"))).Load(); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected not-exist error, got %v", err)
	}
	if _, err := New(NewFile(filepath.Join(dir, "config.ini"))).Load(); err == nil {
		t.Fatal("expected unsupported extension error")
	}
}

func TestConsulValidation(t *testing.T) {
	if _, err := New(NewConsul("", "key", YAML)).Load(); err == nil {
		t.Fatal("expected empty endpoint error")
	}
	if _, err := New(NewConsul("http://localhost:8500", "key", "ini")).Load(); err == nil {
		t.Fatal("expected unsupported format error")
	}
}

func TestDefaults(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "config.yaml", "redis:\n  host: h\n")

	cfg := New(NewFile(filepath.Join(dir, "config.yaml"))).
		Default("redis.port", 6379).
		MustLoad()
	if r := MustBind[redisConf](cfg, "redis"); r.Port != 6379 {
		t.Fatalf("default not applied: %+v", r)
	}
}

func TestOptional(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "base.yaml", "redis:\n  host: h\n  port: 1\n")
	writeFile(t, dir, "override.toml", "[redis]\nport = 2\n")

	cfg, err := New(
		NewFile(filepath.Join(dir, "base.yaml")),
		NewOptional(NewFile(filepath.Join(dir, "missing.json"))),
		NewFile(filepath.Join(dir, "override.toml")),
	).Load()
	if err != nil {
		t.Fatal(err)
	}
	if r := MustBind[redisConf](cfg, "redis"); r.Host != "h" || r.Port != 2 {
		t.Fatalf("unexpected result: %+v", r)
	}
	// Only absence is tolerated: an unreadable document still fails.
	writeFile(t, dir, "broken.json", "{not json")
	if _, err := New(NewOptional(NewFile(filepath.Join(dir, "broken.json")))).Load(); err == nil {
		t.Fatal("invalid optional file accepted")
	}
}
