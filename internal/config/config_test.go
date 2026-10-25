package config

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type mapSource map[string]string

func (m mapSource) Name() string                                    { return "map" }
func (m mapSource) Load(context.Context) (map[string]string, error) { return m, nil }

func required() mapSource {
	return mapSource{"DATABASE_URL": "postgres://u:p@h/db", "JWT_ISSUER": "https://auth.example.com", "JWT_SIGNING_KEY": "k"}
}

func TestLoadDefaultsAndPrecedence(t *testing.T) {
	cfg, err := Load(context.Background(), required(), mapSource{"HTTP_ADDR": ":9000", "HTTP_TRUSTED_PROXIES": "10.0.0.0/8,172.16.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Addr != ":9000" || cfg.Auth.AccessTokenTTL != 15*time.Minute || len(cfg.HTTP.TrustedProxies) != 2 {
		t.Errorf("unexpected config: %+v", cfg.HTTP)
	}
	if cfg.Database.URL.Value() != "postgres://u:p@h/db" {
		t.Error("secret value not decoded")
	}
}

func TestLoadValidation(t *testing.T) {
	if _, err := Load(context.Background(), mapSource{}); err == nil {
		t.Error("missing required keys accepted")
	}
	bad := required()
	bad["ACCESS_TOKEN_TTL"] = "2h"
	if _, err := Load(context.Background(), bad); err == nil {
		t.Error("long access token TTL accepted")
	}
}

func TestSecretIsRedacted(t *testing.T) {
	s := Secret("hunter2")
	b, _ := json.Marshal(struct{ S Secret }{s})
	for _, out := range []string{s.String(), fmt.Sprintf("%v %s %#v", s, s, s), string(b)} {
		if strings.Contains(out, "hunter2") {
			t.Errorf("secret leaked: %s", out)
		}
	}
}

func TestEnvSourcePrefix(t *testing.T) {
	t.Setenv("RBACTEST_HTTP_ADDR", ":1")
	kv, _ := EnvSource{Prefix: "RBACTEST_"}.Load(context.Background())
	if kv["HTTP_ADDR"] != ":1" || len(kv) != 1 {
		t.Errorf("got %v", kv)
	}
}

func TestDirSourceKubernetesLayout(t *testing.T) {
	// Kubernetes mounts: key -> ..data/key symlink, plus hidden bookkeeping.
	dir := t.TempDir()
	data := filepath.Join(dir, "..data")
	os.Mkdir(data, 0o700)
	os.WriteFile(filepath.Join(data, "database-url"), []byte("postgres://x\n"), 0o600)
	os.Symlink(filepath.Join(data, "database-url"), filepath.Join(dir, "database-url"))

	kv, err := DirSource{Path: dir}.Load(context.Background())
	if err != nil || kv["DATABASE_URL"] != "postgres://x" || len(kv) != 1 {
		t.Errorf("got %v, %v", kv, err)
	}
	if kv, err := (DirSource{Path: filepath.Join(dir, "missing")}).Load(context.Background()); err != nil || len(kv) != 0 {
		t.Errorf("missing dir: %v, %v", kv, err)
	}
}

func TestParseDotenv(t *testing.T) {
	kv, err := parseDotenv(strings.NewReader("# c\nexport A=1\nB=\"two words\"\nc.d='x=y'\n\n"))
	if err != nil || kv["A"] != "1" || kv["B"] != "two words" || kv["C_D"] != "x=y" {
		t.Errorf("got %v, %v", kv, err)
	}
}

func TestConsulSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/kv/rbac" || r.Header.Get("X-Consul-Token") != "tok" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		v := base64.StdEncoding.EncodeToString([]byte(":7000"))
		fmt.Fprintf(w, `[{"Key":"rbac/","Value":null},{"Key":"rbac/http_addr","Value":%q}]`, v)
	}))
	defer srv.Close()

	src, err := ParseSource("consul:" + srv.URL + "/rbac")
	if err != nil {
		t.Fatal(err)
	}
	src.(*ConsulSource).Token = "tok"
	kv, err := src.Load(context.Background())
	if err != nil || kv["HTTP_ADDR"] != ":7000" {
		t.Errorf("got %v, %v", kv, err)
	}
}

func TestHTTPJSONSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"HTTP_ADDR":":6000","DB_MAX_OPEN_CONNS":50,"PUBLIC_REGISTRATION_ENABLED":false}`)
	}))
	defer srv.Close()

	src, _ := ParseSource("http:" + srv.URL)
	kv, err := src.Load(context.Background())
	if err != nil || kv["DB_MAX_OPEN_CONNS"] != "50" || kv["PUBLIC_REGISTRATION_ENABLED"] != "false" {
		t.Errorf("got %v, %v", kv, err)
	}
}

func TestParseSourceErrors(t *testing.T) {
	for _, spec := range []string{"vault", "dir:", "file:", "consul:nope", "http:ftp://x"} {
		if _, err := ParseSource(spec); err == nil {
			t.Errorf("%q accepted", spec)
		}
	}
}
