package configkit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appconfigdata"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
)

// ---- fakes ----

type fakeSSM struct {
	params map[string]string // name -> value
	calls  [][]string
}

func (f *fakeSSM) GetParameters(_ context.Context, in *ssm.GetParametersInput, _ ...func(*ssm.Options)) (*ssm.GetParametersOutput, error) {
	if len(in.Names) > ssmMaxNamesPerCall {
		return nil, fmt.Errorf("too many names: %d", len(in.Names))
	}
	if !aws.ToBool(in.WithDecryption) {
		return nil, errors.New("WithDecryption must be set for SecureString parameters")
	}
	f.calls = append(f.calls, in.Names)
	out := &ssm.GetParametersOutput{}
	for _, requested := range in.Names {
		name, selector, _ := strings.Cut(requested, ":")
		value, ok := f.params[name]
		if !ok {
			out.InvalidParameters = append(out.InvalidParameters, requested)
			continue
		}
		p := ssmtypes.Parameter{Name: aws.String(name), Value: aws.String(value), ARN: aws.String("arn:aws:ssm:eu-west-1:1:parameter" + name)}
		if selector != "" {
			p.Selector = aws.String(":" + selector)
		}
		out.Parameters = append(out.Parameters, p)
	}
	return out, nil
}

type fakeAppConfig struct {
	content []byte
	session string
}

func (f *fakeAppConfig) StartConfigurationSession(_ context.Context, in *appconfigdata.StartConfigurationSessionInput, _ ...func(*appconfigdata.Options)) (*appconfigdata.StartConfigurationSessionOutput, error) {
	f.session = aws.ToString(in.ApplicationIdentifier) + "/" + aws.ToString(in.EnvironmentIdentifier) + "/" + aws.ToString(in.ConfigurationProfileIdentifier)
	return &appconfigdata.StartConfigurationSessionOutput{InitialConfigurationToken: aws.String("token-1")}, nil
}

func (f *fakeAppConfig) GetLatestConfiguration(_ context.Context, in *appconfigdata.GetLatestConfigurationInput, _ ...func(*appconfigdata.Options)) (*appconfigdata.GetLatestConfigurationOutput, error) {
	if aws.ToString(in.ConfigurationToken) != "token-1" {
		return nil, errors.New("configuration token from the session not used")
	}
	return &appconfigdata.GetLatestConfigurationOutput{Configuration: f.content, NextPollConfigurationToken: aws.String("token-2")}, nil
}

type fakeSecrets struct {
	out *secretsmanager.GetSecretValueOutput
	id  string
}

func (f *fakeSecrets) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	f.id = aws.ToString(in.SecretId)
	return f.out, nil
}

// ---- SSM ----

func TestSSMParametersMergeInOrder(t *testing.T) {
	client := &fakeSSM{params: map[string]string{
		"/app/base": "redis:\n  host: localhost\n  port: 6379\n",
		"/app/prod": "redis:\n  port: 6380\n",
	}}
	src := NewSSMParameters(SSMParameter{Name: "/app/base", Format: YAML}, SSMParameter{Name: "/app/prod", Format: YAML}).(*ssmSource)
	src.client = client

	cfg, err := New(src).Load()
	if err != nil {
		t.Fatal(err)
	}
	r := MustBind[redisConf](cfg, "redis")
	if r.Host != "localhost" || r.Port != 6380 {
		t.Fatalf("later parameter should override earlier: %+v", r)
	}
}

func TestSSMParametersMixedFormats(t *testing.T) {
	// One batched call; each parameter decoded with its own format.
	client := &fakeSSM{params: map[string]string{
		"/app/base":  "redis:\n  host: localhost\n  port: 6379\n",
		"/app/db":    `{"redis": {"port": 6380}}`,
		"/app/local": "[redis]\nhost = \"cache\"\n",
	}}
	src := NewSSMParameters(
		SSMParameter{Name: "/app/base", Format: YAML},
		SSMParameter{Name: "/app/db", Format: JSON},
		SSMParameter{Name: "/app/local", Format: TOML},
	).(*ssmSource)
	src.client = client

	cfg, err := New(src).Load()
	if err != nil {
		t.Fatal(err)
	}
	if r := MustBind[redisConf](cfg, "redis"); r.Host != "cache" || r.Port != 6380 {
		t.Fatalf("unexpected merge of yaml+json+toml: %+v", r)
	}
	if len(client.calls) != 1 {
		t.Errorf("expected one batched call, got %d", len(client.calls))
	}
}

func TestSSMParametersBatchesAndSelectors(t *testing.T) {
	params := map[string]string{}
	list := []SSMParameter{}
	for i := range 23 { // more than three GetParameters calls' worth
		name := fmt.Sprintf("/app/p%02d", i)
		params[name] = fmt.Sprintf(`{"k%02d": %d}`, i, i)
		list = append(list, SSMParameter{Name: name, Format: JSON})
	}
	list = append(list, SSMParameter{Name: "/app/p00:2", Format: JSON}) // a version selector
	client := &fakeSSM{params: params}
	src := NewSSMParameters(list...).(*ssmSource)
	src.client = client

	cfg, err := New(src).Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(client.calls) != 3 {
		t.Errorf("expected 3 batched calls, got %d", len(client.calls))
	}
	if cfg.Get("k22") != float64(22) && cfg.Get("k22") != 22 {
		t.Errorf("k22 = %v", cfg.Get("k22"))
	}
}

func TestSSMParametersErrors(t *testing.T) {
	src := NewSSMParameters(SSMParameter{Name: "/app/base", Format: YAML}, SSMParameter{Name: "/app/missing", Format: YAML}).(*ssmSource)
	src.client = &fakeSSM{params: map[string]string{"/app/base": "a: 1"}}
	if _, err := New(src).Load(); err == nil || !strings.Contains(err.Error(), "/app/missing") {
		t.Errorf("missing parameter not reported: %v", err)
	}

	bad := NewSSMParameters(SSMParameter{Name: "/app/bad", Format: YAML}).(*ssmSource)
	bad.client = &fakeSSM{params: map[string]string{"/app/bad": "a: [unclosed"}}
	if _, err := New(bad).Load(); err == nil || !strings.Contains(err.Error(), "/app/bad") {
		t.Errorf("invalid document not reported with its parameter: %v", err)
	}

	if _, err := New(NewSSMParameters()).Load(); err == nil {
		t.Error("empty parameter list accepted")
	}
	if _, err := New(NewSSMParameters(SSMParameter{Name: "/x", Format: "ini"})).Load(); err == nil {
		t.Error("unsupported format accepted")
	}
	if _, err := New(NewSSMParameters(SSMParameter{Format: YAML})).Load(); err == nil {
		t.Error("empty parameter name accepted")
	}
}

// ---- AppConfig ----

func TestAppConfigTOML(t *testing.T) {
	client := &fakeAppConfig{content: []byte("[redis]\nhost = \"cache\"\nport = 6390\n")}
	src := NewAppConfig("gate", "prod", "main", TOML).(*appConfigSource)
	src.client = client

	cfg, err := New(src).Load()
	if err != nil {
		t.Fatal(err)
	}
	if r := MustBind[redisConf](cfg, "redis"); r.Host != "cache" || r.Port != 6390 {
		t.Fatalf("unexpected result: %+v", r)
	}
	if client.session != "gate/prod/main" {
		t.Errorf("session identifiers = %q", client.session)
	}
}

func TestAppConfigErrors(t *testing.T) {
	empty := NewAppConfig("gate", "prod", "main", JSON).(*appConfigSource)
	empty.client = &fakeAppConfig{}
	if _, err := New(empty).Load(); err == nil {
		t.Error("empty configuration accepted")
	}
	if _, err := New(NewAppConfig("gate", "", "main", JSON)).Load(); err == nil {
		t.Error("missing environment accepted")
	}
}

// ---- Secrets Manager ----

func TestSecretsManagerStringAndBinary(t *testing.T) {
	for name, out := range map[string]*secretsmanager.GetSecretValueOutput{
		"string": {SecretString: aws.String(`{"redis": {"host": "secret-host", "port": 6400}}`)},
		"binary": {SecretBinary: []byte(`{"redis": {"host": "secret-host", "port": 6400}}`)},
	} {
		client := &fakeSecrets{out: out}
		src := NewSecretsManager("app/prod", JSON).(*secretsManagerSource)
		src.client = client
		cfg, err := New(src).Load()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if r := MustBind[redisConf](cfg, "redis"); r.Host != "secret-host" || r.Port != 6400 {
			t.Errorf("%s: unexpected result: %+v", name, r)
		}
		if client.id != "app/prod" {
			t.Errorf("%s: secret id = %q", name, client.id)
		}
	}
}

func TestSecretsManagerErrors(t *testing.T) {
	empty := NewSecretsManager("app/prod", YAML).(*secretsManagerSource)
	empty.client = &fakeSecrets{out: &secretsmanager.GetSecretValueOutput{}}
	if _, err := New(empty).Load(); err == nil {
		t.Error("secret without value accepted")
	}
	if _, err := New(NewSecretsManager("", YAML)).Load(); err == nil {
		t.Error("empty secret id accepted")
	}
	// The source's description, used in error messages, never contains the value.
	if s := NewSecretsManager("app/prod", YAML).String(); s != "aws secrets manager app/prod" {
		t.Errorf("String() = %q", s)
	}
}

func TestFormatFromPathTOML(t *testing.T) {
	if f, err := FormatFromPath("config.toml"); err != nil || f != TOML {
		t.Errorf("FormatFromPath(config.toml) = %q, %v", f, err)
	}
}
