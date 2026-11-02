package configkit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/appconfigdata"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/spf13/viper"
)

// AWS sources authenticate with the default AWS credential chain and region,
// like the AWS CLI: the EC2/ECS/EKS role, shared config files, SSO, ...
// Every AWS read is bounded by awsTimeout so start-up cannot hang.
const awsTimeout = 15 * time.Second

// ssmMaxNamesPerCall is the GetParameters limit.
const ssmMaxNamesPerCall = 10

func awsContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), awsTimeout)
}

func loadAWSConfig(ctx context.Context) (aws.Config, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
	if err != nil {
		return aws.Config{}, fmt.Errorf("load AWS config: %w", err)
	}
	return cfg, nil
}

// ---- SSM Parameter Store ----

type ssmAPI interface {
	GetParameters(ctx context.Context, in *ssm.GetParametersInput, opts ...func(*ssm.Options)) (*ssm.GetParametersOutput, error)
}

// SSMParameter is one Parameter Store parameter holding a document in
// Format. Name may be a parameter name, an ARN, or carry a version or label
// selector ("/app/config:3").
type SSMParameter struct {
	Name   string
	Format Format
}

type ssmSource struct {
	params []SSMParameter
	client ssmAPI // nil: created from the default AWS config
}

// NewSSMParameters reads Parameter Store parameters (String or SecureString),
// each holding a document in its own format. A standard-tier parameter is
// limited to 4 KB, so a larger config can be split across several
// parameters. They are fetched in batches (one call per 10 parameters) and
// merged in the given order: later parameters override keys of earlier ones
// (nested maps are merged deeply), e.g.
//
//	NewSSMParameters(
//		SSMParameter{Name: "/gate/prod/base", Format: YAML},
//		SSMParameter{Name: "/gate/prod/db", Format: JSON},
//	)
func NewSSMParameters(params ...SSMParameter) Source {
	return &ssmSource{params: params}
}

func (s *ssmSource) String() string {
	names := make([]string, len(s.params))
	for i, p := range s.params {
		names[i] = p.Name
	}
	return "aws ssm " + strings.Join(names, ",")
}

func (s *ssmSource) Load() (map[string]any, error) {
	if len(s.params) == 0 {
		return nil, errors.New("at least one parameter is required")
	}
	names := make([]string, len(s.params))
	for i, p := range s.params {
		if p.Name == "" {
			return nil, errors.New("parameter name must not be empty")
		}
		if !p.Format.valid() {
			return nil, fmt.Errorf("parameter %s: unsupported config format %q", p.Name, p.Format)
		}
		names[i] = p.Name
	}
	ctx, cancel := awsContext()
	defer cancel()
	client := s.client
	if client == nil {
		cfg, err := loadAWSConfig(ctx)
		if err != nil {
			return nil, err
		}
		client = ssm.NewFromConfig(cfg)
	}

	unique := dedupe(names)
	values := make(map[string]string, len(unique))
	for start := 0; start < len(unique); start += ssmMaxNamesPerCall {
		batch := unique[start:min(start+ssmMaxNamesPerCall, len(unique))]
		out, err := client.GetParameters(ctx, &ssm.GetParametersInput{
			Names:          batch,
			WithDecryption: aws.Bool(true), // SecureString parameters
		})
		if err != nil {
			return nil, err
		}
		if len(out.InvalidParameters) > 0 {
			return nil, fmt.Errorf("parameters not found: %s", strings.Join(out.InvalidParameters, ", "))
		}
		for _, p := range out.Parameters {
			value := aws.ToString(p.Value)
			// Index by every form a name may have been requested in.
			values[aws.ToString(p.Name)+aws.ToString(p.Selector)] = value
			values[aws.ToString(p.Name)] = value
			values[aws.ToString(p.ARN)] = value
		}
	}

	merged := viper.New()
	for _, p := range s.params {
		value, ok := values[p.Name]
		if !ok {
			return nil, fmt.Errorf("parameter %s: not returned by Parameter Store", p.Name)
		}
		settings, err := decode([]byte(value), p.Format)
		if err != nil {
			return nil, fmt.Errorf("parameter %s: %w", p.Name, err)
		}
		if err := merged.MergeConfigMap(settings); err != nil {
			return nil, fmt.Errorf("parameter %s: %w", p.Name, err)
		}
	}
	return merged.AllSettings(), nil
}

func dedupe(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := make([]string, 0, len(names))
	for _, n := range names {
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// ---- AppConfig ----

type appConfigAPI interface {
	StartConfigurationSession(ctx context.Context, in *appconfigdata.StartConfigurationSessionInput, opts ...func(*appconfigdata.Options)) (*appconfigdata.StartConfigurationSessionOutput, error)
	GetLatestConfiguration(ctx context.Context, in *appconfigdata.GetLatestConfigurationInput, opts ...func(*appconfigdata.Options)) (*appconfigdata.GetLatestConfigurationOutput, error)
}

type appConfigSource struct {
	application, environment, profile string
	format                            Format
	client                            appConfigAPI // nil: created from the default AWS config
}

// NewAppConfig reads a freeform configuration profile from AWS AppConfig
// through the AppConfig Data API. Each identifier may be a name or an ID, e.g.
// NewAppConfig("gate", "prod", "main", configkit.YAML).
// To read through the AppConfig Agent (sidecar/Lambda extension) instead,
// which caches and polls, use the agent's HTTP endpoint.
func NewAppConfig(application, environment, profile string, format Format) Source {
	return &appConfigSource{application: application, environment: environment, profile: profile, format: format}
}

func (s *appConfigSource) String() string {
	return fmt.Sprintf("aws appconfig %s/%s/%s", s.application, s.environment, s.profile)
}

func (s *appConfigSource) Load() (map[string]any, error) {
	if s.application == "" || s.environment == "" || s.profile == "" {
		return nil, errors.New("appconfig application, environment and profile must not be empty")
	}
	if !s.format.valid() {
		return nil, fmt.Errorf("unsupported config format %q", s.format)
	}
	ctx, cancel := awsContext()
	defer cancel()
	client := s.client
	if client == nil {
		cfg, err := loadAWSConfig(ctx)
		if err != nil {
			return nil, err
		}
		client = appconfigdata.NewFromConfig(cfg)
	}

	session, err := client.StartConfigurationSession(ctx, &appconfigdata.StartConfigurationSessionInput{
		ApplicationIdentifier:          aws.String(s.application),
		EnvironmentIdentifier:          aws.String(s.environment),
		ConfigurationProfileIdentifier: aws.String(s.profile),
	})
	if err != nil {
		return nil, err
	}
	out, err := client.GetLatestConfiguration(ctx, &appconfigdata.GetLatestConfigurationInput{
		ConfigurationToken: session.InitialConfigurationToken,
	})
	if err != nil {
		return nil, err
	}
	// The first call of a session always returns the content; an empty body
	// means the deployed configuration itself is empty.
	if len(out.Configuration) == 0 {
		return nil, errors.New("appconfig returned an empty configuration")
	}
	return decode(out.Configuration, s.format)
}

// ---- Secrets Manager ----

type secretsManagerAPI interface {
	GetSecretValue(ctx context.Context, in *secretsmanager.GetSecretValueInput, opts ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

type secretsManagerSource struct {
	secretID string
	format   Format
	client   secretsManagerAPI // nil: created from the default AWS config
}

// NewSecretsManager reads the current version of a secret whose value
// (SecretString, or SecretBinary) is a document in the given format. The
// secret ID may be a name or an ARN, e.g.
// NewSecretsManager("gate/prod", configkit.JSON).
func NewSecretsManager(secretID string, format Format) Source {
	return &secretsManagerSource{secretID: secretID, format: format}
}

func (s *secretsManagerSource) String() string {
	return "aws secrets manager " + s.secretID
}

func (s *secretsManagerSource) Load() (map[string]any, error) {
	if s.secretID == "" {
		return nil, errors.New("secret ID must not be empty")
	}
	if !s.format.valid() {
		return nil, fmt.Errorf("unsupported config format %q", s.format)
	}
	ctx, cancel := awsContext()
	defer cancel()
	client := s.client
	if client == nil {
		cfg, err := loadAWSConfig(ctx)
		if err != nil {
			return nil, err
		}
		client = secretsmanager.NewFromConfig(cfg)
	}

	out, err := client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(s.secretID)})
	if err != nil {
		return nil, err
	}
	data := out.SecretBinary
	if out.SecretString != nil {
		data = []byte(*out.SecretString)
	}
	if len(data) == 0 {
		return nil, errors.New("secret has no value")
	}
	return decode(data, s.format)
}
