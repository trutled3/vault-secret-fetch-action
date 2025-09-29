package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/lrstanley/clix"
)

var (
	ok        bool
	err       error
	lctx      context.Context
	mountPath string

	cli = &clix.CLI[Flags]{}

	errMsgs = []error{}

	ErrNoValueFound      = errors.New("no value found at path")
	ErrUnmarshallingData = errors.New("unable to unmarshal data to map[string]any")
)

const (
	productsMount       = "kv-v2-b"
	githubGlobalMount   = "kv-v2-a"
	vaultAddress        = "https://vault.com"
	vaultRequestTimeout = 30 * time.Second

	ctxKeyRunLocal contextKey = "run-local"

	productsRoleErr = "failed to login with JWT role: %s. " +
		"Ensure the repository, %s, is listed within the allowed-repositories secret at:\n\n" +
		"https://vault.com/ui/vault/secrets/kv-v2-b/kv/%s%%2Ftrusted-sources" +
		"\n\nOnce added wait roughly 10 minutes for the change to take effect."
)

type Flags struct {
	RawSecrets string `env:"RAW_SECRETS" long:"raw-secrets" required:"true"  description:"Raw secrets string."`
	RunLocal   bool   `env:"RUN_LOCAL" long:"run-local" description:"Run the action locally."`
}

type path struct {
	secret string
	mount  string
}

type Secret struct {
	Path   string
	SubKey string
	EnvVar string
}

type LookupAgent struct {
	Client            *vault.Client
	ProductName       string
	JWTRoleName       string
	WorkflowName      string
	RepositoryName    string
	DeployEnvironment string
	Secrets           []Secret
}

func main() {
	cli.LoggerConfig.Pretty = true
	cli.Parse()
	ctx := log.NewContext(context.Background(), cli.Logger)

	// If cli.Flags.RunLocal is not set, default to false
	ctx = WithRunLocal(ctx, cli.Flags.RunLocal)
	if IsRunLocal(ctx) {
		log.FromContext(ctx).Warn("running locally")
	}

	lookupAgent := &LookupAgent{}

	// this environment variable is always set by GitHub Actions
	repositorySlug := os.Getenv("GITHUB_REPOSITORY") // e.g. github-org/repo
	lookupAgent.RepositoryName = strings.Split(repositorySlug, "/")[1]

	if lookupAgent.ProductName, ok = os.LookupEnv("PRODUCT_NAME"); !ok {
		log.FromContext(ctx).Fatal("PRODUCT_NAME is not set 😱")
	}
	if lookupAgent.WorkflowName, ok = os.LookupEnv("GITHUB_WORKFLOW"); !ok {
		log.FromContext(ctx).Fatal("GITHUB_WORKFLOW is not set 😱")
	}
	if lookupAgent.JWTRoleName, ok = os.LookupEnv("JWT_ROLE"); !ok {
		log.FromContext(ctx).Fatal("JWT_ROLE is not set 😱")
	}
	lookupAgent.DeployEnvironment = os.Getenv("DEPLOY_ENVIRONMENT")
	if lookupAgent.DeployEnvironment == "" {
		log.FromContext(ctx).Info("DEPLOY_ENVIRONMENT is not set")
	}

	lookupAgent.Client, err = NewVaultClient(ctx, lookupAgent.ProductName, lookupAgent.RepositoryName)
	if err != nil {
		log.FromContext(ctx).WithError(err).Fatal("failed to create vault client 😱")
	}

	lookupAgent.Secrets = lookupAgent.ParseInputSecrets(ctx, cli.Flags.RawSecrets)

	for _, secret := range lookupAgent.Secrets {
		var value string
		pass := false
		ctx = LogContext(ctx, log.Fields{"secret": secret.Path, "key": secret.SubKey})

		lookupHeirarchy := BuildLookupHeirarchy(secret, lookupAgent.ProductName, lookupAgent.RepositoryName, lookupAgent.WorkflowName, lookupAgent.DeployEnvironment)
		for _, path := range lookupHeirarchy {
			ctx = LogContext(ctx, log.Fields{"lookup-path": path.secret, "mount-path": path.mount})
			value, err = SecretLookup(lctx, lookupAgent.Client, secret, path.secret, path.mount)
			if err != nil {
				log.FromContext(lctx).Info("not found")
				continue
			}
			pass = true
			WriteOutput(lctx, secret, value)
			break
		}
		if !pass {
			errMsgs = append(errMsgs, fmt.Errorf("%s.%s not found 😱", secret.Path, secret.SubKey))
		}
	}

	for _, errMsg := range errMsgs {
		log.FromContext(ctx).WithError(errMsg).Error("")
	}

	if len(errMsgs) > 0 {
		os.Exit(1)
	}
}

type contextKey string

// WithRunLocal returns a new context with the given runLocal value.
func WithRunLocal(ctx context.Context, runLocal bool) context.Context {
	return context.WithValue(ctx, ctxKeyRunLocal, runLocal)
}

func IsRunLocal(ctx context.Context) bool {
	// REDACTED
}

// LogContext returns a new context with the given logging fields injected into the context, which will
// be included in all subsequent log messages.
func LogContext(ctx context.Context, fields log.Fields) context.Context {
	return log.NewContext(ctx, log.FromContext(ctx).WithFields(fields))
}

func BuildLookupHeirarchy(secret Secret, productName, repositoryName, workflowName, deployEnvironment string) []path {
	var pathHeirarchy []path
	// If a path is passed, check if the github-global/data/ or products/data/ paths, lookup that path & return early,
	// if not continue to heirarchy lookup

	// Order of heirarchy
	lookupHeirarchy := []path{}

	// REDACTED but appends a predefined list of paths to fetch secret from in order of precidence

	return lookupHeirarchy
}

// SecretLookup takes a secret path and a subkey, and returns the value of the key for the given secret path.
func SecretLookup(ctx context.Context, client *vault.Client, secret Secret, path, mountPath string) (string, error) {
	lctx = LogContext(ctx, log.Fields{"lookup-path": path, "mount-path": mountPath})
	// log.FromContext(lctx).Info("looking up secret 🔍")
	resp, err := client.Secrets.KvV2Read(lctx, path, vault.WithMountPath(mountPath))
	if err != nil {
		return "", err
	}

	if resp == nil {
		return "", fmt.Errorf("no data found in secret")
	}

	// REDACTED funcation call that filters json from secret down to the specified key. e.g. store.food.fruit to retrieve
	// the value 'apple' from an example secret {"store": {"food": {"fruit": "apple"}}}

	return v, nil
}

// WriteOutput writes the secret to the environment variable and masks the value in the logs.
func WriteOutput(ctx context.Context, secret Secret, value string) {
	var envFilePath string

	if IsRunLocal(ctx) {
		envFilePath = ".env"
	} else {
		envFilePath = os.Getenv("GITHUB_ENV")
	}

	file, err := os.OpenFile(envFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	lctx = LogContext(ctx, log.Fields{"env-var": secret.EnvVar})
	if err != nil {
		log.FromContext(lctx).WithError(err).Fatal("failed to open GITHUB_ENV")
	}
	defer file.Close()

	if strings.Contains(value, "\n") {
		lines := strings.Split(value, "\n")

		// mask each line of the secret value
		for _, line := range lines {
			// if the line is emtpy, skip
			if strings.TrimSpace(line) == "" {
				continue
			}
			fmt.Printf("::add-mask::%v\n", line)
		}

		// {name}<<{delimiter}
		// {value}
		// {delimiter}
		_, err = file.WriteString(fmt.Sprintf("%s<<EOF\n", secret.EnvVar))
		if err != nil {
			log.FromContext(lctx).WithError(err).Fatal("failed to write GITHUB_ENV")
		}
		_, err = file.WriteString(value)
		if err != nil {
			log.FromContext(lctx).WithError(err).Fatal("failed to write GITHUB_ENV")
		}
		_, err = file.WriteString("\nEOF\n")
		if err != nil {
			log.FromContext(lctx).WithError(err).Fatal("failed to write GITHUB_ENV")
		}
	} else {
		fmt.Printf("::add-mask::%v\n", value)
		_, err = file.WriteString(fmt.Sprintf("%s=%s\n", secret.EnvVar, value))
		if err != nil {
			log.FromContext(lctx).WithError(err).Fatal("failed to write GITHUB_ENV")
		}
	}
	log.FromContext(lctx).Infof("📝 secret written to GITHUB_ENV")
}

// ParseInputSecrets takes a raw string of secrets and parses it into a slice of Secret structs.
func (la *LookupAgent) ParseInputSecrets(ctx context.Context, rawsecrets string) []Secret {
	var secretSlice []Secret

	secrets := strings.Split(rawsecrets, ";")

	for i := range secrets {

		if len(secret) == 0 {
			continue
		}
		lctx = LogContext(ctx, log.Fields{"secret-input": secret})
		log.FromContext(lctx).Info("parsing secret")

		// REDACTED however uses string interpolation to pull the path, 'aws', key, 'accessKey', and env var name, 'AWS_ACCESS_KEY_ID' from
		// the string passed to the service, e.g. "aws accessKey | AWS_ACCESS_KEY_ID"

		secretMap := &Secret{
			Path:   strings.TrimSpace(secretSegments[0]), // aws
			SubKey: strings.TrimSpace(secretSegments[1]), // accessKey
			EnvVar: strings.TrimSpace(secretSplit[1]),    // AWS_ACCESS_KEY_ID
		}

		secretSlice = append(secretSlice, *secretMap)
	}

	return secretSlice
}

// Filter takes a KV V2 secret, validates it has content, and recursively type casts through any maps or
// similar, returning a specific-typed result if it exists. For example:
//
//	util.Filter(secret, "some.sub.value.here") where some -> sub -> value -> here in JSON.
//
// If the value is a list or an object, marshal it to JSON and return it as a string.
func FilterKvV2[T any](secret *vault.Response[schema.KvV2ReadResponse], filter string) (T, error) {
	var noop T
	if secret == nil || secret.Data.Data == nil {
		return noop, ErrNoValueFound
	}

	root := secret.Data.Data

	// if the filter is a wildcard, return the entire secret as a json encoded string
	if filter == "*" {
		// REDACTED
	}

	var isLast, ok bool

	filters := strings.Split(filter, ".")

	for i, f := range filters {
		// REDACTED

		// Check if the value is a map or a slice and marshal it to JSON

		// REDACTED

		// If the value is not directly of type T, try to convert it to string
		// REDACTED

		return noop, ErrNoValueFound
	}
	return noop, nil
}
