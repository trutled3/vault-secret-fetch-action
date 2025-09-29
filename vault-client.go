package main

import (
	"context"
	"fmt"
	"os"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

func NewVaultClient(ctx context.Context, productName, repositoryName string) (*vault.Client, error) {
	var client *vault.Client
	var token string
	var err error

	client, err = vault.New(
		vault.WithAddress(vaultAddress),
		vault.WithRequestTimeout(vaultRequestTimeout),
	)
	if err != nil {
		return nil, fmt.Errorf("error creating vault client: %v", err)
	}

	if cli.Flags.RunLocal {
		if token, ok = os.LookupEnv("VAULT_TOKEN"); !ok {
			return nil, fmt.Errorf("VAULT_TOKEN not set")
		}
	} else {
		var role, mountPath string

		if token, ok = os.LookupEnv("JWT"); !ok {
			return nil, fmt.Errorf("JWT not set")
		}

		if role, ok = os.LookupEnv("JWT_ROLE"); !ok {
			return nil, fmt.Errorf("JWT_ROLE not set")
		}

		if mountPath, ok = os.LookupEnv("JWT_MOUNT_PATH"); !ok {
			return nil, fmt.Errorf("JWT_MOUNT_PATH not set")
		}

		resp, err := client.Auth.JwtLogin(
			ctx,
			schema.JwtLoginRequest{
				Jwt:  token,
				Role: role,
			},
			vault.WithMountPath(mountPath),
		)
		if err != nil {
			var errMsg string
			if role == "github."+productName {
				errMsg = fmt.Sprintf(productsRoleErr, role, repositoryName, productName)
			}

			return nil, fmt.Errorf("%v\n\n%s", err, errMsg)
		}

		token = resp.Auth.ClientToken
	}

	if err = client.SetToken(token); err != nil {
		return nil, fmt.Errorf("error setting vault token: %v", err)
	}

	if _, err = client.Auth.TokenLookUpSelf(ctx); err != nil {
		return nil, fmt.Errorf("error looking up token: %v", err)
	}

	return client, nil
}
