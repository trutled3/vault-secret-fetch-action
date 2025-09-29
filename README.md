# go-vault-secret-fetch 🔎

This utility is used by the [vault-fetch] composite action. This tool is inspired by Hashicorp's [vault-action](https://github.com/hashicorp/vault-action) but customized to support a pre-defined heiarchal path lookup to allow consumers to pass a name of a secret and use contextual information such as the repository's name, workflow name, and deployment environment to dynamically pull a secret.

The utility utilizes the JWT authentication method to read fetch secrets from a predefined KV v2 secrets engine within Vault.

Given the following string structure as a single string, the utility will parse each string separated by a semicolon in to 3 parts.

```bash
aws accessKey | AWS_ACCESS_KEY_ID ;
```

- `aws` is the name of the secret or the full path to the secret.
- `accessKey` is the key for which the value is desired.
- `AWS_ACCESS_KEY_ID` is the environment variable name to set the fetched value to

> [!TIP]
> You can either pass just the name of the secret or the full path.
>
> Full secret paths or secrets from the secrets engine can be fetched by passing the full paths. For example,
>
> ```yaml
>   secrets: |
>    kv-v2-a/data/kcss/team-tokens value | TEAM_TOKENS ;
>    kv-v2-b/data/kcss/nuclear-teams value | DB_PASSWORD
> ```

> [!NOTE]
> If the value of the key specified is an object, the value with be returned as a json encoded string.
>
> If a wildcard, `*`, is specified for the key, the entire secret will be returned as a json encoded string. For example a secret with the below value,
>
> ```json
> {
>   "value": {
>     "foo": "bar"
>   }
> }
> ```
>
> Can be returned as follows,
>
> ```bash
> secret * | ENTIRE_SECRET_JSON
>
> echo $ENTIRE_SECRET_JSON
> {"value":{"foo":"bar"}}
> ```

## Example Usage

*See examples folder!*

1. A JWT Token for the workflow is generated that is set as an environment variable in the next step.
2. The environment variables are set:
    - `PRODUCT_NAME` is retreived from the `REDACTED` custom property.
    - `DEPLOY_ENVIRONMENT` is set with an optional input, `deploy-environment`, the composite action.
    - `RAW_SECRETS` is set with the required input, `secrets`. The format of this secret follows the format:

    ```yaml
    secrets: |
        aws accessKey | AWS_ACCESS_KEY_ID ;
        aws secretKey | AWS_SECRET_ACCESS_KEY
    ```

    ```yaml
    secrets: |
        kv-v2-a/data/team/team-tokens value | TEAM_TOKENS ;
        kv-v2-b/data/team/nuclear-teams value | NUCLEAR_TEAMS
    ```

> [!TIP]
> You can either pass just the name of the secret or the full path.
>
> Full secret paths or secrets from the `kv-v2` secrets engine can be fetched by passing the full paths. For example,
> `kv-v2-a/data/team/team-tokens` or `kv-v2-b/data/team/nuclear-teams`