# Radix Oauth Guard

The Guard is a HTTP Server that responds to requests on http://localhost:8000/auth and authenticates the header `Authorization: Bearer JWT` against the configured ISSUER, AUDIENCE and authorizes the request agains a comma separated list of subjects.

## Configuration

 - `ISSUER` - Required. A issuer to verify JWT against. Must support the `${ISSUER}.well-known/openid-configuration` endpoint.
 - `AUDIENCE` - Required. The configured Audience in the token.
 - `SUBJECTS` - Required. Comma seperated list of subjects that are authorized.
 - `LOG_LEVEL` - Defaults to info.  
 - `LOG_PRETTY` - Defaults to json. Output is ANSI colored text instead of json.

## Developing

You need Go installed. Linting is done by [`golangci-lint`](https://golangci-lint.run/)

### Dependencies - go modules

Go modules are used for dependency management. See [link](https://blog.golang.org/using-go-modules) for information how to add, upgrade and remove dependencies. E.g. To update `radix-operator` dependency:

- list versions: `go list -m -versions github.com/coreos/go-oidc/v3`
- update: `go get github.com/coreos/go-oidc/v3@v3.10.0`

### Running locally

The following env vars are needed. Useful default values in brackets.

```shell
LOG_PRETTY=True ISSUER=https://issuer-url/ AUDIENCE=some-audience SUBJECTS=default,kubernetes,somename go run .
```

#### Validate code

- run `make lint`

#### Update version
We follow the [semantic version](https://semver.org/) as recommended by [go](https://blog.golang.org/publishing-go-modules).

* `tag` in git repository (in `main` branch):

    Run following command to set `tag` (with corresponding version)
    ```
    git tag v1.0.0
    git push origin v1.0.0
    ```

## Deployment

TODO

## Pull request checking

Radix API makes use of [GitHub Actions](https://github.com/features/actions) for build checking in every pull request to the `main` branch. Refer to the [configuration file](.github/workflows/pr.yml) of the workflow for more details.

## Contributing

Read our [contributing guidelines](./CONTRIBUTING.md)

------------------

[Security notification](./SECURITY.md)
