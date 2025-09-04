[![SCM Compliance](https://scm-compliance-api.radix.equinor.com/repos/equinor/radix-oauth-guard/badge)](https://developer.equinor.com/governance/scm-policy/)

# Radix Oauth Guard

The Guard is a HTTP Server that responds to requests on http://localhost:8000/auth and authenticates the header `Authorization: Bearer JWT` against the configured ISSUER, AUDIENCE and authorizes the request agains a comma separated list of subjects.

## How to use

This application is designed to use with Forward Auth, specifically for ingress-nginx, enable with this annotation:
```yaml
metadata:
  annotations:
    nginx.ingress.kubernetes.io/auth-url: "http://oauth-guard.monitor.svc.cluster.local:8000/auth"
```

## Configuration

 - `ISSUER` - Required. A issuer to verify JWT against. Must support the `${ISSUER}.well-known/openid-configuration` endpoint.
 - `AUDIENCE` - Required. The configured Audience in the token.
 - `SUBJECTS` - Required. Comma seperated list of subjects that are authorized.
 - `LOG_LEVEL` - Defaults to info.  
 - `LOG_PRETTY` - Defaults to json. Output is ANSI colored text instead of json.

## Development Process

The `radix-oauth-guard` project follows a **trunk-based development** approach.

### 🔁 Workflow

- **External contributors** should:
  - Fork the repository
  - Create a feature branch in their fork

- **Maintainers** may create feature branches directly in the main repository.

### ✅ Merging Changes

All changes must be merged into the `main` branch using **pull requests** with **squash commits**.

The squash commit message must follow the [Conventional Commits](https://www.conventionalcommits.org/en/about/) specification.

### Running locally

The following env vars are needed. Useful default values in brackets.

```shell
LOG_PRETTY=True ISSUER=https://issuer-url/ AUDIENCE=some-audience SUBJECTS=default,kubernetes,somename go run .
```

### Validate code

- run `make lint`

## Release Process

Merging a pull request into `main` triggers the **Prepare release pull request** workflow.  
This workflow analyzes the commit messages to determine whether the version number should be bumped — and if so, whether it's a major, minor, or patch change.  

It then creates two pull requests:

- one for the new stable version (e.g. `1.2.3`), and  
- one for a pre-release version where `-rc.[number]` is appended (e.g. `1.2.3-rc.1`).

---

Merging either of these pull requests triggers the **Create releases and tags** workflow.  
This workflow reads the version stored in `version.txt`, creates a GitHub release, and tags it accordingly.

The new tag triggers the **Build and deploy Docker and Helm** workflow, which:

- builds and pushes a new container image and Helm chart to `ghcr.io`, and  
- uploads the Helm chart as an artifact to the corresponding GitHub release.

## Contribution

Want to contribute? Read our [contributing guidelines](./CONTRIBUTING.md)

## Security

This is how we handle [security issues](./SECURITY.md)
