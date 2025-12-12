# Release Process

This document describes the release process for `@eecc/rsa-multikey`.

## Prerequisites

1. Ensure you have push access to the repository
2. Ensure you have an npm account with publish access to the `@eecc` scope
3. Ensure your npm token is configured as a GitHub secret named `NPM_TOKEN`
4. Ensure you're on the `main` branch with a clean working directory

## Release Steps

### 1. Run Tests Locally

Before releasing, ensure all tests pass:

```bash
npm test
npm run lint
```

### 2. Create a Release

Use the release script to create a new release:

```bash
# For a patch release (0.0.1 -> 0.0.2)
npm run release patch

# For a minor release (0.0.1 -> 0.1.0)
npm run release minor

# For a major release (0.0.1 -> 1.0.0)
npm run release major

# For a specific version
npm run release 1.2.3

# Dry run (to see what would happen without making changes)
npm run release patch -- --dry-run
```

The release script will:
1. Update the version in `package.json`
2. Commit the version change
3. Create an annotated git tag
4. Push the commit and tag to GitHub

### 3. Automated Workflows

After pushing the tag, GitHub Actions will automatically:

1. **CI Workflow** (`ci.yml`): Runs tests and linting
2. **Publish Workflow** (`publish.yml`): 
   - Verifies the package version matches the tag
   - Runs tests
   - Publishes to npm
   - Verifies the publication
3. **Release Workflow** (`release.yml`):
   - Creates a GitHub release
   - Generates release notes from git commits

## Manual Release (Alternative)

If you prefer to release manually:

```bash
# 1. Update version in package.json
# Edit package.json and change the version field

# 2. Commit the change
git add package.json
git commit -m "chore: release v1.2.3"

# 3. Create and push tag
git tag -a v1.2.3 -m "Release v1.2.3"
git push origin main
git push origin v1.2.3

# 4. Publish to npm (if workflows are not set up)
npm publish --access public
```

## Version Numbering

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version when you make incompatible API changes
- **MINOR** version when you add functionality in a backwards compatible manner
- **PATCH** version when you make backwards compatible bug fixes

## GitHub Secrets

Ensure the following secrets are configured in GitHub:

- `NPM_TOKEN`: npm authentication token with publish access to `@eecc` scope
- `CODECOV_TOKEN` (optional): Codecov token for coverage reporting

## Troubleshooting

### Release script fails with "Working directory is not clean"

Commit or stash your changes before running the release script.

### Release script fails with "Not on main/master branch"

Switch to the main branch:
```bash
git checkout main
```

### npm publish fails

Check that:
1. Your npm token is valid and has publish access
2. The version number hasn't been published before
3. You're authenticated: `npm whoami`

### GitHub Actions workflow fails

Check the Actions tab in GitHub for detailed error messages. Common issues:
- Missing secrets
- Test failures
- Version mismatch between package.json and tag

