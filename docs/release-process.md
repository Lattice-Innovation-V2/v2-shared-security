---
connie-title: "latticepay-security: Release Process"
---

# Release Process

Quick reference for releasing the latticepay-security library.

## What's Automated

- **CI**: Runs on every PR and push to main; blocks merge if tests fail
- **SNAPSHOT**: Published automatically on every commit to main
- **Release**: Published automatically when a semantic version tag is pushed (e.g. `v1.0.0`); no manual approval required
- **Workflows**: Use GCP Workload Identity Federation; see `.github/workflows/` for inputs

## Release Checklist

### Pre-Release

- [ ] All tests passing on main branch
- [ ] CI workflow passing
- [ ] Documentation updated (if needed)
- [ ] CHANGELOG updated with release notes
- [ ] Version decided (follow [Semantic Versioning](https://semver.org/))

### Version Strategy

**Semantic Versioning (`MAJOR.MINOR.PATCH`):**
- **MAJOR** - Breaking changes (e.g., `1.0.0` → `2.0.0`)
- **MINOR** - New features, backward compatible (e.g., `1.0.0` → `1.1.0`)
- **PATCH** - Bug fixes, backward compatible (e.g., `1.0.0` → `1.0.1`)

**Version in this project:** A single `<revision>` property in the **root** `pom.xml` controls all module versions. Update only that property (or use `-Drevision=...` when building); no need to edit child POMs or run `versions:set` across modules.

## Standard Release (No Manual Approval)

Releases are **fully automated** when you push a semantic version tag. No manual approval or workflow dispatch required.

### Step 1: Update Version in POM

The project uses [Maven CI-friendly versions](https://maven.apache.org/maven-ci-friendly.html): a single `<revision>` property in the **root** `pom.xml` drives all module versions. Child POMs reference the parent with `<version>${revision}</version>` and do not need to be edited.

```bash
# Edit root pom.xml: set <revision> to the release version (e.g. 1.0.0)
# Or override on the command line when building:
mvn -Drevision=1.0.0 clean deploy
```

For a release, set the property in the root POM and commit:

```xml
<properties>
    <revision>1.0.0</revision>
    ...
</properties>
```

### Step 2: Commit and Push

```bash
git add pom.xml
git commit -m "Release 1.0.0"
git push origin main
```

### Step 3: Create and Push Tag

```bash
# Create tag locally
git tag v1.0.0

# Push tag (triggers publish workflow automatically)
git push origin v1.0.0
```

**Important:** The workflow runs immediately when the tag is pushed. No manual approval required.

### Step 4: Prepare Next Development Cycle

Update the `<revision>` property in the root `pom.xml` to the next SNAPSHOT (e.g. `1.1.0-SNAPSHOT`), then commit and push:

```bash
# Edit root pom.xml: <revision>1.1.0-SNAPSHOT</revision>

git add pom.xml
git commit -m "Prepare for next development iteration"
git push origin main
```

### Step 5: Verify Release

Check the GitHub Actions workflow:
1. Go to **Actions** tab in GitHub
2. Find the "Publish Maven Artifacts" workflow run for your tag
3. Verify all steps completed successfully
4. Check the summary for consumer integration instructions

Verify artifact in GCP Artifact Registry:
```bash
gcloud artifacts versions list \
  --package=io.latticepay:latticepay-security \
  --repository=maven-libs \
  --location=us-central1 \
  --project=latticepay-prod
```

## Hotfix Release

For urgent bug fixes that need to be released from a maintenance branch:

### Step 1: Create Hotfix Branch

```bash
# From the release tag
git checkout -b hotfix/1.0.1 v1.0.0
```

### Step 2: Apply Fix

```bash
# Make changes
git add .
git commit -m "Fix critical bug in X"
```

### Step 3: Update Version

```bash
mvn versions:set -DnewVersion=1.0.1 -DgenerateBackupPoms=false
git add pom.xml
git commit -m "Release 1.0.1"
```

### Step 4: Merge to Main

```bash
git checkout main
git merge hotfix/1.0.1
git push origin main
```

### Step 5: Tag and Push

```bash
git tag v1.0.1
git push origin v1.0.1
```

### Step 6: Delete Hotfix Branch

```bash
git branch -d hotfix/1.0.1
git push origin --delete hotfix/1.0.1
```

## Snapshot Releases

SNAPSHOT versions are published automatically on every commit to `main`. No manual steps required.

**Usage in consumers:**
```xml
<dependency>
  <groupId>io.latticepay</groupId>
  <artifactId>latticepay-security</artifactId>
  <version>1.1.0-SNAPSHOT</version>
</dependency>
```

**Note:** SNAPSHOT versions are mutable and updated frequently. Use only for development.

## Manual Publish (Emergency Only)

If the GitHub Actions workflow fails and you need to publish manually:

### Step 1: Authenticate Locally

```bash
gcloud auth application-default login
```

### Step 2: Configure Maven Settings

The settings.xml will be generated automatically by the Artifact Registry wagon extension.

### Step 3: Deploy

```bash
# Ensure correct version in POM
mvn versions:set -DnewVersion=1.0.0 -DgenerateBackupPoms=false

# Deploy
GCP_PROJECT_PROD=latticepay-prod mvn clean deploy -DskipTests
```

## Rollback

### Delete a Bad Release

```bash
gcloud artifacts versions delete VERSION \
  --package=io.latticepay:latticepay-security \
  --repository=maven-libs \
  --location=us-central1 \
  --project=latticepay-prod \
  --quiet
```

### Remove Git Tag

```bash
# Delete remote tag
git push --delete origin vVERSION

# Delete local tag
git tag -d vVERSION
```

### Publish Corrected Version

Follow the standard release process with a new patch version.

## Common Scenarios

### Release Candidate (RC)

```bash
# Update version
mvn versions:set -DnewVersion=1.0.0-rc.1 -DgenerateBackupPoms=false

# Commit and tag
git add pom.xml
git commit -m "Release 1.0.0-rc.1"
git push origin main
git tag v1.0.0-rc.1
git push origin v1.0.0-rc.1
```

**Note:** Maven treats `-rc.1` as less than the final `1.0.0` version.

### Beta Release

```bash
mvn versions:set -DnewVersion=1.0.0-beta.1 -DgenerateBackupPoms=false
# ... same process as RC
```

### Major Version Release

```bash
# Update version for breaking changes
mvn versions:set -DnewVersion=2.0.0 -DgenerateBackupPoms=false

# Update documentation for breaking changes
# Update consuming services

# Release
git add pom.xml
git commit -m "Release 2.0.0 - BREAKING CHANGES"
git push origin main
git tag v2.0.0
git push origin v2.0.0
```

## Version Matrix

| Current Version | Change Type | Next Version |
|----------------|-------------|--------------|
| 1.0.0-SNAPSHOT | Release | 1.0.0 |
| 1.0.0 | Patch | 1.0.1 |
| 1.0.0 | Minor | 1.1.0 |
| 1.0.0 | Major | 2.0.0 |
| 1.0.0 | RC | 1.1.0-rc.1 |
| 1.0.0 | Beta | 1.1.0-beta.1 |

## Post-Release

### Update Consumer Services

After releasing a new version, update the dependency version in consuming services' `pom.xml` and verify tests pass.

### Announce Release

Communicate the release to the team:
- Post in Slack channel
- Update internal documentation
- Notify service owners if breaking changes

## Troubleshooting

### Tag Already Exists

**Error:** `fatal: tag 'v1.0.0' already exists`

**Solution:**
```bash
# Delete local tag
git tag -d v1.0.0

# Delete remote tag
git push --delete origin v1.0.0

# Recreate tag
git tag v1.0.0
git push origin v1.0.0
```

### Version Conflict

**Error:** `409 Conflict - Version already exists in Artifact Registry`

**Solution:**
- You cannot overwrite existing versions in Artifact Registry
- Bump to a new version (e.g., `1.0.1`)
- Do not reuse version numbers

### Build Fails After Version Update

**Error:** Tests fail after version bump

**Solution:**
```bash
# Reset version
mvn versions:set -DnewVersion=1.0.0-SNAPSHOT -DgenerateBackupPoms=false

# Fix tests
mvn clean test

# Re-attempt release
```

## References

- [Semantic Versioning](https://semver.org/)
- [Maven Versions Plugin](https://www.mojohaus.org/versions-maven-plugin/)
- [Git Tagging](https://git-scm.com/book/en/v2/Git-Basics-Tagging)
