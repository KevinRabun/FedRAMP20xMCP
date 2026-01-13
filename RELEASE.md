# Release Process

This document outlines the release process for the FedRAMP 20x MCP Server.

## Pre-Release Checklist

### 1. Code Quality

- [ ] All tests passing locally (`python tests/run_all_tests.py`)
- [ ] No TODO, FIXME, or HACK comments in production code
- [ ] Code follows project coding standards
- [ ] All new features have tests
- [ ] Documentation updated for new features

### 2. Version Updates

Update version in **all three files** (must match):

- [ ] `pyproject.toml` - `version = "X.Y.Z"`
- [ ] `server.json` - `version` field (appears twice - top level and in packages[0])
- [ ] `src/fedramp_20x_mcp/__init__.py` - `__version__ = "X.Y.Z"`

**Verify versions match:**
```powershell
# Check all three files have same version
Select-String -Path pyproject.toml,server.json,src/fedramp_20x_mcp/__init__.py -Pattern 'version.*=.*"\d+\.\d+\.\d+"'
```

### 3. Documentation

- [ ] CHANGELOG.md updated with release notes
- [ ] README.md reflects current feature set
- [ ] All tool descriptions accurate
- [ ] Examples tested and working
- [ ] Links verified (no broken links)

### 4. Testing

- [ ] All 277+ tests passing
- [ ] GitHub token set for CVE tests: `$env:GITHUB_TOKEN = (gh auth token)`
- [ ] Test coverage adequate for new features
- [ ] Integration tests with VS Code MCP extension
- [ ] Integration tests with Claude Desktop (if applicable)

### 5. Dependencies

- [ ] All dependencies up to date
- [ ] No known security vulnerabilities (`pip install safety && safety check`)
- [ ] Dependency versions pinned appropriately
- [ ] License compatibility verified

### 6. Security

- [ ] Security Policy (SECURITY.md) reviewed
- [ ] No secrets or tokens in code
- [ ] Vulnerability scanning completed
- [ ] No high-severity findings unresolved

## Release Types

### Patch Release (X.Y.Z)

- Bug fixes only
- No new features
- No breaking changes
- Update Z version number

**Example:** 1.0.0 → 1.0.1

### Minor Release (X.Y.0)

- New features
- New tools or patterns
- No breaking changes
- Update Y version number, reset Z to 0

**Example:** 1.0.1 → 1.1.0

### Major Release (X.0.0)

- Breaking changes to API
- Major architectural changes
- Removal of deprecated features
- Update X version number, reset Y and Z to 0

**Example:** 1.5.3 → 2.0.0

## Release Steps

### 1. Update Version Numbers

```powershell
# Update all three version files
# pyproject.toml
(Get-Content pyproject.toml) -replace 'version = "\d+\.\d+\.\d+"', 'version = "X.Y.Z"' | Set-Content pyproject.toml

# server.json (both occurrences)
(Get-Content server.json) -replace '"version": "\d+\.\d+\.\d+"', '"version": "X.Y.Z"' | Set-Content server.json

# __init__.py
(Get-Content src/fedramp_20x_mcp/__init__.py) -replace '__version__ = "\d+\.\d+\.\d+"', '__version__ = "X.Y.Z"' | Set-Content src/fedramp_20x_mcp/__init__.py
```

### 2. Update CHANGELOG.md

Add new section at top:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- New feature 1
- New feature 2

### Changed
- Change 1
- Change 2

### Fixed
- Bug fix 1
- Bug fix 2

### Deprecated
- Feature being phased out

### Removed
- Removed deprecated feature

### Security
- Security fix 1
```

### 3. Run Full Test Suite

```powershell
# Set GitHub token
$env:GITHUB_TOKEN = (gh auth token)

# Run all tests
python tests/run_all_tests.py

# Verify output shows all passing
# Expected: "ALL TESTS PASSED"
```

### 4. Commit Changes

```bash
git add .
git commit -m "Release vX.Y.Z

- Update version to X.Y.Z in all files
- Update CHANGELOG.md with release notes
- [List other changes]
"
```

### 5. Create Git Tag

```bash
# Create annotated tag
git tag -a vX.Y.Z -m "Release vX.Y.Z"

# Push tag to remote
git push origin vX.Y.Z

# Alternatively, push all tags
git push --tags
```

### 6. Create GitHub Release

1. Go to repository on GitHub
2. Click "Releases" → "Draft a new release"
3. Select the tag `vX.Y.Z`
4. Title: `vX.Y.Z - Release Name`
5. Description: Copy from CHANGELOG.md
6. Check "Set as the latest release" if applicable
7. Click "Publish release"

### 7. Publish to PyPI (if applicable)

```bash
# Build distribution packages
python -m build

# Upload to PyPI (requires PyPI credentials)
python -m twine upload dist/*

# Verify package published
pip install fedramp-20x-mcp==X.Y.Z
```

### 8. Update Documentation Sites

If documentation is hosted externally (e.g., ReadTheDocs, GitHub Pages):

- [ ] Trigger documentation build
- [ ] Verify new version appears
- [ ] Check all links work

### 9. Announce Release

- [ ] Update README badges if needed
- [ ] Post to project channels (Slack, Teams, etc.)
- [ ] Notify stakeholders
- [ ] Update project website if applicable

## Post-Release

### 1. Verify Release

- [ ] Install from PyPI: `pip install fedramp-20x-mcp==X.Y.Z`
- [ ] Test basic functionality
- [ ] Verify VS Code MCP extension works
- [ ] Check GitHub release page

### 2. Monitor for Issues

- [ ] Watch for bug reports
- [ ] Monitor GitHub issues
- [ ] Check CI/CD pipelines

### 3. Plan Next Release

- [ ] Review feedback
- [ ] Prioritize next features
- [ ] Update project roadmap

## Hotfix Process

For critical bugs in production:

1. **Create hotfix branch from tag:**
   ```bash
   git checkout -b hotfix/vX.Y.Z+1 vX.Y.Z
   ```

2. **Fix the bug and test thoroughly**

3. **Update version to X.Y.Z+1** (patch version)

4. **Update CHANGELOG.md** with hotfix details

5. **Commit and tag:**
   ```bash
   git commit -m "Hotfix vX.Y.Z+1: [description]"
   git tag -a vX.Y.Z+1 -m "Hotfix vX.Y.Z+1"
   ```

6. **Merge back to main:**
   ```bash
   git checkout main
   git merge hotfix/vX.Y.Z+1
   git push origin main --tags
   ```

7. **Create GitHub release and publish to PyPI**

## Rollback Procedure

If a release has critical issues:

1. **Create new release** with fix (don't delete tags)
2. **Document issue** in CHANGELOG.md
3. **Update GitHub release** with warning
4. **Yank PyPI release** if needed: `pip install twine && twine upload --skip-existing dist/*`
5. **Notify users** via all channels

## Version Number Guidelines

Follow [Semantic Versioning 2.0.0](https://semver.org/):

- **MAJOR** (X): Breaking changes
- **MINOR** (Y): New features, backward compatible
- **PATCH** (Z): Bug fixes, backward compatible

### Examples

- `1.0.0` → `1.0.1`: Bug fix
- `1.0.1` → `1.1.0`: New MCP tool added
- `1.5.0` → `2.0.0`: Changed tool API signatures

## Release Schedule

### Regular Releases

- **Patch releases**: As needed for critical bugs
- **Minor releases**: Every 4-6 weeks
- **Major releases**: Every 6-12 months

### Security Releases

- **Critical security issues**: Immediate hotfix
- **High-severity issues**: Within 7 days
- **Medium-severity issues**: Next scheduled release

## Contact

For questions about the release process:
- Open an issue on GitHub
- See CONTRIBUTING.md for contribution guidelines
