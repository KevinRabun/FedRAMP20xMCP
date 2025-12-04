## Description

<!-- Provide a clear and concise description of what this PR does -->

## Type of Change

<!-- Mark the relevant option with an "x" -->

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Security fix
- [ ] Performance improvement
- [ ] Code refactoring
- [ ] Dependency update

## Related Issues

<!-- Link to related issues using # notation (e.g., Fixes #123, Relates to #456) -->

Fixes #
Relates to #

## Changes Made

<!-- List the specific changes made in this PR -->

- 
- 
- 

## Testing

<!-- Describe the tests you ran and how to reproduce them -->

### Test Coverage

- [ ] Added new tests for new functionality
- [ ] Updated existing tests
- [ ] All tests pass locally (`pytest`)
- [ ] Test coverage maintained or improved

### Manual Testing

<!-- Describe manual testing steps performed -->

1. 
2. 
3. 

## Security Checklist (KSI-SVC-07, KSI-SVC-08)

- [ ] No secrets, API keys, or sensitive data committed
- [ ] Ran `safety check` - no vulnerable dependencies detected
- [ ] Ran `bandit -r src/` - no security issues found
- [ ] Dependencies use minimum secure versions (if adding/updating)
- [ ] New dependencies are actively maintained and license-compatible
- [ ] Code follows secure coding practices

## Documentation

- [ ] Updated README.md (if needed)
- [ ] Updated CONTRIBUTING.md (if needed)
- [ ] Updated docstrings and inline comments
- [ ] Updated TESTING.md (if adding new tests)
- [ ] Updated .github/copilot-instructions.md (if changing architecture)

## Version Management (if applicable)

If this is a release PR, ensure all 3 version files are updated:

- [ ] Updated `pyproject.toml` (line 3: `version = "X.Y.Z"`)
- [ ] Updated `server.json` (top-level and packages[0]: `"version": "X.Y.Z"`)
- [ ] Updated `src/fedramp_20x_mcp/__init__.py` (line 8: `__version__ = "X.Y.Z"`)

## Checklist

- [ ] My code follows the project's code style
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] My changes generate no new warnings or errors
- [ ] I have run the full test suite and all tests pass
- [ ] I have checked for merge conflicts
- [ ] I have updated the documentation accordingly

## Screenshots (if applicable)

<!-- Add screenshots to help explain your changes -->

## Additional Context

<!-- Add any other context about the PR here -->

## Reviewer Notes

<!-- Any specific areas you'd like reviewers to focus on? -->

---

**For Maintainers:**
- [ ] PR title follows conventional commit format
- [ ] Labels applied appropriately
- [ ] Milestone assigned (if applicable)
- [ ] Breaking changes documented in release notes
