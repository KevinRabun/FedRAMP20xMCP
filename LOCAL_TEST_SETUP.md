# Local Test Setup Guide

## Prerequisites

### 1. GitHub Personal Access Token (Required)
The dependency checking tests query live CVE databases (GitHub Advisory Database and NVD). You need a GitHub token for authentication to avoid rate limiting.

**Create a token:**
1. Go to https://github.com/settings/tokens
2. Click "Generate new token" → "Generate new token (classic)"
3. Name it "FedRAMP20xMCP Tests"
4. Select scope: `public_repo` (read access to public repositories)
5. Generate and copy the token

**Set the environment variable:**

PowerShell:
```powershell
$env:GITHUB_TOKEN = "your_token_here"
```

Persistent (adds to your profile):
```powershell
[System.Environment]::SetEnvironmentVariable('GITHUB_TOKEN', 'your_token_here', 'User')
```

Bash/Linux:
```bash
export GITHUB_TOKEN="your_token_here"
```

### 2. Python Dependencies
```powershell
pip install -e .
pip install pytest
```

## Running Tests

### Run All Tests
```powershell
python -m pytest tests/ -v
```

### Run Specific Test File
```powershell
python -m pytest tests/test_dependency_checking.py -v
```

### Run Single Test
```powershell
python -m pytest tests/test_dependency_checking.py::test_outdated_package_detection -v
```

### Skip Slow Tests
```powershell
python -m pytest tests/ -v -m "not slow"
```

## Current Test Issues (December 6, 2024)

### Failing Tests Analysis

**Test 4: `test_secure_current_packages` - FALSE FAILURE**

This test expects **NO warnings** for:
- System.Text.Json 8.0.5 (latest: 10.0.0)
- Azure.Identity 1.13.0 (latest: 1.17.1)

**Problem:** These packages ARE correctly flagged as outdated:
- 8.0.5 → 10.0.0 = 2 major versions behind (outdated threshold met)
- 1.13.0 → 1.17.1 = 4 minor versions behind (outdated threshold met)

**Solution:** Fix test expectations to accept LOW severity outdated warnings for these versions.

**Tests 2, 3, 8: Missing Vulnerability/Outdated Findings**

These tests expect findings but get 0 results:
- Test 2: System.Text.Json 6.0.0, Azure.Identity 1.5.0 (outdated)
- Test 3: System.Text.Json 5.0.0, System.Security.Cryptography.Xml 5.0.0 (vulnerable)
- Test 8: Newtonsoft.Json 12.0.1 (vulnerable), Azure.Identity 1.5.0 (outdated)

**Root Cause:** The CVE fetcher is working correctly (verified with local test script), but findings aren't being generated.

**Debugging Steps:**

1. **Check if .csproj is being found:**
```python
# In analyzer, add debug output
import sys
print(f"DEBUG: Looking for .csproj from {file_path}", file=sys.stderr)
csproj_files = self._find_csproj_files(file_path)
print(f"DEBUG: Found {len(csproj_files)} .csproj files: {csproj_files}", file=sys.stderr)
```

2. **Check if packages are being parsed:**
```python
# In _parse_csproj, add debug output
print(f"DEBUG: Parsed {len(packages)} packages from {csproj_path}", file=sys.stderr)
for pkg in packages:
    print(f"  - {pkg.name} {pkg.version}", file=sys.stderr)
```

3. **Check if CVE fetcher is being called:**
```python
# In _check_package_vulnerabilities, add debug output
print(f"DEBUG: Checking {len(packages)} packages for vulnerabilities", file=sys.stderr)
for package in packages:
    print(f"DEBUG: Checking {package.name} {package.version}", file=sys.stderr)
    vulnerabilities = fetcher.get_package_vulnerabilities(...)
    print(f"  Found {len(vulnerabilities)} vulnerabilities", file=sys.stderr)
```

## Test Environment Variables

- `GITHUB_TOKEN` - Required for CVE database access (5,000 requests/hour with token vs 60/hour without)
- `SKIP_SLOW_TESTS` - Set to "1" to skip tests that make network calls

## CI/CD Notes

GitHub Actions has `GITHUB_TOKEN` automatically available in the workflow context. The tests should pass in CI with authenticated access.

## Quick Verification

Run this to verify your token works:
```powershell
python -c "import os; from src.fedramp_20x_mcp.cve_fetcher import CVEFetcher; fetcher = CVEFetcher(os.environ.get('GITHUB_TOKEN')); print(fetcher.get_latest_version('System.Text.Json', 'nuget'))"
```

Expected output: `10.0.0` or similar recent version.

## Next Steps

1. **Set GITHUB_TOKEN** in your environment
2. **Run test_dependency_checking.py** to reproduce failures locally
3. **Add debug output** (as shown above) to trace where the logic breaks
4. **Fix test expectations** for test 4 (currently has wrong expectations)
5. **Investigate** why tests 2, 3, 8 get 0 findings when they should detect issues
