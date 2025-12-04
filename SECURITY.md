# Security Policy

## Supported Versions

We release patches for security vulnerabilities. The following versions are currently supported:

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4.0 | :x:                |

## Reporting a Vulnerability

**Do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability in the FedRAMP 20x MCP Server, please report it using **GitHub's Private Vulnerability Reporting**:

🔒 **[Report a vulnerability](https://github.com/KevinRabun/FedRAMP20xMCP/security/advisories/new)**

This ensures your report remains private until we've addressed the issue and published a security advisory.

### What to Include

Please include the following information:
- Type of vulnerability
- Full paths of source file(s) related to the vulnerability
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the vulnerability, including how an attacker might exploit it

### What to Expect

- You will receive a response within 48 hours acknowledging receipt
- We will investigate and provide regular updates on our progress
- If the vulnerability is confirmed, we will:
  - Develop and test a fix
  - Release a security advisory and patched version
  - Credit you for the discovery (unless you prefer to remain anonymous)

## Security Best Practices for Users

### 1. Verify Package Integrity

Always install from official sources:
```bash
pip install fedramp-20x-mcp
```

Verify the package signature:
```bash
pip show fedramp-20x-mcp
```

### 2. Keep Dependencies Updated

The MCP server uses the following dependencies with minimum secure versions:
- `mcp>=1.2.0` - Model Context Protocol SDK
- `httpx>=0.27.0` - HTTP client with security fixes
- `openpyxl>=3.1.0` - Excel file generation
- `python-docx>=1.1.0` - Word document generation

Update regularly:
```bash
pip install --upgrade fedramp-20x-mcp
```

### 3. Review Permissions

When first using the MCP server in VS Code, you'll be prompted to grant permissions. Review these carefully:
- **Read access** to FedRAMP data files (local cache)
- **Network access** to fetch data from GitHub (https://github.com/FedRAMP/docs)
- **File system access** for caching (limited to `__fedramp_cache__` directory)

### 4. Secure Your Configuration

If you configure the MCP server in `.vscode/mcp.json`:
- Keep this file in `.gitignore` if it contains sensitive paths
- Use environment variables for any sensitive configuration
- Review the server command and arguments

### 5. Data Handling

The MCP server:
- ✅ **Does NOT** handle Federal Customer Data
- ✅ **Does NOT** require authentication or credentials
- ✅ Fetches public FedRAMP requirements from official GitHub repository
- ✅ Caches data locally in `__fedramp_cache__` directory (1-hour TTL)
- ✅ Runs entirely on your local machine
- ✅ **Does NOT** send data to external services (except fetching from GitHub)

### 6. Network Security

The server makes HTTPS requests only to:
- `https://api.github.com/repos/FedRAMP/docs` - Discover documentation files
- `https://raw.githubusercontent.com/FedRAMP/docs/main/data/*.json` - Fetch requirements
- `https://raw.githubusercontent.com/FedRAMP/docs/main/docs/**/*.md` - Fetch documentation

All connections use TLS 1.2+ via the `httpx` library.

### 7. Audit Logging

The server logs all operations to stderr for audit purposes:
```python
# Configure logging to stderr only (MCP requirement)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)
```

Review logs for unexpected activity:
- Failed data fetches
- Cache invalidation events
- Tool invocation errors

## Scope

### In Scope

- Vulnerabilities in the MCP server code
- Dependency vulnerabilities in required packages
- Configuration security issues
- Data handling vulnerabilities
- Network request security issues

### Out of Scope

- Vulnerabilities in upstream FedRAMP data (report to FedRAMP)
- Issues in the MCP protocol itself (report to Anthropic)
- Issues in VS Code or GitHub Copilot (report to Microsoft)
- Third-party MCP clients

## Known Limitations

### Not a Production Service

This is a **development tool** for FedRAMP compliance planning:
- Runs locally on developer machines
- Does not handle production workloads
- Does not process Federal Customer Data
- Does not require FedRAMP authorization itself

### Data Freshness

- Data is cached for 1 hour to reduce GitHub API requests
- Cache may be stale if FedRAMP updates requirements
- Manual cache clear: Delete `__fedramp_cache__` directory

### No Authentication

- The server does not implement authentication
- Runs in trusted local environment only
- Should not be exposed to network

## Security Updates

Security updates will be released as:
1. **Patch releases** (0.4.x) for critical vulnerabilities
2. **GitHub Security Advisories** for confirmed vulnerabilities
3. **Release notes** documenting security fixes

Subscribe to releases: https://github.com/KevinRabun/FedRAMP20xMCP/releases

## Compliance Alignment

This security policy addresses:
- **KSI-PIY-03**: Vulnerability disclosure policy (this document)
- **KSI-SVC-08**: Security dependency management (minimum versions)
- **KSI-MLA-05**: Audit logging (stderr logging for all operations)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
