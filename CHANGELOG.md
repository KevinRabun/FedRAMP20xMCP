# Changelog

All notable changes to the FedRAMP 20x MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-13

### 🎉 Initial Stable Release

First production-ready release of the FedRAMP 20x MCP Server providing comprehensive access to FedRAMP 20x security requirements and controls with Azure-first guidance.

### Added

#### Core Features
- **48 MCP Tools** across 13 modules for FedRAMP 20x compliance
- **321 Requirements**: 199 FRRs + 72 KSIs + 50 FRDs
- **18 Comprehensive Prompts** for compliance workflows
- **381 YAML Patterns** across 23 requirement families
- AST-powered code analysis using tree-sitter

#### Data Coverage
- **10 FRR Families**: VDR (59), ADS (22), CCM (25), SCN (26), RSC (10), UCM (4), MAS (12), ICP (9), FSI (16), PVA (22)
- **11 KSI Families**: AFR (11), CED (4), CMT (5), CNA (8), IAM (7), INR (3), MLA (8), PIY (8), RPL (4), SVC (10), TPR (4)
- **50 FedRAMP Definitions** from official documentation
- Retired KSI tracking and authoritative source synchronization

#### Analysis & Code Tools
- **Pattern-Based Analysis Architecture**: Single unified engine replacing 271 traditional analyzers
- **Multi-Language Support**: Python, C#, Java, TypeScript/JavaScript, Bicep, Terraform
- **CI/CD Pipeline Analysis**: GitHub Actions, Azure Pipelines, GitLab CI
- Infrastructure as Code (IaC) validation with FedRAMP 20x compliance checks
- Application code security analysis with dependency vulnerability checking
- Critical pre-deployment validation (`validate_fedramp_config`)

#### Evidence Automation
- **Automated Evidence Collection**: 65 active KSIs with Azure-native automation guidance
- **Ready-to-Use Queries**: KQL, Azure Resource Graph, REST API, Azure CLI, PowerShell
- **Infrastructure Templates**: Bicep and Terraform templates for evidence infrastructure
- **Collection Code**: Python, C#, Java, TypeScript, PowerShell evidence gathering code
- **Evidence Specifications**: Detailed artifact requirements with retention policies

#### Export & Integration
- Excel and CSV export for all requirements and KSIs
- Word document generation for KSI specifications
- Code enrichment with FedRAMP requirement comments
- GitHub Actions/Azure DevOps CI/CD integration guides

#### Documentation
- Comprehensive README with all 48 tools documented
- Advanced Setup Guide for multi-server configuration
- CI/CD Integration Guide
- Pattern Authoring Guide (PATTERN_AUTHORING_GUIDE.md)
- Pattern Schema V2 documentation (PATTERN_SCHEMA_V2.md)
- Testing Guide (TESTING.md) with 31 test files
- Security Policy (SECURITY.md)
- Contributing Guidelines (CONTRIBUTING.md)

#### Testing
- **277 Tests** across 11 test files with 100% pass rate
- **Test Categories**: Core modules, pattern engine, KSI/FRR analyzers, MCP tools, CVE fetcher
- Pattern language parity validation across Python, C#, Java, TypeScript
- Live GitHub repository parsing validation
- Comprehensive KSI requirement validation (130 tests)
- FRR analyzer coverage (35 tests)
- MCP tools integration testing (33 tests)

### Technical Details

#### Architecture
- Model Context Protocol (MCP) SDK 1.2+
- Python 3.10+ support (tested on 3.10, 3.11, 3.12, 3.14)
- STDIO transport for VS Code and Claude Desktop integration
- 1-hour cache TTL for FedRAMP data
- AST-first analysis with tree-sitter

#### Dependencies
- `mcp>=1.2.0` - Model Context Protocol SDK
- `httpx>=0.27.0` - HTTP client for FedRAMP data
- `openpyxl>=3.1.0` - Excel export
- `python-docx>=1.1.0` - Word document generation
- `pyyaml>=6.0` - YAML pattern loading
- `tree-sitter>=0.21.0` - AST parsing
- Language-specific tree-sitter bindings (Python, C#, Java, JavaScript)

#### Security Features
- No authentication required (local development tool)
- No Federal Customer Data handling
- HTTPS-only connections to GitHub
- Audit logging to stderr (KSI-MLA-05)
- Security vulnerability scanning with GitHub Advisory Database

### Integration Support
- **VS Code**: GitHub Copilot Chat integration via MCP extension
- **Claude Desktop**: macOS and Windows configuration
- **MCP Inspector**: Testing and debugging support
- **Azure DevOps**: Pipeline integration examples
- **GitHub Actions**: Workflow templates

### Known Limitations
- OSCAL format optional (not required by FRR-ADS-01)
- Documentation search requires network access to FedRAMP/docs repository
- CVE checking requires GITHUB_TOKEN for API access
- Pattern analysis focused on Azure-first guidance

### Data Sources
- FedRAMP 20x requirements from [github.com/FedRAMP/docs](https://github.com/FedRAMP/docs)
- Official NIST 800-53 control mappings
- Azure Well-Architected Framework guidance
- Cloud Adoption Framework (CAF) patterns

---

## Release Notes

### What's Ready for Production

✅ **All 48 tools fully functional and tested**  
✅ **100% KSI coverage (72 indicators)**  
✅ **199 FRR requirements supported**  
✅ **381 patterns across 23 families**  
✅ **277 tests passing (100% pass rate)**  
✅ **Comprehensive documentation**  
✅ **CI/CD integration guides**  
✅ **Evidence automation for 65 KSIs**  

### Future Enhancements (Post-1.0)

The following features are planned for future releases but are not blockers for 1.0:

- Additional cloud provider patterns (AWS, GCP) beyond Azure-first focus
- OSCAL SSP generation tools (optional, not required by FedRAMP 20x)
- Real-time FedRAMP repository change notifications
- GraphQL API for evidence collection
- Enhanced vulnerability remediation tracking
- Integration with GRC platforms (ServiceNow, Archer, etc.)

### Upgrade Path

This is the first stable release. Future versions will follow semantic versioning:
- **Patch releases (1.0.x)**: Bug fixes, documentation updates
- **Minor releases (1.x.0)**: New features, additional patterns, new tools
- **Major releases (x.0.0)**: Breaking changes to API or data structures

---

[1.0.0]: https://github.com/KevinRabun/FedRAMP20xMCP/releases/tag/v1.0.0
