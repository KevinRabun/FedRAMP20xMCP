# Copilot Instructions for FedRAMP 20x MCP Server

This project is an MCP server that loads FedRAMP 20x requirements from JSON files and official documentation markdown files from https://github.com/FedRAMP/docs and answers user questions about those requirements.

## Important Clarification: OSCAL Format Requirements

**Critical for User Guidance:** FedRAMP 20x requires **machine-readable** formats (JSON, XML, or structured data) for Authorization Data Sharing (FRR-ADS). **OSCAL is NOT mentioned in FedRAMP 20x requirements.**

- **Required:** Machine-readable formats (JSON/XML/structured data)
- **OSCAL Status:** NIST standard that can be used as one implementation approach (not mentioned in FedRAMP 20x)
- **Source:** FRR-ADS-01 specifies "machine-readable" only - no specific format prescribed
- **Implementation:** Users can choose custom JSON/XML or OSCAL based on their needs

When users ask about OSCAL, clarify it's NOT mentioned in FedRAMP 20x - it's one potential NIST-based implementation approach. See OSCAL_CLARIFICATION.md for detailed guidance.

## References
- [MCP Python SDK Documentation](https://github.com/modelcontextprotocol/python-sdk)
- [MCP Server Build Guide](https://modelcontextprotocol.io/docs/develop/build-server)
- [FedRAMP Data Source](https://github.com/FedRAMP/docs/tree/main/data)
- [FedRAMP Documentation](https://github.com/FedRAMP/docs/tree/main/docs)

## Project Completion Status

### Completed Features
✅ Scaffold MCP server using Python SDK
✅ Implement tools to query FedRAMP requirements by control, family, or keyword
✅ Load JSON data from remote source
✅ Provide endpoints for querying requirements
✅ Follow MCP server best practices
✅ Add tools for querying FedRAMP Definitions (50 terms)
✅ Add tools for querying Key Security Indicators (72 indicators)
✅ Add 6 enhancement tools (comparison, examples, dependencies, effort estimation, cloud-native guidance, architecture validation)
✅ Add 8 comprehensive prompts (roadmap, quarterly review, API design, KSI priorities, vendor evaluation, documentation, migration, audit prep)
✅ 1-hour data caching with automatic refresh
✅ **Framework Detection for False Positive Reduction** (Dec 2024):
  - Data Annotations validation framework detection
  - FluentValidation library recognition
  - ASP.NET Core Data Protection API detection
  - Application Insights framework detection
  - Environment-specific configuration handling (dev vs prod)
  - Smart severity adjustment based on framework usage
✅ **Configuration File Analysis** (Dec 2024):
  - appsettings.json security analysis
  - Hardcoded secrets detection
  - Connection string security validation
  - Logging configuration validation
  - HTTPS/HSTS settings verification
  - Production vs development environment differentiation
✅ **Cross-Method Data Flow Tracking** (Dec 2024):
  - Sensitive data propagation detection across variables
  - Indirect PII exposure through return values
  - Sensitive data in logging statement detection
  - Method call graph analysis for data flow
  - Variable assignment tracking with propagation paths
  - Detects 10+ sensitive identifier patterns (SSN, password, token, etc.)
✅ **Dependency Vulnerability Checking** (Dec 2024):
  - **Live CVE Database Integration** - GitHub Advisory Database and NVD API
  - **Multi-Ecosystem Support** - NuGet (.NET), npm (JavaScript), PyPI (Python), Maven (Java)
  - **1-Hour Caching** - Performance optimization for repeated queries
  - **MCP Tools for Users** - check_package_vulnerabilities, scan_dependency_file
  - **Analyzer Integration** - C# analyzer uses live CVE data (no hardcoded vulnerabilities)
  - Version range parsing with semver comparison (<, <=, >, >=, ==)
  - FedRAMP compliance mapping (KSI-SVC-08, KSI-TPR-03)
  - Severity mapping (CRITICAL, HIGH, MEDIUM, LOW with CVSS scores)
✅ **FluentValidation Deep Support** (Dec 2024):
  - AbstractValidator<T> class detection and extraction
  - RuleFor() validation rule parsing
  - DI container registration detection (AddFluentValidation, AddValidatorsFromAssembly)
  - Automatic validation pipeline recognition
  - False positive reduction for separate validator classes
  - Differentiates Data Annotations vs FluentValidation approaches
  - Model-to-validator mapping for accurate validation coverage
  - Enterprise validation pattern recognition

### Current Capabilities
The server provides 33 MCP tools:

**Core Tools:**
1. **get_control** - Get specific FedRAMP requirement by ID
2. **list_family_controls** - List requirements by family
3. **search_requirements** - Search requirements by keywords
4. **get_definition** - Look up FedRAMP term definitions
5. **list_definitions** - List all FedRAMP definitions
6. **search_definitions** - Search within definitions
7. **get_ksi** - Get specific Key Security Indicator
8. **list_ksi** - List all Key Security Indicators

**Documentation Tools:**
9. **search_documentation** - Search official FedRAMP markdown documentation
10. **get_documentation_file** - Get full content of specific documentation file
11. **list_documentation_files** - List all available documentation files

**Enhancement Tools:**
12. **compare_with_rev4** - Compare FedRAMP 20x with Rev 4/5 for 6 areas
13. **get_implementation_examples** - Practical code examples for requirements
14. **check_requirement_dependencies** - Map dependencies between requirements
15. **estimate_implementation_effort** - Timeline and cost estimates
16. **get_cloud_native_guidance** - Cloud-native implementation guidance
17. **validate_architecture** - Architecture review against requirements

**Export Tools:**
18. **export_to_excel** - Export data to Excel files
19. **export_to_csv** - Export data to CSV files
20. **generate_ksi_specification** - Generate detailed KSI product specifications

**Planning Tools:**
21. **generate_implementation_questions** - Generate strategic interview questions for PMs and engineers to think through FedRAMP 20x implementation considerations

**🆕 Evidence Collection Automation Tools:**
22. **get_infrastructure_code_for_ksi** - Generate Bicep/Terraform templates for automated evidence collection infrastructure
23. **get_evidence_collection_code** - Provide Python/C#/PowerShell code examples for collecting KSI evidence programmatically
24. **get_evidence_automation_architecture** - Complete end-to-end architecture guidance for automated evidence collection

**🆕 Implementation Mapping Tools:**
25. **get_ksi_implementation_matrix** - Get comprehensive implementation matrix for all KSIs in a family (complexity, priority, effort estimates, Azure services)
26. **generate_implementation_checklist** - Generate detailed step-by-step implementation checklist for specific KSI with Azure-focused guidance

**🆕 Code Analysis Tools (Multi-Language Support):**
27. **analyze_infrastructure_code** - Analyze IaC (Bicep/Terraform) for FedRAMP compliance issues with actionable recommendations
28. **analyze_application_code** - Analyze application code (Python, C#, Java, TypeScript/JavaScript) for security compliance issues
29. **analyze_cicd_pipeline** - Analyze CI/CD pipelines (GitHub Actions, Azure Pipelines, GitLab CI) for DevSecOps compliance

**🆕 Coverage Audit Tools:**
30. **get_ksi_coverage_summary** - Get summary of KSI analyzer coverage and recommendation quality assessment
31. **get_ksi_coverage_status** - Check if a specific KSI has analyzer coverage and limitations

**🆕 Security Tools (CVE Vulnerability Checking):**
32. **check_package_vulnerabilities** - Check package for CVE vulnerabilities from GitHub Advisory Database / NVD
33. **scan_dependency_file** - Scan entire dependency file (csproj, package.json, requirements.txt, pom.xml) for vulnerable packages

**🆕 Multi-language support**:
- **Python**: Flask, Django, FastAPI
- **C#/.NET**: ASP.NET Core, Entity Framework, Azure SDK (Phase A EF security Dec 2024)
- **Java**: Spring Boot, Spring Security, Jakarta EE
- **TypeScript/JavaScript**: Express, NestJS, Next.js, React, Angular, Vue

**Phase A: Entity Framework Security Enhancements (December 2024):**
- ✅ SQL Injection via ExecuteSqlRaw/FromSqlRaw detection (string interpolation, concatenation)
- ✅ N+1 Query Detection (foreach loops without Include())
- ✅ Missing AsNoTracking() in read-only queries (performance optimization)
- Detects dangerous patterns in EF Core queries
- Recommends parameterized queries, eager loading, and no-tracking queries
- AST-based analysis for accurate detection with minimal false positives

**Comprehensive Prompts:**
1. **initial_assessment_roadmap** - 9-11 month roadmap with budget/team guidance
2. **quarterly_review_checklist** - FRR-CCM-QR checklist for all 72 KSIs
3. **api_design_guide** - Complete FRR-ADS API design with OSCAL formats
4. **ksi_implementation_priorities** - Prioritized 8-phase KSI rollout over 12 months
5. **vendor_evaluation** - Vendor assessment framework with scorecard
6. **documentation_generator** - OSCAL SSP templates and procedure templates
7. **migration_from_rev5** - 7-phase Rev 5 to 20x migration guide
8. **audit_preparation** - 12-week audit preparation timeline and checklist
9. **azure_ksi_automation** - Complete Azure/M365 automation guide for all 72 KSIs with PowerShell, Azure CLI, Graph API, KQL queries, and evidence collection framework

### Data Loaded
- 329 total requirements from 12 documents (100% coverage)
- 50 FedRAMP Definitions (FRD family)
- 72 Key Security Indicators (KSI family)
- All FedRAMP 20x standards: ADS, CCM, FSI, ICP, MAS, PVA, RSC, SCN, UCM, VDR
- Official documentation markdown files (dynamically discovered)
- 1-hour caching with automatic refresh

## Code Organization
**All 4 Phases Refactoring Complete (97.2% reduction):**
- server.py reduced from 9,810 lines to 270 lines
- Infrastructure templates in `templates/bicep/` and `templates/terraform/` (13 files)
- Code templates in `templates/code/` (9 files: Python, C#, PowerShell, Java, TypeScript)
- Template loaders: `get_infrastructure_template(family, type)` and `get_code_template(family, language)` in `templates/__init__.py`
- Prompt templates in `prompts/` directory (15 files)
- Prompt loader: `load_prompt(name)` in `prompts/__init__.py`
- Tool modules in `tools/` directory (8 modules, 29 tools)
- Tool registration: `register_tools(mcp, data_loader)` in `tools/__init__.py`
- Code analyzers in `analyzers/` directory (8 modules: base, bicep_analyzer, terraform_analyzer, python_analyzer, csharp_analyzer, java_analyzer, typescript_analyzer, cicd_analyzer)
- CVE fetcher module: `cve_fetcher.py` - Live vulnerability data from GitHub Advisory Database / NVD - **NEW**

**Tool Organization:**
- `tools/requirements.py` - Core requirements tools (3 tools)
- `tools/definitions.py` - Definition lookup tools (3 tools)
- `tools/ksi.py` - Key Security Indicator tools (2 tools)
- `tools/documentation.py` - Documentation search tools (3 tools)
- `tools/export.py` - Data export tools (3 tools)
- `tools/enhancements.py` - Implementation guidance tools (9 tools: 7 enhancement + 2 implementation mapping)
- `tools/evidence.py` - Evidence automation tools (3 tools)
- `tools/analyzer.py` - Code analysis tools (2 tools)
- `tools/audit.py` - Coverage audit tools (2 tools)
- `tools/security.py` - CVE vulnerability checking tools (2 tools) - **NEW**
- Each module has `*_impl` functions, registered via wrappers in `tools/__init__.py`

**Analyzer Organization:**
- `analyzers/base.py` - Base classes (Finding, AnalysisResult, Severity, BaseAnalyzer)
- `analyzers/bicep_analyzer.py` - BicepAnalyzer (55 KSIs across 7 phases) - SPLIT FROM iac_analyzer.py in Phase 6B
- `analyzers/terraform_analyzer.py` - TerraformAnalyzer (55 KSIs across 7 phases) - SPLIT FROM iac_analyzer.py in Phase 6B
- `analyzers/python_analyzer.py` - PythonAnalyzer (8 KSIs)
- `analyzers/csharp_analyzer.py` - CSharpAnalyzer (8 KSIs) - **NEW: Multi-language support**
- `analyzers/java_analyzer.py` - JavaAnalyzer (8 KSIs) - **NEW: Multi-language support**
- `analyzers/typescript_analyzer.py` - TypeScriptAnalyzer (8 KSIs) - **NEW: Multi-language support**
- `analyzers/cicd_analyzer.py` - CICDAnalyzer (6 KSIs)
- **Phase 1 (8 KSIs - Foundation):** MLA-05, SVC-06, CNA-01, IAM-03, SVC-03, IAM-01, SVC-08, PIY-02
- **Phase 2 (9 KSIs - Critical Infrastructure):** IAM-02, IAM-06, CNA-02, CNA-04, CNA-06, SVC-04, SVC-05, MLA-01, MLA-02
- **Phase 3 (8 KSIs - Secure Coding):** SVC-01, SVC-02, SVC-07, PIY-01, PIY-03, CNA-07, IAM-04, IAM-07
- **Phase 4 (6 KSIs - DevSecOps Automation):** CMT-01, CMT-02, CMT-03, AFR-01, AFR-02, CED-01
- **Phase 5 (6 KSIs - Runtime Security & Monitoring):** MLA-03, MLA-04, MLA-06, INR-01, INR-02, AFR-03
- **Phase 6A (8 KSIs - Infrastructure Resilience):** RPL-01, RPL-02, RPL-03, RPL-04, CNA-03, CNA-05, IAM-05, AFR-11
- **Phase 6B (8 KSIs - Advanced Infrastructure Security):** SVC-09, SVC-10, MLA-07, MLA-08, AFR-07, CNA-08, INR-03, CMT-04
- **Phase 7 (2 KSIs - Supply Chain & Third-Party Security):** TPR-03, TPR-04
- **Coverage:** 55 KSIs out of 65 active (84.6%) - **Maximum practical code-detectable coverage achieved**

## Development Rules

### Code Standards
- Use Python 3.10+
- Use MCP Python SDK 1.2.0+
- Do not print to stdout (use logging to stderr)
- Use STDIO transport for MCP server
- Avoid Unicode symbols in test output (use ASCII-safe markers like ✅/❌ for Windows compatibility)
- **NEVER use deprecated functionality** - Always verify that libraries, actions, APIs, or methods are actively maintained and not deprecated before recommending or implementing them

### Testing & Commit Workflow (CRITICAL - MUST FOLLOW)
**ALWAYS run and verify ALL tests pass locally BEFORE committing to main:**

1. **Set GitHub Token** (required for CVE tests):
   ```powershell
   $env:GITHUB_TOKEN = (gh auth token)
   ```

2. **Run Full Test Suite**:
   ```powershell
   # For specific test file:
   python tests/test_dependency_checking.py
   
   # For all tests:
   python tests/run_all_tests.py
   ```

3. **Verify ALL Tests Pass**:
   - Review actual test output (do NOT assume tests pass)
   - Look for "ALL TESTS PASSED ✓" message
   - Check for any failures, errors, or warnings
   - Count passing vs. total tests

4. **Only Commit After Verification**:
   - Bundle related fixes into a single, well-tested commit
   - Do NOT commit multiple times hoping tests will pass
   - Do NOT push to main without local verification
   - Include test results summary in commit message

5. **Test Commands by Category**:
   - Dependency checking: `python tests/test_dependency_checking.py`
   - Code analyzer: `python tests/test_code_analyzer.py`
   - C# analyzer: `python tests/test_csharp_analyzer.py`
   - All tools: `python tests/test_all_tools.py`

**Why This Matters:**
- GitHub Actions will fail if tests don't pass locally
- Multiple failed commits create noise in commit history
- Wastes time debugging in CI instead of locally
- Protected branches may block or delay merges

**Failure to follow this process is unacceptable and wastes everyone's time.**

### Version Management (CRITICAL - MUST DO FOR EVERY RELEASE)
**When creating a new release, ALWAYS update all 3 version files simultaneously:**

1. **pyproject.toml** - `version = "X.Y.Z"` (line 3)
2. **server.json** - `"version": "X.Y.Z"` (TWO locations: top-level and in packages array)
3. **src/fedramp_20x_mcp/__init__.py** - `__version__ = "X.Y.Z"` (line 8)

**Version Update Checklist:**
- [ ] Update pyproject.toml version
- [ ] Update server.json top-level version
- [ ] Update server.json packages[0].version
- [ ] Update __init__.py __version__
- [ ] Commit with message "Version X.Y.Z: [description]"
- [ ] Create annotated tag: `git tag -a vX.Y.Z -m "Release vX.Y.Z: [description]"`
- [ ] Push with tags: `git push origin main --tags`

**Why This Matters:**
- PyPI rejects duplicate versions (causes publish failures)
- MCP server registry requires consistent versions
- Python module version must match package version
- Inconsistent versions confuse users and tools

**Failure to update all 3 files will break the release process!**

### Content Sourcing Requirements (CRITICAL)
**All recommendations, guidance, and code examples MUST be sourced to authoritative content:**

1. **FedRAMP Requirements Sourcing:**
   - Every FedRAMP requirement reference MUST cite specific requirement IDs (e.g., "FRR-ADS-01", "KSI-IAM-01")
   - Cite specific FedRAMP 20x families: ADS, AFR, CCM, CNA, CMT, FSI, IAM, ICP, MAS, MLA, PIY, PVA, RPL, RSC, SCN, SVC, TPR, UCM, VDR
   - Reference official FedRAMP 20x documentation from https://github.com/FedRAMP/docs when appropriate
   - Never make assumptions about FedRAMP requirements without citing source

2. **Azure/Cloud Architecture Sourcing:**
   - Azure service recommendations MUST reference Azure Well-Architected Framework (WAF) pillars:
     * Security: https://learn.microsoft.com/azure/well-architected/security/
     * Reliability: https://learn.microsoft.com/azure/well-architected/reliability/
     * Performance Efficiency: https://learn.microsoft.com/azure/well-architected/performance-efficiency/
     * Cost Optimization: https://learn.microsoft.com/azure/well-architected/cost-optimization/
     * Operational Excellence: https://learn.microsoft.com/azure/well-architected/operational-excellence/
   - Infrastructure as Code MUST follow Azure Cloud Adoption Framework (CAF) naming conventions:
     * https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/resource-naming
   - Azure security recommendations MUST cite Azure Security Benchmark:
     * https://learn.microsoft.com/security/benchmark/azure/
   - Service-specific guidance MUST link to official Microsoft Learn documentation

3. **Validation Requirements:**
   - Before adding new guidance, verify sources are current and authoritative
   - Check that FedRAMP requirement IDs exist in loaded data
   - Verify Azure service recommendations are production-ready and FedRAMP-authorized where applicable
   - Document any assumptions or general best practices as such (not authoritative requirements)

4. **Examples of Proper Sourcing:**
   - ✅ "Configure Azure Bastion for secure RDP/SSH per Azure WAF Security (https://learn.microsoft.com/azure/bastion/bastion-overview) to address KSI-CNA-01"
   - ✅ "Use Azure Key Vault per Azure WAF Security pillar (https://learn.microsoft.com/azure/key-vault/) for KSI-SVC-06 compliance"
   - ✅ "Follow Azure CAF naming conventions (https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/resource-naming)"
   - ❌ "Use encryption everywhere" (too general, no source)
   - ❌ "Azure recommends..." (cite specific WAF pillar or documentation)

5. **Where Sourcing Applies:**
   - All tool outputs (especially `validate_architecture`, `get_cloud_native_guidance`, `get_implementation_examples`)
   - All prompt templates (comprehensive guides)
   - All infrastructure templates (Bicep/Terraform comments)
   - All code templates (code comments and documentation strings)
   - README examples and guidance

### Project Structure
- Infrastructure templates: `templates/{bicep,terraform}/` directory (7 templates each)
- Code templates: `templates/code/` directory (7 templates: Python, C#, PowerShell)
- Prompt templates: `prompts/` directory (15 prompts)
- Tool modules: `tools/` directory (9 modules, 31 tools)
- Tests: `tests/` directory (21 test files)
- Analyzers: `analyzers/` directory (8 modules: base, bicep_analyzer, terraform_analyzer, python_analyzer, csharp_analyzer, java_analyzer, typescript_analyzer, cicd_analyzer)

### Template & Prompt Management
- Use `get_infrastructure_template(family, type)` to load infrastructure templates
- Use `get_code_template(family, language)` to load code generation templates
- Use `load_prompt(name)` to load prompt templates
- Templates fall back to generic when family-specific versions don't exist
- All templates must have comments/documentation
- Keep prompts focused and under 30KB

### Tool Development
- Tools use registration pattern: `*_impl` functions in modules, wrappers with `@mcp.tool()` in `tools/__init__.py`
- To add new tool: 
  1. Create `*_impl` function in appropriate module (`tools/requirements.py`, `tools/definitions.py`, etc.)
  2. Add wrapper in `tools/__init__.py`
  3. Create corresponding test in `tests/test_*_tools.py`
  4. Update `TESTING.md` with new test documentation

### Test Hygiene (Critical)
- **ALWAYS create tests** when adding new tools, templates, or prompts
- Test files must validate actual functionality, not just existence
- Include both success and error cases in tests
- Test file naming: `test_<component>_tools.py` for tools, `test_<resource>.py` for resources
- Run all tests before committing: `python tests/test_*.py`
- Update `TESTING.md` immediately when adding new tests

### Test Organization (21 test files)
**Core Functionality (8 files):**
- `test_loader.py` - Data loading validation
- `test_definitions.py` - Definition/KSI lookup
- `test_docs_integration.py` - Documentation loading
- `test_implementation_questions.py` - Question generation
- `test_tool_registration.py` - Architecture validation
- `test_evidence_automation.py` - IaC generation
- `test_code_analyzer.py` - Code analysis engine (96 tests: 13 Phase 1, 18 Phase 3, 12 Phase 4, 12 Phase 5, 16 Phase 6A, 16 Phase 6B, 9 Phase 7)
- `test_all_tools.py` - Integration testing

**Tool Functional Tests (11 files):**
- `test_requirements_tools.py` - Requirements tools (get_control, list_family_controls, search_requirements)
- `test_definitions_tools.py` - Definition tools (get_definition, list_definitions, search_definitions)
- `test_ksi_tools.py` - KSI tools (get_ksi, list_ksi)
- `test_documentation_tools.py` - Documentation tools (search, get_file, list_files)
- `test_export_tools.py` - Export tools (excel, csv, ksi_specification)
- `test_enhancement_tools.py` - 7 enhancement tools (compare, examples, dependencies, etc.)
- `test_analyzer_tools.py` - Analyzer MCP tools (10 tests)
- `test_audit_tools.py` - Audit tools (get_ksi_coverage_summary, get_ksi_coverage_status)
- `test_enhancement_tools.py` - 7 enhancement tools (compare, examples, dependencies, etc.)
- `test_analyzer_tools.py` - Analyzer MCP tools (10 tests)
- `test_csharp_analyzer.py` - C# analyzer (12 security checks: ASP.NET Core, Entity Framework, Azure SDK)
- `test_java_analyzer.py` - Java analyzer (12 security checks: Spring Boot, Spring Security, Azure SDK)
- `test_typescript_analyzer.py` - TypeScript/JS analyzer (12 security checks: Express, NestJS, React, Azure SDK)

**Resource Validation (2 files):**
- `test_prompts.py` - All 15 prompt templates
- `test_templates.py` - All 21 infrastructure/code templates

### Documentation Standards
- **Single source of truth**: Keep all documentation consolidated in primary files
- **TESTING.md** - Primary testing documentation (DO NOT create separate summary files)
- **README.md** - User-facing documentation
- **copilot-instructions.md** - This file, for development guidance
- Update documentation immediately when making changes
- Include metrics and examples in documentation
- Document fallback behavior for templates/resources

### Adding New Features Checklist
1. ✅ Implement feature in appropriate module
2. ✅ Create comprehensive tests (success + error cases)
3. ✅ Update `TESTING.md` with test documentation
4. ✅ Update this file (`copilot-instructions.md`) with feature details
5. ✅ Run full test suite to ensure no regressions
6. ✅ Update `README.md` if user-facing changes
7. ✅ Commit with descriptive message including test results
