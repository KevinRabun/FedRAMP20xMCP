# Copilot Instructions for FedRAMP 20x MCP Server

## Project Overview
MCP server that loads FedRAMP 20x requirements from JSON files and official documentation markdown files, provides 48 MCP tools for querying requirements, and includes KSI-centric code analyzers for compliance checking across multiple languages.

## Critical: OSCAL Format Requirements
FedRAMP 20x requires **machine-readable** formats (JSON/XML/structured data) for FRR-ADS. **OSCAL is NOT mentioned in FedRAMP 20x requirements** - it's one optional NIST-based implementation approach. Source: FRR-ADS-01 specifies "machine-readable" only.

## Data & Capabilities
- **199 FedRAMP Requirements (FRRs)** from 10 families (ADS, CCM, FSI, ICP, MAS, PVA, RSC, SCN, UCM, VDR)
- **50 FedRAMP Definitions** (FRD family)
- **72 Key Security Indicators (KSIs)** from 11 families (AFR, CED, CMT, CNA, IAM, INR, MLA, PIY, RPL, SVC, TPR)
- **48 MCP tools** organized in 13 modules
- **Multi-language code analyzers**: Python, C#/.NET, Java, TypeScript/JavaScript, Bicep, Terraform, CI/CD pipelines
- **1-hour caching** with automatic refresh

## KSI Implementation Status
**Accurate Counts (verified via factory and authoritative source):**
- **72 total KSIs**
- **65 active KSIs** (7 retired)
- **41 code-detectable KSIs** (63.1% of active)
- **24 process-based KSIs** (36.9% of active)
- **38 implemented KSIs** (58.5% of active code-detectable)

**Retired KSIs (7):**
- KSI-CMT-05 (superseded by KSI-AFR-05 SCN)
- KSI-MLA-03, KSI-MLA-04, KSI-MLA-06 (superseded by KSI-AFR-04 VDR)
- KSI-SVC-03 (superseded by KSI-AFR-11 UCM)
- KSI-TPR-01, KSI-TPR-02 (superseded by KSI-AFR-01 MAS)

**Complete Families (5/10):** IAM, SVC, CNA, TPR, CMT
**Significantly Complete:** MLA (5/8 active), PIY (2/2 code-detectable), AFR (active), INR (1/1 code-detectable)

**Authoritative Data Sync:**
- The factory's `sync_with_authoritative_data(data_loader)` method ensures RETIRED status stays current
- Called automatically by `list_ksi` and `get_ksi_implementation_status` tools
- Compares analyzer RETIRED flags against GitHub FedRAMP/docs JSON data
- Dynamically updates analyzer metadata at runtime when discrepancies detected
- Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json

## Code Organization
- Infrastructure templates in `templates/bicep/` and `templates/terraform/`
- Code templates in `templates/code/` (Python, C#, PowerShell, Java, TypeScript)
- Prompt templates in `prompts/` directory (15 files)
- Tool modules in `tools/` directory (13 modules, 48 tools)
- Code analyzers in `analyzers/ksi/` directory (72 KSI analyzer files + factory + base)
- CVE fetcher module: `cve_fetcher.py` - Live vulnerability data from GitHub Advisory Database / NVD

## Azure Service Recommendations
**Microsoft Defender for Cloud:** Recommended (not mandatory) for FedRAMP 20x compliance
- **Where mentioned:** ~8-10 KSIs across AFR, PIY, TPR families
- **Why recommended:** Native Azure integration, FedRAMP authorized, streamlines vulnerability scanning, security posture management, and automated evidence collection
- **Alternatives:** Qualys, Tenable (vulnerability scanning); Azure Policy (compliance); Azure Resource Graph + custom scripts (inventory)
- **Guidance:** Use Defender for Cloud unless you have existing security tooling or specific requirements for alternative solutions

**Analyzer Architecture (KSI-Centric):**
- `analyzers/base.py` - Base classes (Finding, AnalysisResult, Severity)
- `analyzers/ksi/base.py` - BaseKSIAnalyzer class for all KSI analyzers
- `analyzers/ksi/factory.py` - KSIAnalyzerFactory for unified KSI analysis
- `analyzers/ksi/ksi_*.py` - 72 individual KSI analyzer files
- Each KSI analyzer supports: Application code (Python, C#, Java, TypeScript/JavaScript), IaC (Bicep, Terraform), CI/CD (GitHub Actions, Azure Pipelines, GitLab CI)

**Factory Pattern Usage:**
- `get_factory()` - Get singleton factory instance
- `factory.analyze(ksi_id, code, language, file_path)` - Analyze code for specific KSI
- `factory.analyze_all_ksis(code, language, file_path)` - Analyze against all KSIs
- `factory.get_analyzer(ksi_id)` - Get specific KSI analyzer instance
- `factory.list_ksis()` - List all 72 registered KSI IDs

## KSI Analyzer Implementation Requirements

### AST-First Analysis (CRITICAL)
**When creating, updating, or reviewing KSI analyzers, ALWAYS prioritize tree-sitter AST over regex:**

1. **Primary Approach: Tree-Sitter AST**
   - Use `analyzers/ast_utils.py` helper functions for all supported languages
   - AST provides accurate, context-aware code analysis
   - Reduces false positives by understanding code structure
   - Supports: Python, C#, Java, TypeScript/JavaScript, Bicep, Terraform

2. **Fallback: Regex Only When Necessary**
   - Use regex ONLY when tree-sitter is unavailable for the language/platform
   - Examples: GitLab CI YAML, Azure Pipelines YAML (no tree-sitter support)
   - Document why regex is used with `# Note: Using regex - tree-sitter not available for [language]`

3. **AST Helper Functions Available:**
   - `find_nodes_by_type(tree, node_type)` - Find all nodes of specific type
   - `get_node_text(node, code)` - Extract text from AST node
   - `find_function_calls(tree, function_name)` - Find all calls to specific function
   - `find_class_definitions(tree)` - Find all class definitions
   - `find_method_definitions(tree, class_name)` - Find methods in specific class
   - `check_attribute_usage(tree, attribute_name)` - Check for attribute/decorator usage

4. **Implementation Pattern:**
   ```python
   from analyzers.ast_utils import parse_code, find_function_calls, get_node_text
   
   # Good: AST-based analysis
   tree = parse_code(code, language)
   if tree:
       # Use AST helpers for accurate detection
       calls = find_function_calls(tree, "dangerous_function")
   
   # Bad: Regex when AST is available
   # if re.search(r'dangerous_function\(', code):  # DON'T DO THIS
   ```

5. **Review Checklist for KSI Analyzers:**
   - [ ] Does language have tree-sitter support? (Python, C#, Java, TS/JS, Bicep, Terraform = YES)
   - [ ] Using AST helpers from `ast_utils.py` instead of regex?
   - [ ] Fallback regex only for unsupported languages with documentation?
   - [ ] Tests verify AST-based detection accuracy?

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
**All recommendations must cite authoritative sources:**

1. **FedRAMP Requirements:** Cite specific IDs (e.g., "FRR-ADS-01", "KSI-IAM-01")
2. **Azure/Cloud:** Reference Azure Well-Architected Framework, Cloud Adoption Framework, or Security Benchmark
3. **Validation:** Verify sources are current and authoritative before adding guidance

**Examples:**
- ✅ "Configure Azure Bastion per Azure WAF Security to address KSI-CNA-01"
- ❌ "Use encryption everywhere" (too general, no source)

### Project Structure
- Infrastructure templates: `templates/{bicep,terraform}/`
- Code templates: `templates/code/`
- Prompt templates: `prompts/` (15 prompts)
- Tool modules: `tools/` (13 modules, 48 tools)
- Tests: `tests/` (70+ test files)
- Analyzers: `analyzers/ksi/` (72 KSI analyzer files + factory + base)
- FRR Analyzers: `analyzers/frr/` (199 FRR analyzer files + factory + base)

### Template & Prompt Management
- Use `get_infrastructure_template(family, type)` to load infrastructure templates
- Use `get_code_template(family, language)` to load code generation templates
- Use `load_prompt(name)` to load prompt templates
- Templates fall back to generic when family-specific versions don't exist

### Tool Development
- Tools use registration pattern: `*_impl` functions in modules, wrappers with `@mcp.tool()` in `tools/__init__.py`
- To add new tool: 
  1. Create `*_impl` function in appropriate module
  2. Add wrapper in `tools/__init__.py`
  3. Create corresponding test in `tests/test_*_tools.py`

### Test Hygiene (Critical)
- **ALWAYS create tests** when adding new tools, templates, or prompts
- Include both success and error cases
- Run all tests before committing: `python tests/run_all_tests.py`
- Update `TESTING.md` immediately when adding new tests
