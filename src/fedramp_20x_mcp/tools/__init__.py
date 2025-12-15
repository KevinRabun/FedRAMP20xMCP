"""
FedRAMP 20x MCP Server - Tools Module

This module organizes all MCP tool functions into logical groups.
Each submodule contains related tools that are registered with the MCP server.
"""
import json
import logging
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from mcp.server.fastmcp import FastMCP
    from ..data_loader import FedRAMPDataLoader

logger = logging.getLogger(__name__)


def register_tools(mcp: "FastMCP", data_loader: "FedRAMPDataLoader"):
    """
    Register all tool functions with the MCP server.
    
    Args:
        mcp: The FastMCP server instance
        data_loader: The data loader instance for accessing FedRAMP data
    """
    # Import all tool modules
    from . import requirements, definitions, ksi, frr, documentation, export, enhancements, evidence, analyzer, audit, security, ksi_status, validation, code_enrichment
    from ..templates import get_infrastructure_template, get_code_template
    
    # Requirements tools
    @mcp.tool()
    async def get_control(control_id: str) -> str:
        """Get detailed information about a specific FedRAMP 20x requirement."""
        return await requirements.get_control_impl(control_id, data_loader)
    
    @mcp.tool()
    async def list_family_controls(family: str) -> str:
        """List all requirements within a specific document family."""
        return await requirements.list_family_controls_impl(family, data_loader)
    
    @mcp.tool()
    async def search_requirements(keywords: str) -> str:
        """Search for FedRAMP 20x requirements containing specific keywords."""
        return await requirements.search_requirements_impl(keywords, data_loader)
    
    # Definition tools
    @mcp.tool()
    async def get_definition(term: str) -> str:
        """Get the FedRAMP definition for a specific term."""
        return await definitions.get_definition_impl(term, data_loader)
    
    @mcp.tool()
    async def list_definitions() -> str:
        """List all FedRAMP definitions with their terms."""
        return await definitions.list_definitions_impl(data_loader)
    
    @mcp.tool()
    async def search_definitions(keywords: str) -> str:
        """Search FedRAMP definitions by keywords."""
        return await definitions.search_definitions_impl(keywords, data_loader)
    
    # KSI tools
    @mcp.tool()
    async def get_ksi(ksi_id: str) -> str:
        """Get detailed information about a specific Key Security Indicator."""
        return await ksi.get_ksi_impl(ksi_id, data_loader)
    
    @mcp.tool()
    async def list_ksi() -> str:
        """
        List all Key Security Indicators with their implementation status.
        
        Returns a comprehensive list showing:
        - Implementation status (Implemented/Not Implemented/Retired)
        - Code detectability (Code-Detectable vs Process-Based)
        - Organized by family
        - Summary statistics
        """
        return await ksi.list_ksi_impl(data_loader)
    
    @mcp.tool()
    async def get_ksi_implementation_summary() -> str:
        """
        Get a summary of KSI implementation status across all families.
        
        Returns statistics showing:
        - Overall implementation coverage
        - Breakdown by family
        - Code-detectable vs process-based KSIs
        - Retired KSIs
        """
        return await ksi.get_ksi_implementation_summary_impl(data_loader)
    
    @mcp.tool()
    async def get_ksi_evidence_automation(ksi_id: str) -> str:
        """
        Get evidence automation recommendations for a specific KSI.
        
        Provides detailed guidance on automating evidence collection including:
        - Azure services needed
        - Collection methods and schedules
        - Storage requirements and retention
        - FRR-ADS API integration
        - Code examples and infrastructure templates
        - Implementation effort and prerequisites
        
        Args:
            ksi_id: The KSI identifier (e.g., "KSI-IAM-01", "KSI-CNA-01")
        
        Returns:
            Comprehensive evidence automation recommendations
        """
        return await ksi.get_ksi_evidence_automation_impl(ksi_id, data_loader)
    
    @mcp.tool()
    async def get_ksi_evidence_queries(ksi_id: str) -> str:
        """
        Get evidence collection queries for a specific KSI.
        
        Returns ready-to-use queries for collecting evidence from Azure:
        - KQL queries for Log Analytics
        - Azure Resource Graph queries
        - REST API calls for Microsoft Graph
        
        Args:
            ksi_id: The KSI identifier (e.g., "KSI-IAM-01", "KSI-CNA-01")
        
        Returns:
            Collection queries with descriptions and usage guidance
        """
        return await ksi.get_ksi_evidence_queries_impl(ksi_id, data_loader)
    
    @mcp.tool()
    async def get_ksi_evidence_artifacts(ksi_id: str) -> str:
        """
        Get list of evidence artifacts to collect for a specific KSI.
        
        Returns detailed information about what artifacts to collect:
        - Artifact names and types (logs, configs, reports)
        - Collection methods and frequency
        - File formats and retention requirements
        
        Args:
            ksi_id: The KSI identifier (e.g., "KSI-IAM-01", "KSI-CNA-01")
        
        Returns:
            Evidence artifacts list with collection details
        """
        return await ksi.get_ksi_evidence_artifacts_impl(ksi_id, data_loader)
    
    # FRR (FedRAMP Requirements) tools
    @mcp.tool()
    async def analyze_frr_code(
        frr_id: str,
        code: str,
        language: str,
        file_path: Optional[str] = None
    ) -> str:
        """
        Analyze code against a specific FedRAMP requirement (FRR).
        
        Detects compliance issues in application code, infrastructure as code,
        or CI/CD pipelines for the specified FRR.
        
        Args:
            frr_id: FRR identifier (e.g., "FRR-VDR-01", "FRR-RSC-01")
            code: Code to analyze
            language: Language/platform (python, csharp, java, typescript, bicep, terraform, 
                     github-actions, azure-pipelines, gitlab-ci)
            file_path: Optional file path for context
        
        Returns:
            Analysis results with findings and recommendations
        """
        return await frr.analyze_frr_code_impl(frr_id, code, language, file_path, data_loader)
    
    @mcp.tool()
    async def analyze_all_frrs(
        code: str,
        language: str,
        file_path: Optional[str] = None
    ) -> str:
        """
        Analyze code against all FedRAMP requirements.
        
        Performs comprehensive analysis across all 199 FRR requirements.
        
        Args:
            code: Code to analyze
            language: Language/platform
            file_path: Optional file path for context
        
        Returns:
            Complete analysis results grouped by family
        """
        return await frr.analyze_all_frrs_impl(code, language, file_path, data_loader)
    
    @mcp.tool()
    async def analyze_frr_family(
        family: str,
        code: str,
        language: str,
        file_path: Optional[str] = None
    ) -> str:
        """
        Analyze code against all requirements in a specific FRR family.
        
        Args:
            family: Family code (VDR, RSC, UCM, SCN, ADS, CCM, MAS, ICP, FSI, PVA, KSI)
            code: Code to analyze
            language: Language/platform
            file_path: Optional file path for context
        
        Returns:
            Analysis results for the specified family
        """
        return await frr.analyze_frr_family_impl(family, code, language, file_path, data_loader)
    
    @mcp.tool()
    async def list_frrs_by_family(family: str) -> str:
        """
        List all FRR requirements in a specific family.
        
        Shows implementation status and code detectability for each FRR.
        
        Args:
            family: Family code (VDR, RSC, UCM, SCN, ADS, CCM, MAS, ICP, FSI, PVA, KSI)
        
        Returns:
            List of FRRs with status indicators
        """
        return await frr.list_frrs_by_family_impl(family, data_loader)
    
    @mcp.tool()
    async def get_frr_metadata(frr_id: str) -> str:
        """
        Get detailed metadata for a specific FRR.
        
        Returns NIST controls, related KSIs, impact levels, and detection strategy.
        
        Args:
            frr_id: FRR identifier (e.g., "FRR-VDR-01")
        
        Returns:
            Detailed FRR metadata
        """
        return await frr.get_frr_metadata_impl(frr_id, data_loader)
    
    @mcp.tool()
    async def get_frr_evidence_automation(frr_id: str) -> str:
        """
        Get evidence automation recommendations for a specific FRR.
        
        Provides detailed guidance on automating evidence collection including:
        - Azure services needed
        - Collection methods and queries (KQL, REST API)
        - Storage requirements
        - Evidence artifacts to collect
        
        Args:
            frr_id: FRR identifier (e.g., "FRR-VDR-01")
        
        Returns:
            Evidence automation recommendations
        """
        return await frr.get_frr_evidence_automation_impl(frr_id, data_loader)
    
    @mcp.tool()
    async def get_frr_implementation_status() -> str:
        """
        Get implementation status summary across all FRR analyzers.
        
        Shows statistics by family with implementation rates.
        
        Returns:
            Status summary with family breakdown
        """
        return await frr.get_frr_implementation_status_impl(data_loader)
    
    # Documentation tools
    @mcp.tool()
    async def search_documentation(keywords: str) -> str:
        """Search FedRAMP official documentation by keywords."""
        return await documentation.search_documentation_impl(keywords, data_loader)
    
    @mcp.tool()
    async def get_documentation_file(file_path: str) -> str:
        """Get the full content of a specific FedRAMP documentation file."""
        return await documentation.get_documentation_file_impl(file_path, data_loader)
    
    @mcp.tool()
    async def list_documentation_files() -> str:
        """List all available FedRAMP documentation files."""
        return await documentation.list_documentation_files_impl(data_loader)
    
    # Export tools
    @mcp.tool()
    async def export_to_excel(export_type: str, output_path: str = "") -> str:
        """Export FedRAMP 20x data to Excel format."""
        return await export.export_to_excel(export_type, output_path)
    
    @mcp.tool()
    async def export_to_csv(export_type: str, output_path: str = "") -> str:
        """Export FedRAMP 20x data to CSV format."""
        return await export.export_to_csv(export_type, output_path)
    
    @mcp.tool()
    async def generate_ksi_specification(ksi_id: str, evidence_collection_strategy: str, output_path: str = "") -> str:
        """Generate a detailed product specification document for a KSI."""
        return await export.generate_ksi_specification(ksi_id, evidence_collection_strategy, output_path)
    
    # Enhancement tools
    @mcp.tool()
    async def compare_with_rev4(requirement_area: str) -> str:
        """Compare FedRAMP 20x requirements to Rev 4/Rev 5 to understand changes."""
        result = await enhancements.compare_with_rev4_impl(requirement_area, data_loader)
        return result + audit.get_coverage_disclaimer()
    
    @mcp.tool()
    async def get_implementation_examples(requirement_id: str) -> str:
        """Get practical implementation examples for a requirement."""
        result = await enhancements.get_implementation_examples_impl(requirement_id, data_loader)
        return result + audit.get_coverage_disclaimer()
    
    @mcp.tool()
    async def check_requirement_dependencies(requirement_id: str) -> str:
        """Show which requirements are related or dependent on a specific requirement."""
        return await enhancements.check_requirement_dependencies_impl(requirement_id, data_loader)
    
    @mcp.tool()
    async def estimate_implementation_effort(requirement_id: str) -> str:
        """Provide rough effort estimates for implementing a specific requirement."""
        return await enhancements.estimate_implementation_effort_impl(requirement_id, data_loader)
    
    @mcp.tool()
    async def get_cloud_native_guidance(technology: str) -> str:
        """Get cloud-native specific guidance for implementing FedRAMP 20x."""
        result = await enhancements.get_cloud_native_guidance_impl(technology, data_loader)
        return result + audit.get_coverage_disclaimer()
    
    @mcp.tool()
    async def validate_architecture(architecture_description: str) -> str:
        """Validate a cloud architecture against FedRAMP 20x requirements."""
        result = await enhancements.validate_architecture_impl(architecture_description, data_loader)
        return result + audit.get_coverage_disclaimer()
    
    @mcp.tool()
    async def generate_implementation_questions(requirement_id: str) -> str:
        """Generate strategic questions for PMs and engineers about implementing a requirement."""
        return await enhancements.generate_implementation_questions_impl(requirement_id, data_loader)
    
    @mcp.tool()
    async def get_ksi_implementation_matrix(ksi_family: str) -> str:
        """Get implementation matrix showing all KSIs in a family with Azure services, effort, and priority."""
        return await enhancements.get_ksi_implementation_matrix_impl(ksi_family, data_loader)
    
    @mcp.tool()
    async def generate_implementation_checklist(ksi_id: str) -> str:
        """Generate actionable step-by-step implementation checklist for a specific KSI."""
        return await enhancements.generate_implementation_checklist_impl(ksi_id, data_loader)
    
    # Evidence automation tools
    @mcp.tool()
    async def get_infrastructure_code_for_ksi(ksi_id: str, infrastructure_type: str = "bicep") -> str:
        """Generate infrastructure code templates for automating KSI evidence collection."""
        result = await evidence.get_infrastructure_code_for_ksi_impl(ksi_id, data_loader, get_infrastructure_template, infrastructure_type)
        return result + audit.get_coverage_disclaimer()
    
    @mcp.tool()
    async def get_evidence_collection_code(ksi_id: str, language: str = "python") -> str:
        """Provide code examples for collecting KSI evidence programmatically."""
        result = await evidence.get_evidence_collection_code_impl(ksi_id, data_loader, get_code_template, language)
        return result + audit.get_coverage_disclaimer()
    
    @mcp.tool()
    async def get_evidence_automation_architecture(ksi_category: str = "all") -> str:
        """Provide comprehensive architecture guidance for automated evidence collection."""
        result = await evidence.get_evidence_automation_architecture_impl(data_loader, ksi_category)
        return result + audit.get_coverage_disclaimer()
    
    # Code analyzer tools
    @mcp.tool()
    async def analyze_infrastructure_code(code: str, file_type: str, file_path: Optional[str] = None, context: Optional[str] = None) -> dict:
        """Analyze Infrastructure as Code (Bicep/Terraform) for FedRAMP 20x compliance issues."""
        return await analyzer.analyze_infrastructure_code_impl(code, file_type, file_path, context)
    
    @mcp.tool()
    async def validate_fedramp_config(code: str, file_type: str, strict_mode: bool = True) -> dict:
        """
        Validate Infrastructure as Code against FedRAMP 20x MANDATORY requirements BEFORE generating/deploying.
        
        🚨 USE THIS TOOL BEFORE FINALIZING ANY TEMPLATE/CODE 🚨
        
        This tool checks for CRITICAL violations that will cause compliance failures:
        - Log Analytics retention < 730 days (CRITICAL)
        - Platform-managed keys instead of Customer-Managed Keys (CRITICAL)
        - Key Vault Standard SKU instead of Premium (CRITICAL)
        - Public access enabled instead of disabled (CRITICAL)
        - Missing diagnostic settings (HIGH)
        
        Returns:
        - passed: bool - Whether ALL validations passed
        - violations: list - CRITICAL issues that MUST be fixed
        - warnings: list - Non-critical issues that SHOULD be fixed
        - compliant_values: list - Requirements that passed validation
        
        Example usage:
        1. Generate Bicep/Terraform code
        2. Call validate_fedramp_config with the code
        3. If violations exist, FIX THEM before deploying
        4. If passed=true, code meets FedRAMP 20x requirements
        """
        return await validation.validate_fedramp_config_impl(code, file_type, strict_mode)
    
    @mcp.tool()
    async def analyze_application_code(code: str, language: str, file_path: Optional[str] = None, dependencies: Optional[list[str]] = None) -> dict:
        """Analyze application code (Python) for FedRAMP 20x security compliance issues."""
        return await analyzer.analyze_application_code_impl(code, language, file_path, dependencies)
    
    @mcp.tool()
    async def analyze_cicd_pipeline(code: str, pipeline_type: str, file_path: Optional[str] = None) -> dict:
        """Analyze CI/CD pipeline configuration (GitHub Actions/Azure Pipelines/GitLab CI) for FedRAMP 20x DevSecOps compliance."""
        return await analyzer.analyze_cicd_pipeline_impl(code, pipeline_type, file_path)
    
    # KSI Coverage Audit tools
    @mcp.tool()
    async def get_ksi_coverage_summary() -> str:
        """
        Get a summary of KSI analyzer coverage and recommendation quality assessment.
        
        Shows which KSIs have analyzer coverage, what limitations exist, and important
        disclaimers about recommendation validation. Use this to understand the scope
        and limitations of automated compliance checking.
        """
        return await audit.get_ksi_coverage_summary_impl(data_loader)
    
    @mcp.tool()
    async def get_ksi_coverage_status(ksi_id: str) -> str:
        """
        Check if a specific KSI has analyzer coverage and what the limitations are.
        
        Args:
            ksi_id: The KSI identifier (e.g., "KSI-MLA-05")
        
        Returns detailed coverage information including which analyzers support this KSI,
        whether it's process-based or technical, and important limitations of the coverage.
        """
        return await audit.get_ksi_coverage_status_impl(ksi_id, data_loader)
    
    # Security tools - CVE vulnerability checking
    @mcp.tool()
    async def check_package_vulnerabilities(
        package_name: str,
        ecosystem: str,
        version: Optional[str] = None,
        github_token: Optional[str] = None
    ) -> str:
        """
        Check a package for known CVE vulnerabilities against authoritative databases.
        
        Queries GitHub Advisory Database (and optionally NVD) for security vulnerabilities
        in the specified package. Returns detailed CVE information, affected versions,
        patched versions, severity ratings, and FedRAMP compliance recommendations.
        
        Args:
            package_name: Package name (e.g., "Newtonsoft.Json", "lodash", "requests", "log4j")
            ecosystem: Package ecosystem - "nuget" (.NET), "npm" (JavaScript/TypeScript), "pypi" (Python), "maven" (Java)
            version: Specific version to check (optional, checks all versions if omitted)
            github_token: GitHub Personal Access Token for higher API rate limits (optional)
        
        Returns:
            JSON with vulnerability details including CVE IDs, severity, CVSS scores,
            affected/patched versions, descriptions, and FedRAMP compliance status.
        
        Example:
            check_package_vulnerabilities("Newtonsoft.Json", "nuget", "12.0.1")
            check_package_vulnerabilities("lodash", "npm")
        
        Maps to FedRAMP 20x requirements:
        - KSI-SVC-08: Secure Dependencies - vulnerability management
        - KSI-TPR-03: Supply Chain Security - third-party risk assessment
        """
        return await security.check_package_vulnerabilities_impl(package_name, ecosystem, version, github_token)
    
    @mcp.tool()
    async def scan_dependency_file(
        file_content: str,
        file_type: str,
        github_token: Optional[str] = None
    ) -> str:
        """
        Scan an entire dependency file for vulnerable packages.
        
        Analyzes dependency manifests and checks all packages against CVE databases.
        Provides comprehensive vulnerability report with prioritized remediation guidance.
        
        Args:
            file_content: Full content of the dependency file
            file_type: Type of file - "csproj", "packages.config", "package.json", "requirements.txt", "pom.xml"
            github_token: GitHub Personal Access Token for higher API rate limits (optional)
        
        Returns:
            JSON with scan results including total vulnerabilities, severity breakdown,
            vulnerable packages list, and prioritized remediation recommendations.
        
        Supported file formats:
        - NuGet: *.csproj (PackageReference), packages.config, Directory.Packages.props
        - npm: package.json, package-lock.json
        - Python: requirements.txt, Pipfile, pyproject.toml
        - Maven: pom.xml
        
        Example:
            scan_dependency_file(csproj_content, "csproj")
            scan_dependency_file(requirements_txt, "requirements.txt")
        
        Maps to FedRAMP 20x requirements:
        - KSI-SVC-08: Secure Dependencies
        - KSI-TPR-03: Supply Chain Security
        - KSI-CMT-01: Continuous Monitoring (automated vulnerability scanning)
        """
        return await security.scan_dependency_file_impl(file_content, file_type, github_token)
    
    # KSI Status tools
    @mcp.tool()
    async def get_ksi_implementation_status() -> str:
        """
        Get comprehensive implementation status of all KSI analyzers.
        
        Dynamically queries each KSI analyzer to report:
        - Total KSIs, active vs retired
        - Implementation status (IMPLEMENTED, PARTIAL, NOT_IMPLEMENTED)
        - Code detectability (CODE_DETECTABLE vs PROCESS_BASED)
        - Status organized by family
        - Implementation percentages
        
        Returns:
            JSON with complete KSI status including:
            - Overall statistics (total, active, implemented, code_detectable)
            - Family-level breakdown
            - Individual KSI details with metadata
            - Implementation and code detectability percentages
        
        This tool eliminates the need to maintain separate tracking documents by
        querying each KSI analyzer's CODE_DETECTABLE and IMPLEMENTATION_STATUS properties.
        
        Example output:
        {
            "total_ksis": 72,
            "active_ksis": 65,
            "retired_ksis": 7,
            "implemented_ksis": 38,
            "code_detectable_ksis": 38,
            "process_based_ksis": 27,
            "implementation_percentage": 58.5,
            "families": {...}
        }
        """
        result = await ksi_status.get_ksi_implementation_status_impl(data_loader)
        return json.dumps(result, indent=2)
    
    @mcp.tool()
    async def get_ksi_family_status(family: str) -> str:
        """
        Get implementation status for a specific KSI family.
        
        Args:
            family: Family code (e.g., "IAM", "SVC", "CNA", "AFR", "MLA")
        
        Returns:
            JSON with family-specific status:
            - Total KSIs in family
            - Active vs retired count
            - Implementation status
            - Code detectability breakdown
            - List of all KSIs with their properties
        
        Supported families:
        - IAM: Identity and Access Management
        - SVC: Service Configuration
        - MLA: Monitoring, Logging, and Alerting
        - CNA: Cloud and Network Architecture
        - AFR: Authorization by FedRAMP
        - TPR: Third-Party Risk
        - CMT: Change Management and Testing
        - RPL: Resiliency and Performance Limits
        - INR: Incident Response
        - PIY: Privacy
        - CED: Cybersecurity Education
        
        Example:
            get_ksi_family_status("IAM")
        """
        result = await ksi_status.get_ksi_family_status_impl(family, data_loader)
        return json.dumps(result, indent=2)
    
    @mcp.tool()
    async def add_requirement_comments(
        code: str,
        ksi_ids: Optional[str] = None,
        frr_ids: Optional[str] = None,
        language: str = "bicep"
    ) -> str:
        """
        Add FedRAMP requirement comments to code or IaC templates.
        
        Enriches generated code with detailed KSI and FRR requirement information
        in comments, ensuring traceability to specific compliance requirements.
        
        Args:
            code: The code or template to enrich
            ksi_ids: Comma-separated KSI IDs (e.g., "KSI-IAM-01,KSI-MLA-01")
            frr_ids: Comma-separated FRR IDs (e.g., "FRR-VDR-01,FRR-ADS-01")
            language: Programming language for comment syntax
                Options: bicep, terraform, python, csharp, java, typescript, powershell
        
        Returns:
            Enriched code with requirement header comments and inline annotations
        
        Example:
            ```bicep
            // Original code:
            resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
              name: 'mykeyvault'
            }
            
            // After enrichment with add_requirement_comments(code, "KSI-SVC-01", "FRR-RSC-01", "bicep"):
            // ==========================================
            // FedRAMP 20x Compliance Requirements
            // ==========================================
            //
            // Key Security Indicators (KSI):
            //
            // KSI-SVC-01: Secrets Management
            //   All secrets must be stored in Azure Key Vault with
            //   soft delete and purge protection enabled.
            //
            // FedRAMP Requirements (FRR):
            //
            // FRR-RSC-01: Recommended Secure Configuration
            //   Apply security baselines and hardening standards.
            // ==========================================
            
            resource kv 'Microsoft.KeyVault/vaults@2023-07-01' = {
              name: 'mykeyvault'
              tags: {
                Compliance: 'FedRAMP 20x'
                Requirements: 'KSI-SVC-01, FRR-RSC-01'
              }
            }
            ```
        
        Use this tool when:
        - Generating Bicep/Terraform infrastructure code
        - Writing C#/Python/Java application code for FedRAMP compliance
        - Need to document which requirements a code block addresses
        - Creating templates or examples for teams
        """
        # Parse comma-separated IDs
        ksi_list = [k.strip() for k in ksi_ids.split(",")] if ksi_ids else None
        frr_list = [f.strip() for f in frr_ids.split(",")] if frr_ids else None
        
        # Generate enriched code
        if language.lower() == "bicep":
            enriched = code_enrichment.enrich_bicep_template(
                code, ksi_list, frr_list, data_loader
            )
            enriched = code_enrichment.add_requirement_tags(
                enriched, ksi_list, frr_list, "bicep"
            )
        elif language.lower() == "csharp":
            enriched = code_enrichment.enrich_csharp_code(
                code, ksi_list, frr_list, data_loader
            )
        else:
            # For other languages, just add header
            header = code_enrichment.get_requirement_header(
                ksi_list, frr_list, data_loader, language
            )
            enriched = f"{header}\n\n{code}"
        
        return enriched
    
    logger.info("Registered 48 tools across 13 modules")
