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
    from . import requirements, definitions, ksi, documentation, export, enhancements, evidence, analyzer, audit, security
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
        """List all Key Security Indicators."""
        return await ksi.list_ksi_impl(data_loader)
    
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
    
    logger.info("Registered 33 tools across 10 modules")
