"""
FRR-RSC-10: Versioning and Release History

Providers SHOULD provide versioning and a release history for recommended secure default settings for _top-level administrative accounts_ and _privileged accounts_ as they are adjusted over time.

Official FedRAMP 20x Requirement
Source: FRR-RSC (Resource Categorization) family
Primary Keyword: SHOULD
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_RSC_10_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-RSC-10: Versioning and Release History
    
    **Official Statement:**
    Providers SHOULD provide versioning and a release history for recommended secure default settings for _top-level administrative accounts_ and _privileged accounts_ as they are adjusted over time.
    
    **Family:** RSC - Resource Categorization
    
    **Primary Keyword:** SHOULD
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    - High: Yes
    
    **NIST Controls:**
    - TODO: Add relevant NIST controls
    
    **Related KSIs:**
    - TODO: Add related KSI IDs
    
    **Detectability:** Unknown
    
    **Detection Strategy:**
    TODO: Describe what this analyzer detects and how:
        1. Application code patterns (Python, C#, Java, TypeScript) - Use AST
        2. Infrastructure patterns (Bicep, Terraform) - Use regex
        3. CI/CD patterns (GitHub Actions, Azure Pipelines, GitLab CI) - Use regex
    
    """
    
    FRR_ID = "FRR-RSC-10"
    FRR_NAME = "Versioning and Release History"
    FRR_STATEMENT = """Providers SHOULD provide versioning and a release history for recommended secure default settings for _top-level administrative accounts_ and _privileged accounts_ as they are adjusted over time."""
    FAMILY = "RSC"
    FAMILY_NAME = "Resource Categorization"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CM-3", "Configuration Change Control"),
        ("CM-6", "Configuration Settings"),
        ("SA-5", "Information System Documentation")
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = []
    
    def __init__(self):
        """Initialize FRR-RSC-10 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Check for version management of security configuration.
        
        Looks for:
        - Version attributes/constants
        - Changelog/release notes generation
        - Semantic versioning usage
        """
        findings = []
        lines = code.split('\n')
        
        # Check for version tracking
        version_patterns = [
            r'__version__\s*=', r'VERSION\s*=', r'CONFIG_VERSION',
            r'generate.*changelog', r'release.*notes',
            r'semver', r'version.*history'
        ]
        
        for i, line in enumerate(lines, start=1):
            for pattern in version_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Version tracking detected",
                        description=f"Line {i} tracks version information. FRR-RSC-10 requires versioning and release history for secure default settings as they change over time.",
                        severity=Severity.LOW,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 3),
                        recommendation="Ensure versioning includes: (1) Semantic versioning, (2) Release history/changelog, (3) Security setting changes documented, (4) Rationale for changes"
                    ))
                    return findings
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Check C# for version tracking."""
        patterns = [r'\[assembly:\s*AssemblyVersion', r'Version\s*=', r'ChangeLog']
        return self._check_versioning(code, file_path, patterns)
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Check Java for version tracking."""
        patterns = [r'<version>', r'VERSION\s*=', r'pom\.xml']
        return self._check_versioning(code, file_path, patterns)
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Check TypeScript for version tracking (package.json)."""
        if 'package.json' in file_path.lower() and '"version"' in code:
            return [Finding(
                ksi_id=self.FRR_ID,
                requirement_id=self.FRR_ID,
                title="Version tracking in package.json",
                description="Version found in package.json. Ensure CHANGELOG.md documents security setting changes per FRR-RSC-10.",
                severity=Severity.LOW,
                file_path=file_path,
                line_number=1,
                code_snippet="",
                recommendation="Maintain CHANGELOG.md with security configuration version history"
            )]
        return []
    
    def _check_versioning(self, code: str, file_path: str, patterns: List[str]) -> List[Finding]:
        """Shared versioning detection."""
        findings = []
        for pattern in patterns:
            if re.search(pattern, code, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Version tracking found",
                    description="Versioning detected. Verify release history for secure default settings per FRR-RSC-10.",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    recommendation="Document security setting changes in release notes"
                ))
                break
        return findings
        lines = code.split('\n')
        
        # TODO: Implement AST analysis for TypeScript
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-RSC-10 compliance.
        
        TODO: Implement Bicep analysis
        - Detect relevant Azure resources
        - Check for compliance violations
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Bicep regex patterns
        # Example:
        # resource_pattern = r"resource\s+\w+\s+'Microsoft\.\w+/\w+@[\d-]+'\s*="
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-RSC-10 compliance.
        
        TODO: Implement Terraform analysis
        - Detect relevant resources
        - Check for compliance violations
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Terraform regex patterns
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-RSC-10 compliance.
        
        TODO: Implement GitHub Actions analysis
        - Check for required steps/actions
        - Verify compliance configuration
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitHub Actions analysis
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-RSC-10 compliance.
        
        TODO: Implement Azure Pipelines analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement Azure Pipelines analysis
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-RSC-10 compliance.
        
        TODO: Implement GitLab CI analysis
        """
        findings = []
        lines = code.split('\n')
        
        # TODO: Implement GitLab CI analysis
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> dict:
        """
        Get KQL queries and API endpoints for collecting FRR-RSC-10 evidence.
        
        Returns automated queries to collect evidence of versioning and release
        history for recommended secure default settings.
        """
        return {
            "automated_queries": [
                # Azure DevOps: Repository commits for baseline configuration
                """Resources
                | where type =~ 'microsoft.devops/repository'
                | where name contains 'baseline' or name contains 'defaults' or name contains 'security-config'
                | project name, type, resourceGroup, subscriptionId, lastCommitDate=properties.lastCommitDate""",
                
                # Azure Storage: Versioned configuration files
                """Resources
                | where type =~ 'microsoft.storage/storageaccounts'
                | extend hasVersioning = properties.blobContainerVersioning == 'Enabled'
                | where hasVersioning == true
                | project name, type, resourceGroup, subscriptionId, versioningEnabled=properties.blobContainerVersioning""",
                
                # GitHub API: Release history for secure defaults
                """# Manual: GET https://api.github.com/repos/{org}/{repo}/releases
                # Filter for repos containing secure configuration baselines
                # Extract: version tags, release dates, change descriptions"""
            ],
            "manual_queries": [
                "Review GitHub/Azure DevOps release history for baseline configurations",
                "Check CHANGELOG.md or RELEASE-NOTES.md for version history",
                "Verify semantic versioning (e.g., v1.0.0, v1.1.0) for baseline changes"
            ]
        }
    
    def get_evidence_artifacts(self) -> dict:
        """
        Get list of evidence artifacts for FRR-RSC-10 compliance.
        
        Returns documentation and files demonstrating versioning and release
        history for secure default settings.
        """
        return {
            "evidence_artifacts": [
                "VERSIONING-POLICY.md - Policy requiring versioning for secure defaults",
                "CHANGELOG.md - Release history for baseline configuration changes",
                "baselines/v1.0.0/ - Versioned baseline configuration files",
                "baselines/v1.1.0/ - Updated baseline with change description",
                "RELEASE-NOTES.md - Detailed release notes for each version",
                "VERSION-TAGS.txt - Git tags showing version history",
                "MIGRATION-GUIDE.md - Instructions for upgrading between versions"
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating FRR-RSC-10 evidence collection.
        
        Returns guidance for implementing versioning and release history
        for recommended secure default settings.
        """
        return {
            "implementation_notes": [
                "1. Implement semantic versioning",
                "   - Use semantic versioning (vMAJOR.MINOR.PATCH) for baseline configurations",
                "   - MAJOR: Breaking changes to security settings",
                "   - MINOR: New security settings added",
                "   - PATCH: Documentation/clarification updates",
                "   - Example: v1.0.0 → v1.1.0 (added MFA requirement)",
                "",
                "2. Maintain CHANGELOG.md",
                "   - Document all changes to secure default settings",
                "   - Include: version, date, description of changes, security impact",
                "   - Follow Keep a Changelog format",
                "   - Example entry: '## [1.1.0] - 2024-01-15 - Added MFA requirement for admin accounts'",
                "",
                "3. Version control baseline files",
                "   - Store baseline configurations in Git repository",
                "   - Create Git tags for each version (e.g., git tag v1.1.0)",
                "   - Store versioned files in separate directories (baselines/v1.0.0/, v1.1.0/)",
                "   - Enable Azure Blob Storage versioning for published baselines",
                "",
                "4. Publish release notes",
                "   - Create GitHub Releases for each baseline version",
                "   - Include release notes explaining changes and migration steps",
                "   - Link to updated guidance documentation",
                "   - Notify customers of new versions via email/blog",
                "",
                "5. Automate version tracking",
                "   - CI/CD pipeline to validate version bumps on baseline changes",
                "   - Automated CHANGELOG.md updates from commit messages",
                "   - Version number in baseline file headers",
                "   - Example: GitHub Actions workflow checking for version tag on merge"
            ]
        }
