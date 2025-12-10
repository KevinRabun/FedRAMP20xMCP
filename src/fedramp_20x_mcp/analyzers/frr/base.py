"""
Base class for FRR-centric analyzers.

Each FRR analyzer is self-contained with:
- Official FedRAMP 20x metadata embedded
- All language implementations (Python, C#, Java, TypeScript, Bicep, Terraform)
- CI/CD pipeline analysis (GitHub Actions, Azure Pipelines, GitLab CI)
- Evidence automation recommendations
"""

from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from ..base import Finding, AnalysisResult, Severity


class BaseFRRAnalyzer(ABC):
    """
    Abstract base class for FRR-specific analyzers.
    
    Each FRR analyzer must implement detection methods for applicable languages:
    - Application: analyze_python, analyze_csharp, analyze_java, analyze_typescript
    - IaC: analyze_bicep, analyze_terraform
    - CI/CD: analyze_github_actions, analyze_azure_pipelines, analyze_gitlab_ci
    
    Analyzers can return empty lists for non-applicable language/FRR combinations.
    """
    
    # Must be set by subclass
    FRR_ID: str  # e.g., "FRR-VDR-01"
    FRR_NAME: str  # e.g., "Critical Vulnerability Remediation"
    FRR_STATEMENT: str  # Official requirement statement
    FAMILY: str  # e.g., "VDR"
    FAMILY_NAME: str  # e.g., "Vulnerability Detection and Response"
    IMPACT_LOW: bool
    IMPACT_MODERATE: bool
    NIST_CONTROLS: List[tuple[str, str]]  # [(control_id, control_name), ...]
    CODE_DETECTABLE: bool = True  # Set to False for process/documentation-based requirements
    IMPLEMENTATION_STATUS: str = "NOT_IMPLEMENTED"  # "IMPLEMENTED", "NOT_IMPLEMENTED", or "PARTIAL"
    RELATED_KSIS: List[str] = []  # Related KSI IDs (e.g., ["KSI-AFR-04", "KSI-SVC-07"])
    
    def __init__(self, frr_id: str, frr_name: str, frr_statement: str):
        """
        Initialize FRR analyzer.
        
        Args:
            frr_id: FRR identifier (e.g., "FRR-VDR-01")
            frr_name: Human-readable name (e.g., "Critical Vulnerability Remediation")
            frr_statement: Official FedRAMP 20x statement
        """
        self.frr_id = frr_id
        self.frr_name = frr_name
        self.frr_statement = frr_statement
    
    def analyze(self, code: str, language: str, file_path: str = "") -> AnalysisResult:
        """
        Analyze code for this FRR across the specified language.
        
        Args:
            code: Source code or configuration content
            language: Language/framework (python, csharp, java, typescript, bicep, terraform, github_actions, azure_pipelines, gitlab_ci)
            file_path: Optional file path for context
            
        Returns:
            AnalysisResult with findings for this FRR
        """
        # Handle both string and CodeLanguage enum
        from fedramp_20x_mcp.analyzers.ast_utils import CodeLanguage
        if isinstance(language, CodeLanguage):
            language_lower = language.value.lower()
        else:
            language_lower = language.lower()
        
        # Route to appropriate language analyzer
        if language_lower in ("python", "py", "python3"):
            findings = self.analyze_python(code, file_path)
        elif language_lower in ("csharp", "c#", "cs"):
            findings = self.analyze_csharp(code, file_path)
        elif language_lower == "java":
            findings = self.analyze_java(code, file_path)
        elif language_lower in ("typescript", "javascript", "ts", "js"):
            findings = self.analyze_typescript(code, file_path)
        elif language_lower == "bicep":
            findings = self.analyze_bicep(code, file_path)
        elif language_lower in ("terraform", "tf"):
            findings = self.analyze_terraform(code, file_path)
        elif language_lower in ("github_actions", "github-actions"):
            findings = self.analyze_github_actions(code, file_path)
        elif language_lower in ("azure_pipelines", "azure-pipelines"):
            findings = self.analyze_azure_pipelines(code, file_path)
        elif language_lower in ("gitlab_ci", "gitlab-ci"):
            findings = self.analyze_gitlab_ci(code, file_path)
        else:
            findings = []
        
        # Add FRR ID to all findings
        for finding in findings:
            if not finding.requirement_id:
                finding.requirement_id = self.frr_id
        
        return AnalysisResult(
            ksi_id=self.frr_id,  # Reuse ksi_id field for FRR ID
            ksi_name=self.frr_name,
            findings=findings,
            total_issues=len(findings),
            critical_count=sum(1 for f in findings if f.severity == Severity.CRITICAL),
            high_count=sum(1 for f in findings if f.severity == Severity.HIGH),
            medium_count=sum(1 for f in findings if f.severity == Severity.MEDIUM),
            low_count=sum(1 for f in findings if f.severity == Severity.LOW)
        )
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS (Override in subclass)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Python code. Override in subclass if applicable."""
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze C# code. Override in subclass if applicable."""
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java code. Override in subclass if applicable."""
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze TypeScript/JavaScript code. Override in subclass if applicable."""
        return []
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Override in subclass)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Bicep IaC. Override in subclass if applicable."""
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Terraform IaC. Override in subclass if applicable."""
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Override in subclass)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitHub Actions workflow. Override in subclass if applicable."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Azure Pipelines YAML. Override in subclass if applicable."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitLab CI YAML. Override in subclass if applicable."""
        return []
    
    # ============================================================================
    # EVIDENCE AUTOMATION (Override in subclass)
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for this FRR.
        
        Returns:
            Dict containing:
            - frr_id: The FRR identifier
            - frr_name: Human-readable name
            - evidence_type: "log-based", "config-based", "process-based", or "artifact-based"
            - automation_feasibility: "high", "medium", or "low"
            - azure_services: List of recommended Azure services
            - collection_methods: List of evidence collection methods
            - implementation_steps: Step-by-step guide
            - evidence_artifacts: List of artifacts to collect
            - update_frequency: How often to collect evidence
            - responsible_party: Who should own this
        """
        return {
            "frr_id": self.frr_id,
            "frr_name": self.frr_name,
            "evidence_type": "config-based",
            "automation_feasibility": "high",
            "azure_services": [],
            "collection_methods": [],
            "implementation_steps": [],
            "evidence_artifacts": [],
            "update_frequency": "monthly",
            "responsible_party": "Cloud Security Team"
        }
    
    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries with:
            - query_type: "Azure Monitor KQL", "Azure Resource Graph KQL", "PowerShell", etc.
            - query_name: Descriptive name
            - query: The actual query
            - purpose: What this query collects
        """
        return []
    
    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        """
        Get descriptions of evidence artifacts to collect.
        
        Returns:
            List of artifact dictionaries with:
            - artifact_name: Name of the artifact
            - artifact_type: Type (e.g., "JSON", "CSV", "PDF")
            - description: What it contains
            - collection_method: How to collect it
            - storage_location: Where to store it
        """
        return []
    
    # ============================================================================
    # UTILITY METHODS
    # ============================================================================
    
    def _get_snippet(self, lines: List[str], line_num: int, context: int = 2) -> str:
        """
        Get code snippet with context lines.
        
        Args:
            lines: All lines of code
            line_num: Line number (1-indexed)
            context: Number of lines before/after to include
            
        Returns:
            Code snippet with line numbers
        """
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        
        snippet_lines = []
        for i in range(start, end):
            marker = ">>> " if i == line_num - 1 else "    "
            snippet_lines.append(f"{marker}{i+1}: {lines[i]}")
        
        return "\n".join(snippet_lines)
