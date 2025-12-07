"""
Base class for KSI-centric analyzers.

Each KSI analyzer is self-contained with:
- Official FedRAMP 20x metadata embedded
- All language implementations (Python, C#, Java, TypeScript, Bicep, Terraform)
- CI/CD pipeline analysis (GitHub Actions, Azure Pipelines, GitLab CI)
"""

from abc import ABC, abstractmethod
from typing import List, Optional
from ..base import Finding, AnalysisResult, Severity


class BaseKSIAnalyzer(ABC):
    """
    Abstract base class for KSI-specific analyzers.
    
    Each KSI analyzer must implement detection methods for applicable languages:
    - Application: analyze_python, analyze_csharp, analyze_java, analyze_typescript
    - IaC: analyze_bicep, analyze_terraform
    - CI/CD: analyze_github_actions, analyze_azure_pipelines, analyze_gitlab_ci
    
    Analyzers can return empty lists for non-applicable language/KSI combinations.
    """
    
    # Must be set by subclass
    KSI_ID: str
    KSI_NAME: str
    KSI_STATEMENT: str
    FAMILY: str
    FAMILY_NAME: str
    IMPACT_LOW: bool
    IMPACT_MODERATE: bool
    NIST_CONTROLS: List[str]
    RETIRED: bool = False
    CODE_DETECTABLE: bool = True  # Set to False for process/documentation-based KSIs
    IMPLEMENTATION_STATUS: str = "NOT_IMPLEMENTED"  # "IMPLEMENTED", "NOT_IMPLEMENTED", or "PARTIAL"
    
    def __init__(self, ksi_id: str, ksi_name: str, ksi_statement: str):
        """
        Initialize KSI analyzer.
        
        Args:
            ksi_id: KSI identifier (e.g., "KSI-IAM-06")
            ksi_name: Human-readable name (e.g., "Suspicious Activity")
            ksi_statement: Official FedRAMP 20x statement
        """
        self.ksi_id = ksi_id
        self.ksi_name = ksi_name
        self.ksi_statement = ksi_statement
    
    def analyze(self, code: str, language: str, file_path: str = "") -> AnalysisResult:
        """
        Analyze code for this KSI across the specified language.
        
        Args:
            code: Source code or configuration content
            language: Language/framework (python, csharp, java, typescript, bicep, terraform, github_actions, azure_pipelines, gitlab_ci)
            file_path: Optional file path for context
            
        Returns:
            AnalysisResult with findings for this KSI
        """
        language_lower = language.lower()
        
        # Route to appropriate language analyzer
        if language_lower == "python":
            findings = self.analyze_python(code, file_path)
        elif language_lower in ("csharp", "c#", "cs"):
            findings = self.analyze_csharp(code, file_path)
        elif language_lower == "java":
            findings = self.analyze_java(code, file_path)
        elif language_lower in ("typescript", "javascript", "ts", "js"):
            findings = self.analyze_typescript(code, file_path)
        elif language_lower == "bicep":
            findings = self.analyze_bicep(code, file_path)
        elif language_lower == "terraform":
            findings = self.analyze_terraform(code, file_path)
        elif language_lower in ("github_actions", "github-actions"):
            findings = self.analyze_github_actions(code, file_path)
        elif language_lower in ("azure_pipelines", "azure-pipelines"):
            findings = self.analyze_azure_pipelines(code, file_path)
        elif language_lower in ("gitlab_ci", "gitlab-ci"):
            findings = self.analyze_gitlab_ci(code, file_path)
        else:
            findings = []
        
        return AnalysisResult(
            ksi_id=self.ksi_id,
            ksi_name=self.ksi_name,
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
    
    def get_metadata(self) -> dict:
        """
        Get KSI metadata.
        
        Returns:
            Dictionary with KSI metadata including statement, controls, impact levels, 
            implementation status, and code detectability
        """
        return {
            "ksi_id": self.KSI_ID,
            "ksi_name": self.KSI_NAME,
            "statement": self.KSI_STATEMENT,
            "family": self.FAMILY,
            "family_name": self.FAMILY_NAME,
            "impact": {
                "low": self.IMPACT_LOW,
                "moderate": self.IMPACT_MODERATE
            },
            "controls": self.NIST_CONTROLS,  # Changed from nist_controls to controls for test compatibility
            "nist_controls": self.NIST_CONTROLS,  # Keep both for backward compatibility
            "retired": self.RETIRED,
            "code_detectable": self.CODE_DETECTABLE,
            "implementation_status": self.IMPLEMENTATION_STATUS
        }
    
    def is_implemented(self) -> bool:
        """Check if this KSI has analyzer implementations."""
        return self.IMPLEMENTATION_STATUS == "IMPLEMENTED" and not self.RETIRED
    
    def is_code_detectable(self) -> bool:
        """Check if this KSI can be detected via code analysis."""
        return self.CODE_DETECTABLE and not self.RETIRED

