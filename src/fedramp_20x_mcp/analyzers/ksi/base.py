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
    NIST_CONTROLS: List[tuple[str, str]]
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
            language: Language/framework (python, csharp, java, typescript, bicep, terraform, github_actions, azure_pipelines, gitlab_ci) - can be string or CodeLanguage enum
            file_path: Optional file path for context
            
        Returns:
            AnalysisResult with findings for this KSI
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
        # Extract control IDs from tuples (control_id, description)
        control_ids = [ctrl[0] if isinstance(ctrl, tuple) else ctrl for ctrl in self.NIST_CONTROLS]
        
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
            "controls": control_ids,  # Just the IDs for easy checking
            "nist_controls": self.NIST_CONTROLS,  # Full tuples for detailed info
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
    
    # ============================================================================
    # EVIDENCE AUTOMATION METHODS (Override in subclass to provide recommendations)
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for this KSI.
        
        Override in subclass to provide KSI-specific guidance. Returns a structured
        dictionary with evidence collection strategies, Azure services, code examples,
        and deployment guidance.
        
        Returns:
            Dictionary with evidence automation recommendations:
            {
                "ksi_id": str,
                "ksi_name": str,
                "evidence_type": str,  # "code-based", "log-based", "config-based", "metric-based", "process-based"
                "automation_feasibility": str,  # "high", "medium", "low", "manual-only"
                "azure_services": List[dict],  # Azure services for evidence collection
                "collection_methods": List[dict],  # Methods for collecting evidence
                "storage_requirements": dict,  # Evidence storage requirements
                "api_integration": dict,  # FRR-ADS API integration guidance
                "code_examples": dict,  # Code templates by language
                "infrastructure_templates": dict,  # IaC templates
                "retention_policy": str,  # Evidence retention requirements
                "implementation_effort": str  # "low", "medium", "high"
            }
        """
        return {
            "ksi_id": self.KSI_ID,
            "ksi_name": self.KSI_NAME,
            "evidence_type": "process-based",
            "automation_feasibility": "manual-only",
            "azure_services": [],
            "collection_methods": [],
            "storage_requirements": {},
            "api_integration": {},
            "code_examples": {},
            "infrastructure_templates": {},
            "retention_policy": "Per FedRAMP requirements (minimum 3 years for moderate impact)",
            "implementation_effort": "high",
            "notes": "Override this method in subclass to provide KSI-specific evidence automation recommendations."
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get Azure Resource Graph or KQL queries for collecting evidence.
        
        Override in subclass to provide KSI-specific queries for Azure Monitor,
        Log Analytics, Resource Graph, or other Azure data sources.
        
        Returns:
            List of query dictionaries:
            [
                {
                    "name": str,  # Query name/purpose
                    "query_type": str,  # "kusto", "resource_graph", "rest_api"
                    "query": str,  # Actual query text
                    "data_source": str,  # Azure service (e.g., "Log Analytics", "Resource Graph")
                    "schedule": str,  # Collection frequency (e.g., "hourly", "daily")
                    "output_format": str  # "json", "csv", "table"
                }
            ]
        """
        return []
    
    def get_evidence_artifacts(self) -> List[dict]:
        """
        Get list of evidence artifacts that should be collected for this KSI.
        
        Override in subclass to specify what evidence files, logs, configurations,
        or reports are needed to demonstrate compliance.
        
        Returns:
            List of artifact dictionaries:
            [
                {
                    "artifact_name": str,  # Name of evidence artifact
                    "artifact_type": str,  # "log", "config", "report", "screenshot", "policy"
                    "description": str,  # What this artifact demonstrates
                    "collection_method": str,  # How to collect it
                    "format": str,  # File format (json, csv, pdf, etc.)
                    "frequency": str,  # How often to collect (continuous, daily, monthly, on-demand)
                    "retention": str  # How long to keep (e.g., "3 years")
                }
            ]
        """
        return []
    
    # ============================================================================
    # HELPER METHODS (Available to all subclasses)
    # ============================================================================
    
    def _find_line(self, lines: List[str], search_term: str, use_regex: bool = False) -> Optional[dict]:
        """
        Find line containing search term or matching regex pattern.
        
        Args:
            lines: List of code lines
            search_term: String to search for (case-insensitive) or regex pattern if use_regex=True
            use_regex: If True, treat search_term as regex pattern (default: False)
            
        Returns:
            Dict with 'line_num' (1-based int) and 'line' (str content), or None if not found
        """
        if use_regex:
            import re
            try:
                pattern = re.compile(search_term, re.IGNORECASE)
                for i, line in enumerate(lines, 1):
                    if pattern.search(line):
                        return {'line_num': i, 'line': line}
            except re.error:
                # Invalid regex, fall back to substring search
                pass
        
        # Simple substring search (default behavior)
        search_lower = search_term.lower()
        for i, line in enumerate(lines, 1):
            if search_lower in line.lower():
                return {'line_num': i, 'line': line}
        return None
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """
        Get code snippet around a line number.
        
        Args:
            lines: List of code lines
            line_number: 1-based line number to center on
            context: Number of lines before/after to include (default: 2)
            
        Returns:
            Code snippet with context lines, or empty string if invalid line number
        """
        if line_number == 0 or not lines:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
    
    def _get_context(self, lines: List[str], line_num: int, context_lines: int = 5) -> str:
        """
        Get context around a line (alias for _get_snippet with larger context).
        
        Args:
            lines: List of code lines
            line_num: 1-based line number
            context_lines: Number of lines before/after to include (default: 5)
            
        Returns:
            Code snippet with context lines
        """
        return self._get_snippet(lines, line_num, context_lines)
    
    def _get_snippet_from_bytes(self, code: str, start_byte: int, end_byte: int, context: int = 2) -> str:
        """
        Extract code snippet from byte positions (for AST analysis).
        
        Args:
            code: Full source code as string
            start_byte: Start byte position
            end_byte: End byte position
            context: Number of lines before/after to include (default: 2)
            
        Returns:
            Code snippet with context lines
        """
        # Convert byte positions to line numbers
        lines = code.split('\n')
        line_num = code[:start_byte].count('\n') + 1
        return self._get_snippet(lines, line_num, context)
    
    def _find_text_line(self, lines: List[str], text: str) -> int:
        """Find line number containing text (case-insensitive)."""
        text_lower = text.lower()
        for i, line in enumerate(lines, 1):
            if text_lower in line.lower():
                return i
        return 0

