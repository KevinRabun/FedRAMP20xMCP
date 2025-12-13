"""
Base classes for code analyzers.

Provides common data structures and interfaces for all analyzers.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
    """Severity level for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """
    Represents a single compliance finding in code.
    
    Attributes:
        requirement_id: FedRAMP requirement ID (e.g., "KSI-MLA-05") - can be None if ksi_id is provided
        severity: Severity level of the finding
        title: Short description of the issue
        description: Detailed explanation of the issue
        file_path: Path to the file containing the issue
        line_number: Line number where the issue was found (optional)
        code_snippet: Relevant code snippet (optional)
        recommendation: Specific recommendation to fix the issue (alias: remediation)
        good_practice: Whether this is a positive finding (default: False)
        ksi_id: Optional KSI identifier (for KSI-centric architecture) - if provided and requirement_id is None, requirement_id will be set to ksi_id
        pattern_id: Optional pattern identifier (e.g., "iam.mfa.fido2_import")
    """
    severity: Severity
    title: str
    description: str
    file_path: str
    recommendation: str = ""  # Make it optional with default
    requirement_id: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    good_practice: bool = False
    ksi_id: Optional[str] = None
    pattern_id: Optional[str] = None
    
    def __post_init__(self):
        """Set requirement_id to ksi_id if not provided, handle remediation alias."""
        if self.requirement_id is None and self.ksi_id is not None:
            self.requirement_id = self.ksi_id
        elif self.ksi_id is None and self.requirement_id is not None:
            self.ksi_id = self.requirement_id
    
    def __init__(self, **kwargs):
        """Allow both recommendation and remediation as aliases."""
        # Handle remediation as alias for recommendation
        if 'remediation' in kwargs and 'recommendation' not in kwargs:
            kwargs['recommendation'] = kwargs.pop('remediation')
        elif 'remediation' in kwargs:
            kwargs.pop('remediation')  # Remove duplicate if both provided
        
        # Set all fields
        self.severity = kwargs.get('severity')
        self.title = kwargs.get('title')
        self.description = kwargs.get('description')
        self.file_path = kwargs.get('file_path')
        self.recommendation = kwargs.get('recommendation', "")
        self.requirement_id = kwargs.get('requirement_id')
        self.line_number = kwargs.get('line_number')
        self.code_snippet = kwargs.get('code_snippet')
        self.good_practice = kwargs.get('good_practice', False)
        self.ksi_id = kwargs.get('ksi_id')
        self.pattern_id = kwargs.get('pattern_id')
        
        # Run post-init logic
        if self.requirement_id is None and self.ksi_id is not None:
            self.requirement_id = self.ksi_id
        elif self.ksi_id is None and self.requirement_id is not None:
            self.ksi_id = self.requirement_id
    
    def to_dict(self) -> dict:
        """Convert finding to dictionary for JSON serialization."""
        result = {
            "requirement_id": self.requirement_id,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "code_snippet": self.code_snippet,
            "recommendation": self.recommendation,
            "good_practice": self.good_practice,
        }
        if self.ksi_id:
            result["ksi_id"] = self.ksi_id
        if self.pattern_id:
            result["pattern_id"] = self.pattern_id
        return result


@dataclass
class AnalysisResult:
    """
    Results from analyzing code files.
    
    Attributes:
        findings: List of findings discovered
        files_analyzed: Number of files analyzed
        good_practices_count: Number of good practices detected
        high_priority_count: Number of high-severity issues
        medium_priority_count: Number of medium-severity issues
        low_priority_count: Number of low-severity issues
        ksi_id: Optional KSI identifier (for KSI-centric architecture)
        ksi_name: Optional KSI name (for KSI-centric architecture)
        total_issues: Total number of issues found
        critical_count: Number of critical-severity issues
        high_count: Number of high-severity issues
        medium_count: Number of medium-severity issues
        low_count: Number of low-severity issues
    """
    findings: list[Finding] = field(default_factory=list)
    files_analyzed: int = 0
    ksi_id: Optional[str] = None
    ksi_name: Optional[str] = None
    total_issues: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    @property
    def good_practices_count(self) -> int:
        """Count of good practices detected."""
        return sum(1 for f in self.findings if f.good_practice)
    
    @property
    def high_priority_count(self) -> int:
        """Count of high-severity issues."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH and not f.good_practice)
    
    @property
    def medium_priority_count(self) -> int:
        """Count of medium-severity issues."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM and not f.good_practice)
    
    @property
    def low_priority_count(self) -> int:
        """Count of low-severity issues."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW and not f.good_practice)
    
    def to_dict(self) -> dict:
        """Convert analysis result to dictionary for JSON serialization."""
        return {
            "findings": [f.to_dict() for f in self.findings],
            "files_analyzed": self.files_analyzed,
            "summary": {
                "high_priority": self.high_priority_count,
                "medium_priority": self.medium_priority_count,
                "low_priority": self.low_priority_count,
                "good_practices": self.good_practices_count,
            }
        }


class BaseAnalyzer:
    """Base class for all code analyzers."""
    
    def __init__(self):
        """Initialize the analyzer."""
        self.result = AnalysisResult()
    
    def analyze(self, code: str, file_path: str) -> AnalysisResult:
        """
        Analyze code and return findings.
        
        Args:
            code: The code content to analyze
            file_path: Path to the file being analyzed
            
        Returns:
            AnalysisResult containing all findings
        """
        raise NotImplementedError("Subclasses must implement analyze()")
    
    def add_finding(self, finding: Finding) -> None:
        """Add a finding to the result."""
        self.result.findings.append(finding)
    
    def get_line_number(self, code: str, search_text: str) -> Optional[int]:
        """
        Find the line number of text in code.
        
        Args:
            code: The code content
            search_text: Text to search for
            
        Returns:
            Line number (1-indexed) or None if not found
        """
        lines = code.split('\n')
        for i, line in enumerate(lines, start=1):
            if search_text in line:
                return i
        return None
