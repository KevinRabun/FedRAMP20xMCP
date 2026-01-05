"""
KSI Reference Validation Tests

Validates that all KSI references in code, tests, and documentation match
the authoritative FedRAMP 20x definitions from the cached data.

This test prevents future misidentifications like:
- KSI-PIY-01 being called "Encryption at Rest" instead of "Automated Inventory"
- KSI-SVC-01 being called "Secrets Management" instead of "Continuous Improvement"
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple
import pytest


# Authoritative KSI definitions from FedRAMP 20x
# Source: https://github.com/FedRAMP/docs
AUTHORITATIVE_KSI_DEFINITIONS = {
    # PIY - Policy and Inventory (NOT Privacy!)
    "KSI-PIY-01": "Automated Inventory",
    "KSI-PIY-02": None,  # RETIRED - superseded by KSI-AFR-01
    "KSI-PIY-03": "Documentation Requirements",
    "KSI-PIY-04": "Risk Assessment",
    "KSI-PIY-05": "Authorization",
    "KSI-PIY-06": "Continuous Authorization",
    "KSI-PIY-07": "Specialized Assessments",
    "KSI-PIY-08": "Interconnections",
    
    # SVC - Service Configuration
    "KSI-SVC-01": "Continuous Improvement",
    "KSI-SVC-02": "Network Encryption",
    "KSI-SVC-03": None,  # RETIRED - superseded by KSI-AFR-11
    "KSI-SVC-04": "Configuration Automation",
    "KSI-SVC-05": "Resource Integrity",
    "KSI-SVC-06": "Secret Management",
    "KSI-SVC-07": "Patching",
    "KSI-SVC-08": "Malicious Code Protection",
    "KSI-SVC-09": "Flaw Remediation",
    "KSI-SVC-10": "Developer Security and Privacy",
    
    # IAM - Identity and Access Management
    "KSI-IAM-01": "Phishing-Resistant MFA",
    "KSI-IAM-02": "Privileged Access",
    "KSI-IAM-03": "Separation of Duties",
    "KSI-IAM-04": "Least Privilege",
    "KSI-IAM-05": "Service Accounts",
    "KSI-IAM-06": "Suspicious Activity",
    "KSI-IAM-07": "Session Management",
    
    # CNA - Cloud Network Architecture
    "KSI-CNA-01": "Restrict Network Traffic",
    "KSI-CNA-02": "Boundary Protection",
    "KSI-CNA-03": "Traffic Inspection",
    "KSI-CNA-04": "Name Resolution",
    "KSI-CNA-05": "DDoS Protection",
    
    # MLA - Monitoring, Logging, and Auditing
    "KSI-MLA-01": "Security Information and Event Management (SIEM)",
    "KSI-MLA-02": "Audit Record Retention",
    "KSI-MLA-03": None,  # RETIRED
    "KSI-MLA-04": None,  # RETIRED
    "KSI-MLA-05": "Audit Record Review",
    "KSI-MLA-06": None,  # RETIRED
    "KSI-MLA-07": "Continuous Monitoring",
    
    # CMT - Change Management and Transparency
    "KSI-CMT-01": "Change Control Board",
    "KSI-CMT-02": "Configuration Change Control",
    "KSI-CMT-03": "Impact Analysis",
    "KSI-CMT-04": "Transparency",
    "KSI-CMT-05": None,  # RETIRED - superseded by KSI-AFR-05
    
    # TPR - Third Party Risk
    "KSI-TPR-01": None,  # RETIRED - superseded by KSI-AFR-01
    "KSI-TPR-02": None,  # RETIRED - superseded by KSI-AFR-01
    "KSI-TPR-03": "Third Party Contracts",
    
    # Additional themes
    "KSI-VDR-01": "Vulnerability Scanning",
    "KSI-SCN-01": "Baseline Configuration",
    "KSI-RSC-01": "Contingency Planning",
    "KSI-ADS-01": "Audit Storage",
}

# Known wrong descriptions that should never appear
FORBIDDEN_DESCRIPTIONS = {
    "KSI-PIY-01": [
        "encryption at rest",
        "data encryption",
        "privacy",
        "pii",
        "data classification",
    ],
    "KSI-PIY-02": [
        "encryption in transit",
        "tls",
        "https",
        "pii handling",
    ],
    "KSI-SVC-01": [
        "secrets management",
        "secret management", 
        "key vault",
        "error handling",
        "logging",
    ],
    "KSI-SVC-02": [
        "secrets",
        "key vault",
        "input validation",
        "sql injection",
    ],
    "KSI-SVC-06": [
        "network security",
        "nsg",
        "firewall",
        "private endpoint",
    ],
}

# PIY acronym validation
PIY_CORRECT = "Policy and Inventory"
PIY_WRONG = ["Privacy", "PII", "Personal Information"]


def get_project_root() -> Path:
    """Get project root directory."""
    return Path(__file__).parent.parent


def load_authoritative_ksi_data() -> Dict:
    """Load KSI definitions from cached authoritative data."""
    cache_file = get_project_root() / "src" / "fedramp_20x_mcp" / "__fedramp_cache__" / "fedramp_controls.json"
    if cache_file.exists():
        with open(cache_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}


def find_ksi_references_in_file(file_path: Path) -> List[Tuple[int, str, str]]:
    """
    Find all KSI references in a file.
    
    Returns list of (line_number, ksi_id, context) tuples.
    """
    references = []
    
    # Pattern to match KSI-XXX-NN with surrounding context
    ksi_pattern = re.compile(r'(KSI-[A-Z]{2,3}-\d{2})[:\s]*([^"\n\r]{0,100})', re.IGNORECASE)
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for match in ksi_pattern.finditer(line):
                    ksi_id = match.group(1).upper()
                    context = match.group(2).strip() if match.group(2) else ""
                    references.append((line_num, ksi_id, context))
    except Exception:
        pass
    
    return references


def find_piy_acronym_usage(file_path: Path) -> List[Tuple[int, str]]:
    """
    Find PIY acronym definitions/expansions in a file.
    
    Returns list of (line_number, context) tuples where PIY is defined.
    """
    usages = []
    
    # Pattern to match PIY with parenthetical expansion
    piy_pattern = re.compile(r'PIY\s*\(([^)]+)\)', re.IGNORECASE)
    
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                for match in piy_pattern.finditer(line):
                    expansion = match.group(1).strip()
                    usages.append((line_num, expansion))
    except Exception:
        pass
    
    return usages


class TestKSIReferenceValidation:
    """Validate KSI references across the codebase."""
    
    @pytest.fixture
    def project_root(self) -> Path:
        return get_project_root()
    
    @pytest.fixture
    def authoritative_data(self) -> Dict:
        return load_authoritative_ksi_data()
    
    def test_authoritative_cache_exists(self, project_root):
        """Verify authoritative KSI cache exists."""
        cache_file = project_root / "src" / "fedramp_20x_mcp" / "__fedramp_cache__" / "fedramp_controls.json"
        assert cache_file.exists(), "Authoritative FedRAMP cache file not found"
    
    def test_authoritative_data_has_ksi_definitions(self, authoritative_data):
        """Verify authoritative data contains KSI definitions."""
        assert authoritative_data, "Failed to load authoritative data"
        
        # Check for key KSIs
        requirements = authoritative_data.get("requirements", {})
        assert "KSI-PIY-01" in requirements, "KSI-PIY-01 not in authoritative data"
        assert "KSI-SVC-01" in requirements, "KSI-SVC-01 not in authoritative data"
        
        # Verify correct names
        piy_01 = requirements.get("KSI-PIY-01", {})
        assert piy_01.get("name") == "Automated Inventory", \
            f"KSI-PIY-01 should be 'Automated Inventory', got '{piy_01.get('name')}'"
        
        svc_01 = requirements.get("KSI-SVC-01", {})
        assert svc_01.get("name") == "Continuous Improvement", \
            f"KSI-SVC-01 should be 'Continuous Improvement', got '{svc_01.get('name')}'"
        
        svc_06 = requirements.get("KSI-SVC-06", {})
        assert svc_06.get("name") == "Secret Management", \
            f"KSI-SVC-06 should be 'Secret Management', got '{svc_06.get('name')}'"
    
    def test_no_forbidden_ksi_descriptions_in_tests(self, project_root):
        """Verify test files don't contain forbidden KSI descriptions."""
        tests_dir = project_root / "tests"
        violations = []
        
        for test_file in tests_dir.glob("*.py"):
            references = find_ksi_references_in_file(test_file)
            
            for line_num, ksi_id, context in references:
                if ksi_id in FORBIDDEN_DESCRIPTIONS:
                    context_lower = context.lower()
                    for forbidden in FORBIDDEN_DESCRIPTIONS[ksi_id]:
                        if forbidden in context_lower:
                            violations.append(
                                f"{test_file.name}:{line_num} - {ksi_id} has forbidden description '{forbidden}' in: {context}"
                            )
        
        assert not violations, \
            f"Found {len(violations)} forbidden KSI descriptions:\n" + "\n".join(violations)
    
    def test_no_forbidden_ksi_descriptions_in_tools(self, project_root):
        """Verify tool files don't contain forbidden KSI descriptions."""
        tools_dir = project_root / "src" / "fedramp_20x_mcp" / "tools"
        violations = []
        
        for tool_file in tools_dir.glob("*.py"):
            references = find_ksi_references_in_file(tool_file)
            
            for line_num, ksi_id, context in references:
                if ksi_id in FORBIDDEN_DESCRIPTIONS:
                    context_lower = context.lower()
                    for forbidden in FORBIDDEN_DESCRIPTIONS[ksi_id]:
                        if forbidden in context_lower:
                            violations.append(
                                f"{tool_file.name}:{line_num} - {ksi_id} has forbidden description '{forbidden}'"
                            )
        
        assert not violations, \
            f"Found {len(violations)} forbidden KSI descriptions in tools:\n" + "\n".join(violations)
    
    def test_piy_acronym_not_privacy_in_docs(self, project_root):
        """Verify PIY is never expanded as 'Privacy' in documentation."""
        violations = []
        
        # Files to exclude (they document issues, not make claims)
        exclude_files = {"REVIEW_FINDINGS.md", "REVIEW_CHECKLIST.md"}
        
        # Check markdown files
        for md_file in project_root.glob("*.md"):
            if md_file.name in exclude_files:
                continue
            usages = find_piy_acronym_usage(md_file)
            for line_num, expansion in usages:
                for wrong in PIY_WRONG:
                    if wrong.lower() in expansion.lower():
                        violations.append(
                            f"{md_file.name}:{line_num} - PIY incorrectly defined as '{expansion}'"
                        )
        
        # Check docs folder
        docs_dir = project_root / "docs"
        if docs_dir.exists():
            for md_file in docs_dir.glob("*.md"):
                usages = find_piy_acronym_usage(md_file)
                for line_num, expansion in usages:
                    for wrong in PIY_WRONG:
                        if wrong.lower() in expansion.lower():
                            violations.append(
                                f"docs/{md_file.name}:{line_num} - PIY incorrectly defined as '{expansion}'"
                            )
        
        assert not violations, \
            f"PIY should be 'Policy and Inventory', not 'Privacy':\n" + "\n".join(violations)
    
    def test_piy_acronym_not_privacy_in_tests(self, project_root):
        """Verify PIY is never expanded as 'Privacy' in test files."""
        tests_dir = project_root / "tests"
        violations = []
        
        for test_file in tests_dir.glob("*.py"):
            usages = find_piy_acronym_usage(test_file)
            for line_num, expansion in usages:
                for wrong in PIY_WRONG:
                    if wrong.lower() in expansion.lower():
                        violations.append(
                            f"{test_file.name}:{line_num} - PIY incorrectly defined as '{expansion}'"
                        )
        
        assert not violations, \
            f"PIY should be 'Policy and Inventory', not 'Privacy':\n" + "\n".join(violations)
    
    def test_retired_ksis_not_actively_used(self, authoritative_data):
        """Verify retired KSIs are properly marked in authoritative data."""
        requirements = authoritative_data.get("requirements", {})
        
        retired_ksis = [
            "KSI-CMT-05",
            "KSI-MLA-03", "KSI-MLA-04", "KSI-MLA-06",
            "KSI-PIY-02",
            "KSI-SVC-03",
            "KSI-TPR-01", "KSI-TPR-02",
        ]
        
        for ksi_id in retired_ksis:
            ksi_data = requirements.get(ksi_id, {})
            assert ksi_data.get("retired") is True, \
                f"{ksi_id} should be marked as retired in authoritative data"


class TestKSIDefinitionAccuracy:
    """Test that specific KSI definitions match authoritative source."""
    
    @pytest.fixture
    def authoritative_data(self) -> Dict:
        return load_authoritative_ksi_data()
    
    @pytest.mark.parametrize("ksi_id,expected_name", [
        ("KSI-PIY-01", "Automated Inventory"),
        # KSI-PIY-02 is retired (superseded by KSI-AFR-01)
        ("KSI-SVC-01", "Continuous Improvement"),
        ("KSI-SVC-02", "Network Encryption"),
        ("KSI-SVC-06", "Secret Management"),
        ("KSI-IAM-01", "Phishing-Resistant MFA"),
        ("KSI-CNA-01", "Restrict Network Traffic"),
        ("KSI-MLA-01", "Security Information and Event Management (SIEM)"),
    ])
    def test_ksi_definition_matches_authoritative(self, authoritative_data, ksi_id, expected_name):
        """Verify KSI definition matches authoritative FedRAMP 20x source."""
        requirements = authoritative_data.get("requirements", {})
        ksi_data = requirements.get(ksi_id, {})
        
        actual_name = ksi_data.get("name")
        assert actual_name == expected_name, \
            f"{ksi_id}: expected '{expected_name}', got '{actual_name}'"
