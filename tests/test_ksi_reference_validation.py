"""
KSI Reference Validation Tests

Validates that all KSI references in code, tests, and documentation match
the authoritative FedRAMP 20x definitions from the cached data.

This test prevents future misidentifications like:
- KSI-PIY-GIV being called "Encryption at Rest" instead of "Generating Inventories"
- KSI-SVC-EIS being called "Secrets Management" instead of "Evaluating and Improving Security"

Note: FedRAMP 20x v0.9.0-beta changed KSI IDs from numbered format (KSI-PIY-01) to
descriptive format (KSI-PIY-GIV). The "fka" (formerly known as) field maps old IDs
to new ones.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Tuple
import pytest


# Authoritative KSI definitions from FedRAMP 20x v0.9.0-beta
# Source: https://github.com/FedRAMP/docs
# Note: IDs changed from numbered (KSI-PIY-01) to descriptive (KSI-PIY-GIV)
AUTHORITATIVE_KSI_DEFINITIONS = {
    # PIY - Policy and Inventory (NOT Privacy!)
    "KSI-PIY-GIV": "Generating Inventories",  # fka: KSI-PIY-01
    "KSI-PIY-RES": "Reviewing Executive Support",  # fka: KSI-PIY-08
    "KSI-PIY-RIS": "Reviewing Investments in Security",  # fka: KSI-PIY-06
    "KSI-PIY-RSD": "Reviewing Security in the SDLC",  # fka: KSI-PIY-04
    "KSI-PIY-RVD": "Reviewing Vulnerability Disclosures",  # fka: KSI-PIY-03
    
    # SVC - Service Configuration
    "KSI-SVC-EIS": "Evaluating and Improving Security",  # fka: KSI-SVC-01
    "KSI-SVC-SNT": "Securing Network Traffic",  # fka: KSI-SVC-02
    "KSI-SVC-ACM": "Automating Configuration Management",  # fka: KSI-SVC-04
    "KSI-SVC-VRI": "Validating Resource Integrity",  # fka: KSI-SVC-05
    "KSI-SVC-ASM": "Automating Secret Management",  # fka: KSI-SVC-06
    "KSI-SVC-PRR": "Preventing Residual Risk",  # fka: KSI-SVC-08
    "KSI-SVC-VCM": "Validating Communications",  # fka: KSI-SVC-09
    "KSI-SVC-RUD": "Removing Unwanted Data",  # fka: KSI-SVC-10
    
    # IAM - Identity and Access Management
    "KSI-IAM-MFA": "Enforcing Phishing-Resistant MFA",  # fka: KSI-IAM-01
    "KSI-IAM-APM": "Adopting Passwordless Methods",  # fka: KSI-IAM-02
    "KSI-IAM-SNU": "Securing Non-User Authentication",  # fka: KSI-IAM-03
    "KSI-IAM-JIT": "Authorizing Just-in-Time",  # fka: KSI-IAM-04
    "KSI-IAM-ELP": "Ensuring Least Privilege",  # fka: KSI-IAM-05
    "KSI-IAM-SUS": "Responding to Suspicious Activity",  # fka: KSI-IAM-06
    "KSI-IAM-AAM": "Automating Account Management",  # fka: KSI-IAM-07
    
    # CNA - Cloud Network Architecture
    "KSI-CNA-RNT": "Restricting Network Traffic",  # fka: KSI-CNA-01
    "KSI-CNA-MAT": "Minimizing Attack Surface",  # fka: KSI-CNA-02
    "KSI-CNA-ULN": "Using Logical Networking",  # fka: KSI-CNA-03
    "KSI-CNA-DFP": "Defining Functionality and Privileges",  # fka: KSI-CNA-04
    "KSI-CNA-RVP": "Reviewing Protections",  # fka: KSI-CNA-05
    "KSI-CNA-OFA": "Optimizing for Availability",  # fka: KSI-CNA-06
    "KSI-CNA-IBP": "Implementing Best Practices",  # fka: KSI-CNA-07
    "KSI-CNA-EIS": "Enforcing Intended State",  # fka: KSI-CNA-08
    
    # MLA - Monitoring, Logging, and Auditing
    "KSI-MLA-OSM": "Operating SIEM Capability",  # fka: KSI-MLA-01
    "KSI-MLA-RVL": "Reviewing Logs",  # fka: KSI-MLA-02
    "KSI-MLA-EVC": "Evaluating Configurations",  # fka: KSI-MLA-05
    "KSI-MLA-LET": "Logging Event Types",  # fka: KSI-MLA-07
    "KSI-MLA-ALA": "Authorizing Log Access",  # fka: KSI-MLA-08
    
    # CMT - Change Management (and Transparency theme removed)
    "KSI-CMT-LMC": "Logging Changes",  # fka: KSI-CMT-01
    "KSI-CMT-RMV": "Redeploying vs Modifying",  # fka: KSI-CMT-02
    "KSI-CMT-VTD": "Validating Throughout Deployment",  # fka: KSI-CMT-03
    "KSI-CMT-RVP": "Reviewing Change Procedures",  # fka: KSI-CMT-04
    
    # SCR - Supply Chain Risk (fka TPR - Third Party Risk)
    "KSI-SCR-MIT": "Mitigating Supply Chain Risk",  # fka: KSI-TPR-03
    "KSI-RSC-MON": "Monitoring Supply Chain Risk",  # fka: KSI-TPR-04
    
    # Additional categories
    "KSI-AFR-VDR": "Vulnerability Detection and Response",  # fka: KSI-AFR-04
    "KSI-AFR-SCN": "Significant Change Notifications",  # fka: KSI-AFR-05
    "KSI-AFR-ADS": "Authorization Data Sharing",  # fka: KSI-AFR-03
    "KSI-CED-RGT": "Reviewing General Training",  # fka: KSI-CED-01
    "KSI-CED-RST": "Reviewing Role-Specific Training",  # fka: KSI-CED-02
    "KSI-CED-DET": "Reviewing Development and Engineering Training",  # fka: KSI-CED-03
    "KSI-CED-RRT": "Reviewing Response and Recovery Training",  # fka: KSI-CED-04
    "KSI-INR-RIR": "Reviewing Incident Response Procedures",  # fka: KSI-INR-01
    "KSI-INR-RPI": "Reviewing Past Incidents",  # fka: KSI-INR-02
    "KSI-INR-AAR": "Generating After Action Reports",  # fka: KSI-INR-03
    "KSI-RPL-RRO": "Reviewing Recovery Objectives",  # fka: KSI-RPL-01
    "KSI-RPL-ARP": "Aligning Recovery Plan",  # fka: KSI-RPL-02
    "KSI-RPL-ABO": "Aligning Backups with Objectives",  # fka: KSI-RPL-03
    "KSI-RPL-TRC": "Testing Recovery Capabilities",  # fka: KSI-RPL-04
}

# Known wrong descriptions that should never appear
# Using new IDs (with fka mapping for reference)
FORBIDDEN_DESCRIPTIONS = {
    "KSI-PIY-GIV": [  # fka: KSI-PIY-01 - Generating Inventories
        "encryption at rest",
        "data encryption",
        "privacy",
        "pii",
        "data classification",
    ],
    "KSI-SVC-EIS": [  # fka: KSI-SVC-01 - Evaluating and Improving Security
        "secrets management",
        "secret management", 
        "key vault",
        "error handling",
        "logging",
    ],
    "KSI-SVC-SNT": [  # fka: KSI-SVC-02 - Securing Network Traffic
        "secrets",
        "key vault",
        "input validation",
        "sql injection",
    ],
    "KSI-SVC-ASM": [  # fka: KSI-SVC-06 - Automating Secret Management
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
    
    # Pattern to match KSI-XXX-YYY (new format) or KSI-XXX-NN (old format) with surrounding context
    # New format: KSI-IAM-MFA, KSI-PIY-GIV, KSI-SVC-ASM (3+ chars for suffix)
    # Old format: KSI-IAM-01, KSI-PIY-02, KSI-SVC-06 (2 digits)
    ksi_pattern = re.compile(r'(KSI-[A-Z]{2,3}-[A-Z0-9]{2,4})[:\s]*([^"\n\r]{0,100})', re.IGNORECASE)
    
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
        
        # Check for key KSIs - using new format IDs (v0.9.0-beta)
        ksis = authoritative_data.get("ksi", {})
        assert "KSI-PIY-GIV" in ksis, "KSI-PIY-GIV (fka KSI-PIY-01) not in authoritative data"
        assert "KSI-SVC-EIS" in ksis, "KSI-SVC-EIS (fka KSI-SVC-01) not in authoritative data"
        
        # Verify correct names
        piy_giv = ksis.get("KSI-PIY-GIV", {})
        assert piy_giv.get("name") == "Generating Inventories", \
            f"KSI-PIY-GIV should be 'Generating Inventories', got '{piy_giv.get('name')}'"
        
        svc_eis = ksis.get("KSI-SVC-EIS", {})
        assert svc_eis.get("name") == "Evaluating and Improving Security", \
            f"KSI-SVC-EIS should be 'Evaluating and Improving Security', got '{svc_eis.get('name')}'"
        
        svc_asm = ksis.get("KSI-SVC-ASM", {})
        assert svc_asm.get("name") == "Automating Secret Management", \
            f"KSI-SVC-ASM should be 'Automating Secret Management', got '{svc_asm.get('name')}'"
    
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
    
    def test_retired_ksis_not_in_active_data(self, authoritative_data):
        """Verify retired KSIs are not present in authoritative data.
        
        In FedRAMP 20x v0.9.0-beta, retired KSIs were removed entirely rather than
        being marked with a 'retired' flag. This test verifies they don't appear.
        """
        ksis = authoritative_data.get("ksi", {})
        
        # Old retired KSI IDs that should not exist
        retired_old_ids = [
            "KSI-CMT-05",
            "KSI-MLA-03", "KSI-MLA-04", "KSI-MLA-06",
            "KSI-PIY-02",
            "KSI-SVC-03",
            "KSI-TPR-01", "KSI-TPR-02",
        ]
        
        for old_id in retired_old_ids:
            assert old_id not in ksis, \
                f"Retired {old_id} should not be in KSI data"
            # Also check it doesn't appear as a new ID's fka value
            for ksi_id, ksi_data in ksis.items():
                fka = ksi_data.get("fka", "")
                assert fka != old_id, \
                    f"Retired {old_id} should not have a successor, found in {ksi_id}"


class TestKSIDefinitionAccuracy:
    """Test that specific KSI definitions match authoritative source."""
    
    @pytest.fixture
    def authoritative_data(self) -> Dict:
        return load_authoritative_ksi_data()
    
    @pytest.mark.parametrize("ksi_id,expected_name", [
        # Using new KSI IDs from v0.9.0-beta
        ("KSI-PIY-GIV", "Generating Inventories"),  # fka: KSI-PIY-01
        ("KSI-SVC-EIS", "Evaluating and Improving Security"),  # fka: KSI-SVC-01
        ("KSI-SVC-SNT", "Securing Network Traffic"),  # fka: KSI-SVC-02
        ("KSI-SVC-ASM", "Automating Secret Management"),  # fka: KSI-SVC-06
        ("KSI-IAM-MFA", "Enforcing Phishing-Resistant MFA"),  # fka: KSI-IAM-01
        ("KSI-CNA-RNT", "Restricting Network Traffic"),  # fka: KSI-CNA-01
        ("KSI-MLA-OSM", "Operating SIEM Capability"),  # fka: KSI-MLA-01
    ])
    def test_ksi_definition_matches_authoritative(self, authoritative_data, ksi_id, expected_name):
        """Verify KSI definition matches authoritative FedRAMP 20x source."""
        ksis = authoritative_data.get("ksi", {})
        ksi_data = ksis.get(ksi_id, {})
        
        actual_name = ksi_data.get("name")
        assert actual_name == expected_name, \
            f"{ksi_id}: expected '{expected_name}', got '{actual_name}'"
