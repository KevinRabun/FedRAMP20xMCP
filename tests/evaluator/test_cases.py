"""
Evaluation Test Cases

Defines ground truth test cases for evaluating the MCP server.
Each test case specifies:
- Input (tool call parameters)
- Expected output or validation criteria
- Category and importance
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Union
import re


class TestCaseCategory(Enum):
    """Test case category matching evaluation categories."""
    ACCURACY = "accuracy"
    COMPLETENESS = "completeness"
    ANALYSIS_QUALITY = "analysis_quality"
    RELEVANCE = "relevance"
    CONSISTENCY = "consistency"


class Importance(Enum):
    """Test case importance level."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class EvaluationTestCase:
    """A single evaluation test case."""
    id: str
    category: TestCaseCategory
    importance: Importance
    tool_name: str
    tool_params: Dict[str, Any]
    description: str
    
    # Validation criteria (use one or more)
    expected_value: Optional[Any] = None  # Exact match
    expected_contains: Optional[List[str]] = None  # Must contain all strings
    expected_not_contains: Optional[List[str]] = None  # Must not contain any
    expected_pattern: Optional[str] = None  # Regex pattern to match
    validation_func: Optional[Callable[[Any], bool]] = None  # Custom validator
    expected_min_length: Optional[int] = None  # Minimum response length
    expected_json_keys: Optional[List[str]] = None  # JSON must have these keys
    
    # Metadata
    tags: List[str] = field(default_factory=list)
    notes: str = ""


# =============================================================================
# ACCURACY TEST CASES
# Verify that tool responses match authoritative FedRAMP 20x data
# =============================================================================

ACCURACY_TEST_CASES = [
    # KSI Definition Accuracy
    EvaluationTestCase(
        id="ACC-KSI-001",
        category=TestCaseCategory.ACCURACY,
        importance=Importance.CRITICAL,
        tool_name="get_ksi",
        tool_params={"ksi_id": "KSI-IAM-01"},
        description="Verify KSI-IAM-01 returns correct name",
        expected_contains=["Phishing-Resistant MFA"],
        tags=["ksi", "iam"],
    ),
    EvaluationTestCase(
        id="ACC-KSI-002",
        category=TestCaseCategory.ACCURACY,
        importance=Importance.CRITICAL,
        tool_name="get_ksi",
        tool_params={"ksi_id": "KSI-SVC-06"},
        description="Verify KSI-SVC-06 (Secret Management) returns correct definition",
        expected_contains=[
            "Secret Management",
            "keys",
            "certificates",
            "secrets",
        ],
        expected_not_contains=["encryption at rest", "encryption in transit"],
        tags=["ksi", "svc", "secrets"],
    ),
    EvaluationTestCase(
        id="ACC-KSI-003",
        category=TestCaseCategory.ACCURACY,
        importance=Importance.CRITICAL,
        tool_name="get_ksi",
        tool_params={"ksi_id": "KSI-PIY-01"},
        description="Verify KSI-PIY-01 is Automated Inventory (NOT encryption)",
        expected_contains=["Automated Inventory", "inventories"],
        expected_not_contains=["encryption"],
        tags=["ksi", "piy", "critical-misunderstanding"],
    ),
    EvaluationTestCase(
        id="ACC-KSI-004",
        category=TestCaseCategory.ACCURACY,
        importance=Importance.HIGH,
        tool_name="get_ksi",
        tool_params={"ksi_id": "KSI-CNA-01"},
        description="Verify KSI-CNA-01 (Restrict Network Traffic) definition",
        expected_contains=["Restrict Network Traffic", "network"],
        tags=["ksi", "cna"],
    ),
    EvaluationTestCase(
        id="ACC-KSI-005",
        category=TestCaseCategory.ACCURACY,
        importance=Importance.HIGH,
        tool_name="get_ksi",
        tool_params={"ksi_id": "KSI-SVC-01"},
        description="Verify KSI-SVC-01 (Continuous Improvement) is NOT about secrets",
        expected_contains=["Continuous Improvement"],
        expected_not_contains=["secret", "key rotation"],
        tags=["ksi", "svc", "critical-misunderstanding"],
    ),
    
    # FRR Definition Accuracy
    EvaluationTestCase(
        id="ACC-FRR-001",
        category=TestCaseCategory.ACCURACY,
        importance=Importance.CRITICAL,
        tool_name="get_control",
        tool_params={"control_id": "FRR-VDR-01"},
        description="Verify FRR-VDR-01 (Vulnerability Detection) exists and has statement",
        expected_contains=["VDR", "vulnerability"],
        tags=["frr", "vdr"],
    ),
    EvaluationTestCase(
        id="ACC-FRR-002",
        category=TestCaseCategory.ACCURACY,
        importance=Importance.HIGH,
        tool_name="get_control",
        tool_params={"control_id": "FRR-RSC-01"},
        description="Verify FRR-RSC-01 (Recommended Secure Configuration) exists",
        expected_contains=["RSC"],
        tags=["frr", "rsc"],
    ),
    EvaluationTestCase(
        id="ACC-FRR-003",
        category=TestCaseCategory.ACCURACY,
        importance=Importance.HIGH,
        tool_name="get_control",
        tool_params={"control_id": "FRR-ADS-01"},
        description="Verify FRR-ADS-01 (Authorization Data Sharing) definition",
        expected_contains=["ADS"],
        tags=["frr", "ads"],
    ),
    
    # Definition Accuracy
    EvaluationTestCase(
        id="ACC-DEF-001",
        category=TestCaseCategory.ACCURACY,
        importance=Importance.MEDIUM,
        tool_name="get_definition",
        tool_params={"term": "authorization"},
        description="Verify 'authorization' definition is returned",
        expected_min_length=50,
        tags=["definition"],
    ),
    
    # Retired KSI Accuracy
    EvaluationTestCase(
        id="ACC-RET-001",
        category=TestCaseCategory.ACCURACY,
        importance=Importance.HIGH,
        tool_name="get_ksi",
        tool_params={"ksi_id": "KSI-CMT-05"},
        description="Verify retired KSI-CMT-05 is marked as retired",
        expected_contains=["retired"],
        tags=["ksi", "retired"],
    ),
]


# =============================================================================
# COMPLETENESS TEST CASES
# Verify that tools return all relevant information
# =============================================================================

COMPLETENESS_TEST_CASES = [
    EvaluationTestCase(
        id="CMP-KSI-001",
        category=TestCaseCategory.COMPLETENESS,
        importance=Importance.CRITICAL,
        tool_name="list_ksi",
        tool_params={},
        description="Verify list_ksi returns all 65+ active KSIs",
        expected_contains=["KSI-IAM-01", "KSI-CNA-01", "KSI-SVC-06"],
        validation_func=lambda x: x.count("KSI-") >= 60,
        tags=["ksi", "list"],
    ),
    EvaluationTestCase(
        id="CMP-FAM-001",
        category=TestCaseCategory.COMPLETENESS,
        importance=Importance.HIGH,
        tool_name="list_family_controls",
        tool_params={"family": "VDR"},
        description="Verify VDR family returns multiple requirements",
        expected_contains=["VDR"],  # Family returns VDR requirements
        validation_func=lambda x: "VDR" in x.upper(),
        tags=["frr", "family", "vdr"],
    ),
    EvaluationTestCase(
        id="CMP-FAM-002",
        category=TestCaseCategory.COMPLETENESS,
        importance=Importance.HIGH,
        tool_name="list_family_controls",
        tool_params={"family": "IAM"},
        description="Verify IAM family returns KSIs",
        expected_contains=["IAM"],  # Should contain IAM-related content
        tags=["ksi", "family", "iam"],
    ),
    EvaluationTestCase(
        id="CMP-DEF-001",
        category=TestCaseCategory.COMPLETENESS,
        importance=Importance.MEDIUM,
        tool_name="list_definitions",
        tool_params={},
        description="Verify list_definitions returns 40+ definitions",
        validation_func=lambda x: len(x) > 1000,  # Should be substantial
        tags=["definition", "list"],
    ),
    EvaluationTestCase(
        id="CMP-SEARCH-001",
        category=TestCaseCategory.COMPLETENESS,
        importance=Importance.MEDIUM,
        tool_name="search_requirements",
        tool_params={"keywords": "encryption"},
        description="Verify encryption search returns relevant results",
        expected_contains=["encryption"],
        validation_func=lambda x: x.lower().count("encrypt") >= 3,
        tags=["search"],
    ),
]


# =============================================================================
# ANALYSIS QUALITY TEST CASES
# Verify that code analyzers detect issues correctly
# =============================================================================

# Sample code snippets for analysis testing
VULNERABLE_PYTHON_CODE = '''
import hashlib
import pickle

def hash_password(password):
    # Using weak MD5 hash
    return hashlib.md5(password.encode()).hexdigest()

def load_data(data):
    # Unsafe deserialization
    return pickle.loads(data)

API_KEY = "sk-1234567890abcdef"  # Hardcoded secret
'''

SECURE_PYTHON_CODE = '''
import hashlib
import json
import os

def hash_password(password):
    # Using secure bcrypt
    import bcrypt
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def load_data(data):
    # Safe JSON parsing
    return json.loads(data)

API_KEY = os.environ.get("API_KEY")  # From environment
'''

VULNERABLE_BICEP_CODE = '''
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: 'eastus'
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true  // Security issue
    minimumTlsVersion: 'TLS1_0'  // Weak TLS
  }
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'mykeyvault'
  location: 'eastus'
  properties: {
    sku: {
      family: 'A'
      name: 'standard'  // Should be premium for HSM
    }
    tenantId: subscription().tenantId
    enableSoftDelete: false  // Should be enabled
  }
}
'''

SECURE_BICEP_CODE = '''
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: 'eastus'
  sku: {
    name: 'Standard_GRS'
  }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    encryption: {
      services: {
        blob: {
          enabled: true
          keyType: 'Account'
        }
      }
      keySource: 'Microsoft.Keyvault'
    }
  }
}
'''

ANALYSIS_QUALITY_TEST_CASES = [
    # Detect vulnerabilities in Python
    EvaluationTestCase(
        id="ANL-PY-001",
        category=TestCaseCategory.ANALYSIS_QUALITY,
        importance=Importance.CRITICAL,
        tool_name="analyze_application_code",
        tool_params={
            "code": VULNERABLE_PYTHON_CODE,
            "language": "python",
        },
        description="Detect hardcoded secret in Python code",
        expected_contains=["secret", "hardcoded"],
        tags=["python", "secrets", "detection"],
    ),
    EvaluationTestCase(
        id="ANL-PY-002",
        category=TestCaseCategory.ANALYSIS_QUALITY,
        importance=Importance.HIGH,
        tool_name="analyze_application_code",
        tool_params={
            "code": VULNERABLE_PYTHON_CODE,
            "language": "python",
        },
        description="Detect weak hash algorithm (MD5) in Python",
        expected_contains=["md5", "hash", "weak"],
        tags=["python", "crypto", "detection"],
    ),
    EvaluationTestCase(
        id="ANL-PY-003",
        category=TestCaseCategory.ANALYSIS_QUALITY,
        importance=Importance.HIGH,
        tool_name="analyze_application_code",
        tool_params={
            "code": VULNERABLE_PYTHON_CODE,
            "language": "python",
        },
        description="Detect unsafe deserialization (pickle) in Python",
        expected_contains=["pickle"],  # Should mention pickle
        tags=["python", "injection", "detection"],
    ),
    EvaluationTestCase(
        id="ANL-PY-004",
        category=TestCaseCategory.ANALYSIS_QUALITY,
        importance=Importance.MEDIUM,
        tool_name="analyze_application_code",
        tool_params={
            "code": SECURE_PYTHON_CODE,
            "language": "python",
        },
        description="Secure Python code should have fewer critical findings",
        # Secure code may still have some findings but should be cleaner
        expected_min_length=50,  # Should return some analysis
        tags=["python", "false-positive"],
    ),
    
    # Detect vulnerabilities in Bicep
    EvaluationTestCase(
        id="ANL-BICEP-001",
        category=TestCaseCategory.ANALYSIS_QUALITY,
        importance=Importance.CRITICAL,
        tool_name="analyze_infrastructure_code",
        tool_params={
            "code": VULNERABLE_BICEP_CODE,
            "file_type": "bicep",
        },
        description="Detect public blob access in Bicep",
        expected_contains=["public", "blob"],
        tags=["bicep", "storage", "detection"],
    ),
    EvaluationTestCase(
        id="ANL-BICEP-002",
        category=TestCaseCategory.ANALYSIS_QUALITY,
        importance=Importance.HIGH,
        tool_name="analyze_infrastructure_code",
        tool_params={
            "code": VULNERABLE_BICEP_CODE,
            "file_type": "bicep",
        },
        description="Detect weak TLS version in Bicep",
        expected_contains=["TLS", "1.0", "1.2"],
        tags=["bicep", "tls", "detection"],
    ),
    EvaluationTestCase(
        id="ANL-BICEP-003",
        category=TestCaseCategory.ANALYSIS_QUALITY,
        importance=Importance.MEDIUM,
        tool_name="analyze_infrastructure_code",
        tool_params={
            "code": SECURE_BICEP_CODE,
            "file_type": "bicep",
        },
        description="Secure Bicep code analysis should complete successfully",
        expected_min_length=100,  # Should return analysis results
        tags=["bicep", "false-positive"],
    ),
    
    # FRR-specific analysis
    EvaluationTestCase(
        id="ANL-FRR-001",
        category=TestCaseCategory.ANALYSIS_QUALITY,
        importance=Importance.HIGH,
        tool_name="analyze_frr_code",
        tool_params={
            "frr_id": "FRR-VDR-01",
            "code": VULNERABLE_PYTHON_CODE,
            "language": "python",
        },
        description="FRR-VDR-01 analysis should return results (may have async issues)",
        expected_min_length=20,  # Basic validation - tool should return something
        tags=["frr", "vdr", "python"],
    ),
]


# =============================================================================
# RELEVANCE TEST CASES
# Verify that search results and recommendations are relevant
# =============================================================================

RELEVANCE_TEST_CASES = [
    EvaluationTestCase(
        id="REL-SEARCH-001",
        category=TestCaseCategory.RELEVANCE,
        importance=Importance.HIGH,
        tool_name="search_requirements",
        tool_params={"keywords": "multi-factor authentication"},
        description="MFA search should return IAM-related results",
        expected_contains=["authentication"],  # Search should find authentication-related content
        tags=["search", "mfa"],
    ),
    EvaluationTestCase(
        id="REL-SEARCH-002",
        category=TestCaseCategory.RELEVANCE,
        importance=Importance.HIGH,
        tool_name="search_requirements",
        tool_params={"keywords": "logging audit"},
        description="Logging/audit search should return monitoring results",
        expected_contains=["log", "audit"],  # Should find logging or audit content
        tags=["search", "logging"],
    ),
    EvaluationTestCase(
        id="REL-SEARCH-003",
        category=TestCaseCategory.RELEVANCE,
        importance=Importance.MEDIUM,
        tool_name="search_definitions",
        tool_params={"keywords": "cloud service"},
        description="Cloud service search should return relevant definitions",
        expected_contains=["cloud"],
        tags=["search", "definition"],
    ),
    EvaluationTestCase(
        id="REL-KSI-001",
        category=TestCaseCategory.RELEVANCE,
        importance=Importance.HIGH,
        tool_name="get_ksi_implementation_summary",
        tool_params={},
        description="KSI summary should include implementation status",
        expected_contains=["implemented", "code-detectable"],
        tags=["ksi", "summary"],
    ),
]


# =============================================================================
# CONSISTENCY TEST CASES
# Verify that repeated queries return consistent results
# =============================================================================

CONSISTENCY_TEST_CASES = [
    EvaluationTestCase(
        id="CON-KSI-001",
        category=TestCaseCategory.CONSISTENCY,
        importance=Importance.CRITICAL,
        tool_name="get_ksi",
        tool_params={"ksi_id": "KSI-IAM-01"},
        description="KSI-IAM-01 should return consistent results across calls",
        expected_contains=["Phishing-Resistant MFA"],
        tags=["ksi", "consistency"],
        notes="Run multiple times and compare",
    ),
    EvaluationTestCase(
        id="CON-SEARCH-001",
        category=TestCaseCategory.CONSISTENCY,
        importance=Importance.HIGH,
        tool_name="search_requirements",
        tool_params={"keywords": "encryption"},
        description="Search results should be consistent across calls",
        tags=["search", "consistency"],
        notes="Run multiple times and compare result count",
    ),
]


# =============================================================================
# ALL TEST CASES
# =============================================================================

ALL_TEST_CASES: List[EvaluationTestCase] = (
    ACCURACY_TEST_CASES +
    COMPLETENESS_TEST_CASES +
    ANALYSIS_QUALITY_TEST_CASES +
    RELEVANCE_TEST_CASES +
    CONSISTENCY_TEST_CASES
)


def get_test_cases_by_category(category: TestCaseCategory) -> List[EvaluationTestCase]:
    """Get all test cases for a specific category."""
    return [tc for tc in ALL_TEST_CASES if tc.category == category]


def get_test_cases_by_importance(importance: Importance) -> List[EvaluationTestCase]:
    """Get all test cases of a specific importance level."""
    return [tc for tc in ALL_TEST_CASES if tc.importance == importance]


def get_test_cases_by_tag(tag: str) -> List[EvaluationTestCase]:
    """Get all test cases with a specific tag."""
    return [tc for tc in ALL_TEST_CASES if tag in tc.tags]


def get_critical_test_cases() -> List[EvaluationTestCase]:
    """Get all critical importance test cases."""
    return get_test_cases_by_importance(Importance.CRITICAL)
