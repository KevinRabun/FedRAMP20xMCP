"""
KSI Coverage Audit Tools

Provides tools for understanding analyzer coverage and recommendation quality.
"""

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..data_loader import FedRAMPDataLoader

logger = logging.getLogger(__name__)

# Manually documented KSI coverage based on analyzer implementations
BICEP_COVERAGE = [
    # Phase 1 (8 KSIs)
    "KSI-MLA-05", "KSI-SVC-06", "KSI-CNA-01", "KSI-IAM-03", 
    "KSI-SVC-03", "KSI-IAM-01", "KSI-SVC-08", "KSI-PIY-02",
    # Phase 2 (9 KSIs)
    "KSI-IAM-02", "KSI-IAM-06", "KSI-CNA-02", "KSI-CNA-04",
    "KSI-CNA-06", "KSI-SVC-04", "KSI-SVC-05", "KSI-MLA-01", "KSI-MLA-02",
    # Phase 3 (8 KSIs)
    "KSI-SVC-01", "KSI-SVC-02", "KSI-SVC-07", "KSI-PIY-01",
    "KSI-PIY-03", "KSI-CNA-07", "KSI-IAM-04", "KSI-IAM-07",
    # Phase 4 (6 KSIs)
    "KSI-CMT-01", "KSI-CMT-02", "KSI-CMT-03", "KSI-AFR-01",
    "KSI-AFR-02", "KSI-CED-01",
    # Phase 5 (6 KSIs)
    "KSI-MLA-03", "KSI-MLA-04", "KSI-MLA-06", "KSI-INR-01",
    "KSI-INR-02", "KSI-AFR-03",
    # Phase 6A (8 KSIs)
    "KSI-RPL-01", "KSI-RPL-02", "KSI-RPL-03", "KSI-RPL-04",
    "KSI-CNA-03", "KSI-CNA-05", "KSI-IAM-05", "KSI-AFR-11",
    # Phase 6B (8 KSIs)
    "KSI-SVC-09", "KSI-SVC-10", "KSI-MLA-07", "KSI-MLA-08",
    "KSI-AFR-07", "KSI-CNA-08", "KSI-INR-03", "KSI-CMT-04",
    # Phase 7 (2 KSIs)
    "KSI-TPR-03", "KSI-TPR-04"
]

TERRAFORM_COVERAGE = BICEP_COVERAGE  # Same as Bicep

# Phase 1 (8 KSIs) + Phase 2 (2 KSIs) + Phase 3 (8 KSIs) + Phase 4 (4 KSIs) + Phase 5 (6 KSIs) = 28 KSIs
PYTHON_COVERAGE = [
    # Phase 1: Foundation
    "KSI-MLA-05", "KSI-SVC-06", "KSI-CNA-01", "KSI-IAM-03",
    "KSI-SVC-03", "KSI-IAM-01", "KSI-SVC-08", "KSI-PIY-02",
    # Phase 2: Application Security
    "KSI-IAM-05",  # Service Account Management
    "KSI-CNA-03",  # Microservices Security
    # Phase 3: Secure Coding Practices
    "KSI-SVC-01", "KSI-SVC-02", "KSI-SVC-07", "KSI-PIY-01",
    "KSI-PIY-03", "KSI-CNA-07", "KSI-IAM-04", "KSI-IAM-07",
    # Phase 4: Monitoring and Observability
    "KSI-MLA-03",  # Security Monitoring
    "KSI-MLA-04",  # Anomaly Detection
    "KSI-MLA-06",  # Performance Monitoring
    "KSI-INR-01",  # Incident Response
    # Phase 5: DevSecOps Automation
    "KSI-CMT-01",  # Configuration Management
    "KSI-CMT-02",  # Version Control Enforcement
    "KSI-CMT-03",  # Automated Testing
    "KSI-AFR-01",  # Audit Logging
    "KSI-AFR-02",  # Log Integrity
    "KSI-CED-01",  # Key Management
]

CSHARP_COVERAGE = PYTHON_COVERAGE
JAVA_COVERAGE = PYTHON_COVERAGE
TYPESCRIPT_COVERAGE = PYTHON_COVERAGE

# KSIs that are not technical (process/policy only)
# Reduced from 23 to 15 after CODE_DETECTABLE accuracy verification (Dec 2024)
# Removed: AFR-02, PIY-04, PIY-05, PIY-06, PIY-07, PIY-08, RPL-02, RPL-04
# (these have code-detectable components in CI/CD, IaC, or SBOM/dependency scanning)
NON_TECHNICAL_KSIS = [
    "KSI-AFR-01", "KSI-AFR-03", "KSI-AFR-05", "KSI-AFR-06",
    "KSI-AFR-08", "KSI-AFR-09", "KSI-AFR-10",
    "KSI-CED-01", "KSI-CED-02", "KSI-CED-03", "KSI-CED-04",
    "KSI-INR-01", "KSI-INR-03",
    "KSI-PIY-03",
    "KSI-RPL-01"
]


async def get_ksi_coverage_summary_impl(data_loader: "FedRAMPDataLoader") -> str:
    """Get a summary of KSI analyzer coverage and recommendation quality."""
    data = await data_loader.load_data()
    ksi_data = data.get('ksi', {})
    total_ksis = len(ksi_data)
    
    all_covered = set(BICEP_COVERAGE + PYTHON_COVERAGE)
    uncovered = set(ksi_data.keys()) - all_covered - set(NON_TECHNICAL_KSIS)
    
    result = "# FedRAMP 20x KSI Coverage Summary\n\n"
    result += "## Quick Stats\n\n"
    result += f"- **Total KSIs:** {total_ksis}\n"
    result += f"- **Infrastructure Coverage (Bicep/Terraform):** {len(BICEP_COVERAGE)} KSIs ({len(BICEP_COVERAGE)/total_ksis*100:.1f}%)\n"
    result += f"- **Application Coverage (Python/C#/Java/TS):** {len(PYTHON_COVERAGE)} KSIs ({len(PYTHON_COVERAGE)/total_ksis*100:.1f}%)\n"
    result += f"- **Unique KSIs Covered:** {len(all_covered)} KSIs ({len(all_covered)/total_ksis*100:.1f}%)\n"
    result += f"- **Non-Technical (Process) KSIs:** {len(NON_TECHNICAL_KSIS)} KSIs\n"
    result += f"- **Technical KSIs Missing:** {len(uncovered)} KSIs\n\n"
    
    result += "## What We CAN Attest To ✅\n\n"
    result += "- Recommendations follow Azure Well-Architected Framework principles\n"
    result += "- Code patterns detect common security misconfigurations\n"
    result += "- Infrastructure templates use Azure best practices\n"
    result += "- All implemented analyzers have passing test suites\n"
    result += "- Recommendations cite specific Azure services and documentation\n\n"
    
    result += "## What We CANNOT Attest To ❌\n\n"
    result += "- Recommendations have NOT been validated by FedRAMP 3PAOs\n"
    result += "- Code has NOT been tested against real authorization packages\n"
    result += "- No production validation in FedRAMP-authorized environments\n"
    result += "- No external security expert review\n"
    result += "- Framework-specific edge cases may not be covered\n"
    result += "- Only 76% of KSIs have infrastructure coverage\n"
    result += "- Only 11% of KSIs have application code coverage\n\n"
    
    result += "## ⚠️ IMPORTANT DISCLAIMER\n\n"
    result += "**This MCP server should be treated as:**\n\n"
    result += "- ✅ A helpful development-time guardrail\n"
    result += "- ✅ A starting point for FedRAMP compliance\n"
    result += "- ✅ An educational tool for understanding KSI requirements\n\n"
    result += "**This MCP server is NOT:**\n\n"
    result += "- ❌ A substitute for 3PAO assessment\n"
    result += "- ❌ A guarantee of FedRAMP authorization\n"
    result += "- ❌ A replacement for security expert review\n\n"
    
    result += f"## Missing Coverage ({len(uncovered)} Technical KSIs)\n\n"
    if uncovered:
        for ksi_id in sorted(uncovered):
            ksi_info = ksi_data.get(ksi_id, {})
            title = ksi_info.get('title', ksi_info.get('name', 'No title'))
            result += f"- **{ksi_id}**: {title}\n"
    
    result += "\n---\n"
    result += "*For detailed coverage analysis, see KSI_COVERAGE_AUDIT.md in the repository*\n"
    
    return result


async def get_ksi_coverage_status_impl(ksi_id: str, data_loader: "FedRAMPDataLoader") -> str:
    """Check if a specific KSI has analyzer coverage and what the limitations are."""
    data = await data_loader.load_data()
    ksi_data = data.get('ksi', {})
    
    if ksi_id not in ksi_data:
        return f"❌ Error: KSI '{ksi_id}' not found in FedRAMP 20x data"
    
    ksi_info = ksi_data[ksi_id]
    title = ksi_info.get('title', ksi_info.get('name', 'No title'))
    
    result = f"# Coverage Status: {ksi_id}\n\n"
    result += f"**Title:** {title}\n\n"
    
    # Check coverage
    in_bicep = ksi_id in BICEP_COVERAGE
    in_terraform = ksi_id in TERRAFORM_COVERAGE
    in_python = ksi_id in PYTHON_COVERAGE
    in_csharp = ksi_id in CSHARP_COVERAGE
    in_java = ksi_id in JAVA_COVERAGE
    in_typescript = ksi_id in TYPESCRIPT_COVERAGE
    is_process = ksi_id in NON_TECHNICAL_KSIS
    
    result += "## Analyzer Coverage\n\n"
    result += f"- **Bicep IaC:** {'✅ Covered' if in_bicep else '❌ Not covered'}\n"
    result += f"- **Terraform IaC:** {'✅ Covered' if in_terraform else '❌ Not covered'}\n"
    result += f"- **Python:** {'✅ Covered' if in_python else '❌ Not covered'}\n"
    result += f"- **C#:** {'✅ Covered' if in_csharp else '❌ Not covered'}\n"
    result += f"- **Java:** {'✅ Covered' if in_java else '❌ Not covered'}\n"
    result += f"- **TypeScript/JS:** {'✅ Covered' if in_typescript else '❌ Not covered'}\n\n"
    
    # Status assessment
    if is_process:
        result += "## Status: ⚪ Process-Based\n\n"
        result += "This KSI is process or policy-based with no direct technical implementation.\n"
        result += "It requires organizational procedures and documentation.\n\n"
    elif in_bicep and in_python:
        result += "## Status: ✅ Full Coverage\n\n"
        result += "This KSI has both infrastructure and application code analyzer coverage.\n\n"
    elif in_bicep:
        result += "## Status: 🟡 Partial Coverage (IaC Only)\n\n"
        result += "This KSI has infrastructure analyzer coverage but lacks application code checks.\n"
        result += "Application-level implementations of this KSI will not be validated.\n\n"
    elif in_python:
        result += "## Status: 🟡 Partial Coverage (Application Only)\n\n"
        result += "This KSI has application code analyzer coverage but lacks infrastructure checks.\n"
        result += "Infrastructure-level implementations of this KSI will not be validated.\n\n"
    else:
        result += "## Status: 🔴 No Coverage\n\n"
        result += "This KSI has no analyzer coverage implemented.\n"
        result += "**Recommendations for this KSI have not been validated and should be reviewed by a 3PAO.**\n\n"
    
    result += "## ⚠️ Important Limitations\n\n"
    result += "Even with analyzer coverage, please note:\n\n"
    result += "1. **Not 3PAO Validated**: Analyzer rules have not been reviewed by FedRAMP assessors\n"
    result += "2. **Best Effort**: Recommendations are based on Azure best practices, not authorization packages\n"
    result += "3. **May Miss Edge Cases**: Framework-specific or complex scenarios may not be detected\n"
    result += "4. **No Guarantee**: Passing analyzer checks does NOT guarantee FedRAMP compliance\n\n"
    
    result += "**Always consult with a FedRAMP 3PAO for authoritative guidance.**\n"
    
    return result


def get_coverage_disclaimer() -> str:
    """Get a standard disclaimer about analyzer coverage limitations."""
    return (
        "\n\n---\n\n"
        "⚠️ **Analyzer Coverage Disclaimer**: This recommendation is based on Azure best practices "
        "and has NOT been validated by FedRAMP 3PAOs. Analyzer coverage varies by KSI "
        "(76% infrastructure, 11% application code). Always consult with a 3PAO for authoritative guidance. "
        "Use `get_ksi_coverage_status` to check coverage for specific KSIs."
    )
