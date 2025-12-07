"""
KSI-PIY-02: Security Objectives and Requirements

Document the security objectives and requirements for each information resource or set of information resources.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_PIY_02_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-PIY-02: Security Objectives and Requirements
    
    **Official Statement:**
    Document the security objectives and requirements for each information resource or set of information resources.
    
    **Family:** PIY - Policy and Inventory
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-1
    - ac-21
    - at-1
    - au-1
    - ca-1
    - cm-1
    - cp-1
    - cp-2.1
    - cp-2.8
    - cp-4.1
    - ia-1
    - ir-1
    - ma-1
    - mp-1
    - pe-1
    - pl-1
    - pl-2
    - pl-4
    - pl-4.1
    - ps-1
    - ra-1
    - ra-9
    - sa-1
    - sc-1
    - si-1
    - sr-1
    - sr-2
    - sr-3
    - sr-11
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-PIY-02"
    KSI_NAME = "Security Objectives and Requirements"
    KSI_STATEMENT = """Document the security objectives and requirements for each information resource or set of information resources."""
    FAMILY = "PIY"
    FAMILY_NAME = "Policy and Inventory"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-1", "ac-21", "at-1", "au-1", "ca-1", "cm-1", "cp-1", "cp-2.1", "cp-2.8", "cp-4.1", "ia-1", "ir-1", "ma-1", "mp-1", "pe-1", "pl-1", "pl-2", "pl-4", "pl-4.1", "ps-1", "ra-1", "ra-9", "sa-1", "sc-1", "si-1", "sr-1", "sr-2", "sr-3", "sr-11"]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
    def __init__(self):
        super().__init__(
            ksi_id=self.KSI_ID,
            ksi_name=self.KSI_NAME,
            ksi_statement=self.KSI_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-PIY-02 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Document the security objectives and requirements for each information resource ...
        """
        findings = []
        
        # TODO: Implement Python-specific detection logic
        # Example patterns to detect:
        # - Configuration issues
        # - Missing security controls
        # - Framework-specific vulnerabilities
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-PIY-02 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Document the security objectives and requirements for each information resource ...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-PIY-02 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Document the security objectives and requirements for each information resource ...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-PIY-02 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Document the security objectives and requirements for each information resource ...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-PIY-02 compliance.
        
        Detects:
        - Missing resource tags for classification/inventory
        - Missing security documentation
        - Unclassified data resources
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Resources without tags (MEDIUM)
        resource_pattern = r"resource\s+\w+\s+'([^']+)'"
        for i, line in enumerate(lines, 1):
            match = re.search(resource_pattern, line)
            if match:
                resource_type = match.group(1)
                # Check if resource has tags in next 50 lines
                context_end = min(len(lines), i + 50)
                context = '\n'.join(lines[i:context_end])
                has_tags = 'tags:' in context or 'tags =' in context
                
                # Skip certain resource types that don't support tags
                skip_types = ['Microsoft.Resources/', 'Microsoft.Authorization/']
                if any(skip in resource_type for skip in skip_types):
                    continue
                
                if not has_tags:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title=f"Resource Missing Classification Tags",
                        description=(
                            f"Resource of type '{resource_type}' does not have tags defined. "
                            "KSI-PIY-02 requires documenting security objectives and requirements "
                            "for each information resource (PL-2, PL-4). Azure tags should classify "
                            "resources by sensitivity, owner, purpose, and compliance requirements. "
                            "Without tags, resources cannot be properly inventoried, managed, or "
                            "protected according to their security requirements."
                        ),
                        file_path=file_path,
                        line_number=i,
                        snippet=self._get_snippet(lines, i, context=3),
                        remediation=(
                            f"Add classification tags to resource:\\n"
                            f"resource example '{resource_type}' = {{\\n"
                            "  name: 'resource-name'\\n"
                            "  location: location\\n"
                            "  \\n"
                            "  tags: {\\n"
                            "    // Security classification (REQUIRED for KSI-PIY-02)\\n"
                            "    Sensitivity: 'Confidential'  // Public, Internal, Confidential, Restricted\\n"
                            "    DataClassification: 'PII'    // None, PII, PHI, Financial, etc.\\n"
                            "    \\n"
                            "    // Ownership and accountability\\n"
                            "    Owner: 'team-name@company.com'\\n"
                            "    CostCenter: 'CC-12345'\\n"
                            "    \\n"
                            "    // Purpose and compliance\\n"
                            "    Purpose: 'Customer data processing'\\n"
                            "    Compliance: 'FedRAMP-Moderate'\\n"
                            "    Environment: 'Production'\\n"
                            "    \\n"
                            "    // Lifecycle management\\n"
                            "    CreatedDate: '2025-12-06'\\n"
                            "    ReviewDate: '2026-12-06'\\n"
                            "  }\\n"
                            "}\\n\\n"
                            "These tags enable:\\n"
                            "- Automated security policy enforcement\\n"
                            "- Resource inventory and classification\\n"
                            "- Cost allocation and governance\\n"
                            "- Compliance reporting"
                        )
                    ))
        
        # Pattern 2: Storage accounts without data classification (HIGH)\n        has_storage = bool(re.search(r"Microsoft\\.Storage/storageAccounts", code))
        if has_storage:
            storage_with_tags = bool(re.search(r"Microsoft\\.Storage/storageAccounts.*?tags:", code, re.DOTALL))
            if not storage_with_tags:
                line_num = self._find_line(lines, 'storageAccounts')
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Storage Account Missing Data Classification Tags",
                    description=(
                        "Storage account deployed without data classification tags. "
                        "KSI-PIY-02 requires documenting security requirements for data resources (PL-2, RA-9). "
                        "Storage accounts often contain sensitive data and MUST have classification tags "
                        "to ensure appropriate security controls are applied."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Add data classification tags to storage account:\\n"
                        "tags: {\\n"
                        "  DataClassification: 'PII'  // REQUIRED: Classify data stored\\n"
                        "  Sensitivity: 'Confidential'\\n"
                        "  EncryptionRequired: 'true'\\n"
                        "  BackupRequired: 'true'\\n"
                        "  RetentionPeriod: '7-years'\\n"
                        "  DataResidency: 'US-Only'\\n"
                        "}"
                    )
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-PIY-02 compliance.
        
        Detects:
        - Missing resource tags for classification
        - Untagged data resources
        """
        findings = []
        lines = code.split('\\n')
        
        # Pattern 1: Resources without tags (MEDIUM)
        resource_pattern = r'resource\\s+"([^"]+)"\\s+"([^"]+)"'
        for i, line in enumerate(lines, 1):
            match = re.search(resource_pattern, line)
            if match:
                resource_type = match.group(1)
                resource_name = match.group(2)
                
                # Check if resource has tags in next 50 lines
                context_end = min(len(lines), i + 50)
                context = '\\n'.join(lines[i:context_end])
                has_tags = 'tags' in context and ('=' in context or '{' in context)
                
                # Skip resources that don't support tags
                skip_types = ['azurerm_resource_group', 'random_', 'null_resource']
                if any(skip in resource_type for skip in skip_types):
                    continue
                
                if not has_tags and 'azurerm_' in resource_type:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title=f"Resource '{resource_name}' Missing Classification Tags",
                        description=(
                            f"Terraform resource '{resource_name}' ({resource_type}) does not have tags. "
                            "KSI-PIY-02 requires documenting security objectives for each resource (PL-2, PL-4). "
                            "Tags enable resource classification, security policy enforcement, and compliance tracking."
                        ),
                        file_path=file_path,
                        line_number=i,
                        snippet=self._get_snippet(lines, i, context=3),
                        remediation=(
                            f'Add tags block to resource "{resource_name}":\\n'
                            f'resource "{resource_type}" "{resource_name}" {{\\n'
                            '  # ... resource configuration ...\\n'
                            '  \\n'
                            '  tags = {\\n'
                            '    # Security classification (REQUIRED)\\n'
                            '    Sensitivity         = "Confidential"\\n'
                            '    DataClassification  = "PII"\\n'
                            '    \\n'
                            '    # Ownership\\n'
                            '    Owner              = "team-name@company.com"\\n'
                            '    CostCenter         = "CC-12345"\\n'
                            '    \\n'
                            '    # Compliance\\n'
                            '    Compliance         = "FedRAMP-Moderate"\\n'
                            '    Environment        = var.environment\\n'
                            '    ManagedBy          = "Terraform"\\n'
                            '  }\\n'
                            '}'
                        )
                    ))
        
        # Pattern 2: Storage accounts without data classification (HIGH)
        storage_match = re.search(r'resource\\s+"azurerm_storage_account"', code)
        if storage_match:
            # Check if any storage account has data classification tags
            has_data_class = bool(re.search(r'DataClassification|data_classification', code, re.IGNORECASE))
            if not has_data_class:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Storage Account Missing Data Classification Tags",
                    description=(
                        "Storage account(s) deployed without data classification tags. "
                        "KSI-PIY-02 requires documenting security requirements for data resources (PL-2, RA-9)."
                    ),
                    file_path=file_path,
                    line_number=self._find_line(lines, 'azurerm_storage_account'),
                    snippet=self._get_snippet(lines, self._find_line(lines, 'azurerm_storage_account'), context=3),
                    remediation=(
                        "Add data classification to storage account tags:\\n"
                        'resource "azurerm_storage_account" "example" {\\n'
                        '  # ... configuration ...\\n'
                        '  \\n'
                        '  tags = {\\n'
                        '    DataClassification  = "PII"      # REQUIRED\\n'
                        '    Sensitivity         = "Confidential"\\n'
                        '    EncryptionRequired  = "true"\\n'
                        '    BackupRequired      = "true"\\n'
                        '    RetentionPeriod     = "7-years"\\n'
                        '  }\\n'
                        '}'
                    )
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-PIY-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-PIY-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-PIY-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], search_term: str) -> int:
        """Find line number containing search term."""
        for i, line in enumerate(lines, 1):
            if search_term.lower() in line.lower():
                return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
