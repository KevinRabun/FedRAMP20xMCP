"""
KSI-RPL-02: Recovery Plan

Develop and maintain a recovery plan that aligns with the defined recovery objectives.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_RPL_02_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-RPL-02: Recovery Plan
    
    **Official Statement:**
    Develop and maintain a recovery plan that aligns with the defined recovery objectives.
    
    **Family:** RPL - Recovery Planning
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cp-2
    - cp-2.1
    - cp-2.3
    - cp-4.1
    - cp-6
    - cp-6.1
    - cp-6.3
    - cp-7
    - cp-7.1
    - cp-7.2
    - cp-7.3
    - cp-8
    - cp-8.1
    - cp-8.2
    - cp-10
    - cp-10.2
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-RPL-02"
    KSI_NAME = "Recovery Plan"
    KSI_STATEMENT = """Develop and maintain a recovery plan that aligns with the defined recovery objectives."""
    FAMILY = "RPL"
    FAMILY_NAME = "Recovery Planning"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("cp-2", "Contingency Plan"),
        ("cp-2.1", "Coordinate with Related Plans"),
        ("cp-2.3", "Resume Mission and Business Functions"),
        ("cp-4.1", "Coordinate with Related Plans"),
        ("cp-6", "Alternate Storage Site"),
        ("cp-6.1", "Separation from Primary Site"),
        ("cp-6.3", "Accessibility"),
        ("cp-7", "Alternate Processing Site"),
        ("cp-7.1", "Separation from Primary Site"),
        ("cp-7.2", "Accessibility"),
        ("cp-7.3", "Priority of Service"),
        ("cp-8", "Telecommunications Services"),
        ("cp-8.1", "Priority of Service Provisions"),
        ("cp-8.2", "Single Points of Failure"),
        ("cp-10", "System Recovery and Reconstitution"),
        ("cp-10.2", "Transaction Recovery")
    ]
    CODE_DETECTABLE = False
    IMPLEMENTATION_STATUS = "NOT_IMPLEMENTED"
    RETIRED = False
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-RPL-02 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Develop and maintain a recovery plan that aligns with the defined recovery objec...
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
        Analyze C# code for KSI-RPL-02 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Develop and maintain a recovery plan that aligns with the defined recovery objec...
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-RPL-02 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Develop and maintain a recovery plan that aligns with the defined recovery objec...
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-RPL-02 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Develop and maintain a recovery plan that aligns with the defined recovery objec...
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep template for KSI-RPL-02 compliance.
        
        Detects:
        - Missing backup vault configuration
        - Missing backup policies
        - Missing retention policies
        - Missing geo-redundant storage
        """
        findings = []
        lines = code.split('\n')
        
        # Check for backup infrastructure
        has_backup_vault = bool(re.search(r'Microsoft\.RecoveryServices/vaults', code, re.IGNORECASE))
        has_backup_policy = bool(re.search(r'backupPolicies|backup.*policy', code, re.IGNORECASE))
        has_retention = bool(re.search(r'retention.*policy|retention.*period', code, re.IGNORECASE))
        has_geo_redundancy = bool(re.search(r'(GeoRedundant|ZoneRedundant)', code, re.IGNORECASE))
        has_vm_backup = bool(re.search(r'Microsoft\.RecoveryServices.*protectedItems', code, re.IGNORECASE))
        
        if not has_backup_vault:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Azure Backup Vault",
                description="No Recovery Services Vault configured. KSI-RPL-02 requires automated backup infrastructure aligned with recovery plan.",
                severity=Severity.CRITICAL,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add Recovery Services Vault: resource backupVault 'Microsoft.RecoveryServices/vaults@2023-01-01' = { name: 'vault-backup-prod', properties: { } }"
            ))
        
        if not has_backup_policy:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing backup policy",
                description="No backup policy configured. KSI-RPL-02 requires backup schedules and retention policies.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Add backup policy with schedule: schedulePolicy: { scheduleRunFrequency: 'Daily', scheduleRunTimes: ['2023-01-01T02:00:00Z'] }"
            ))
        
        if not has_geo_redundancy:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing geo-redundant backup storage",
                description="Backup storage not configured for geo-redundancy. KSI-RPL-02 recovery plan should include geographic redundancy.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1, 5),
                recommendation="Configure geo-redundancy: properties: { storageType: 'GeoRedundant', storageTypeState: 'Locked' }"
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-RPL-02 compliance.
        
        TODO: Implement detection logic for Azure resources related to:
        - Develop and maintain a recovery plan that aligns with the defined recovery objec...
        """
        findings = []
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-RPL-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-RPL-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-RPL-02 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    

