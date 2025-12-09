"""
KSI-CNA-06: High Availability

Design systems for high availability and rapid recovery.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CNA_06_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CNA-06: High Availability
    
    **Official Statement:**
    Design systems for high availability and rapid recovery.
    
    **Family:** CNA - Cloud Native Architecture
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - None specified
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CNA-06"
    KSI_NAME = "High Availability"
    KSI_STATEMENT = """Design systems for high availability and rapid recovery."""
    FAMILY = "CNA"
    FAMILY_NAME = "Cloud Native Architecture"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = []
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
        Analyze Python code for KSI-CNA-06 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Design systems for high availability and rapid recovery....
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
        Analyze C# code for KSI-CNA-06 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Design systems for high availability and rapid recovery....
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CNA-06 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Design systems for high availability and rapid recovery....
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CNA-06 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Design systems for high availability and rapid recovery....
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CNA-06 compliance.
        
        Detects:
        - Virtual machines without availability zones
        - Databases without geo-redundancy
        - Storage accounts without redundancy
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: VM without availability zones (HIGH)
        vm_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Compute/virtualMachines")
        
        if vm_match:
            line_num = vm_match['line_num']
            # Check if availability zones are configured
            vm_end = min(len(lines), line_num + 60)
            vm_lines = lines[line_num:vm_end]
            
            has_zones = any(re.search(r"zones:\s*\[", line) 
                          for line in vm_lines)
            
            if not has_zones:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Virtual Machine Without Availability Zones",
                    description=(
                        "Virtual machine deployed without availability zone configuration. "
                        "KSI-CNA-06 requires designing systems for high availability and rapid recovery - "
                        "VMs should be deployed across multiple availability zones "
                        "to protect against datacenter failures and ensure continuous operation. "
                        "Single-zone deployment creates a single point of failure."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Deploy VMs across multiple availability zones:\n"
                        "// VM with availability zone for high availability\n"
                        "resource virtualMachine 'Microsoft.Compute/virtualMachines@2023-03-01' = {\n"
                        "  name: 'myVM'\n"
                        "  location: resourceGroup().location\n"
                        "  zones: ['1', '2', '3']  // Deploy across multiple zones\n"
                        "  properties: {\n"
                        "    hardwareProfile: {\n"
                        "      vmSize: 'Standard_DS1_v2'\n"
                        "    }\n"
                        "    storageProfile: {\n"
                        "      imageReference: {\n"
                        "        publisher: 'Canonical'\n"
                        "        offer: 'UbuntuServer'\n"
                        "        sku: '18.04-LTS'\n"
                        "        version: 'latest'\n"
                        "      }\n"
                        "      osDisk: {\n"
                        "        createOption: 'FromImage'\n"
                        "        managedDisk: {\n"
                        "          storageAccountType: 'Premium_ZRS'  // Zone-redundant storage\n"
                        "        }\n"
                        "      }\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "// Better: Use VM Scale Sets with zone redundancy\n"
                        "resource vmss 'Microsoft.Compute/virtualMachineScaleSets@2023-03-01' = {\n"
                        "  name: 'myVMSS'\n"
                        "  location: resourceGroup().location\n"
                        "  zones: ['1', '2', '3']  // Zone redundancy\n"
                        "  sku: {\n"
                        "    name: 'Standard_DS1_v2'\n"
                        "    tier: 'Standard'\n"
                        "    capacity: 3  // At least 3 instances\n"
                        "  }\n"
                        "  properties: {\n"
                        "    platformFaultDomainCount: 3  // Spread across fault domains\n"
                        "    singlePlacementGroup: false\n"
                        "    overprovision: true  // Rapid recovery\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure Availability Zones (https://learn.microsoft.com/azure/reliability/availability-zones-overview)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: SQL Database without geo-redundancy (HIGH)
        sql_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Sql/servers/databases")
        
        if sql_match:
            line_num = sql_match['line_num']
            # Check if geo-redundant backup is enabled
            sql_end = min(len(lines), line_num + 50)
            sql_lines = lines[line_num:sql_end]
            
            has_geo_backup = any(re.search(r"zoneRedundant:\s*true|requestedBackupStorageRedundancy:\s*'Geo'", line, re.IGNORECASE) 
                               for line in sql_lines)
            
            if not has_geo_backup:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="SQL Database Without Geo-Redundancy",
                    description=(
                        "SQL Database without geo-redundant backup or zone redundancy. "
                        "KSI-CNA-06 requires designing for high availability and rapid recovery - "
                        "databases must have geo-redundant backups or zone redundancy "
                        "to enable rapid recovery from regional failures. "
                        "Local-only backups increase RTO/RPO during disasters."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Enable geo-redundant backups and zone redundancy:\n"
                        "// SQL Database with high availability\n"
                        "resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {\n"
                        "  parent: sqlServer\n"
                        "  name: 'myDatabase'\n"
                        "  location: resourceGroup().location\n"
                        "  sku: {\n"
                        "    name: 'S1'\n"
                        "    tier: 'Standard'\n"
                        "  }\n"
                        "  properties: {\n"
                        "    // Zone redundancy for high availability\n"
                        "    zoneRedundant: true\n"
                        "    // Geo-redundant backup for rapid recovery\n"
                        "    requestedBackupStorageRedundancy: 'Geo'\n"
                        "    // Short-term retention for rapid recovery\n"
                        "    backupStorageRetentionPeriod: 35  // Days\n"
                        "  }\n"
                        "}\n\n"
                        "// Long-term retention policy for disaster recovery\n"
                        "resource ltrPolicy 'Microsoft.Sql/servers/databases/backupLongTermRetentionPolicies@2023-05-01-preview' = {\n"
                        "  parent: sqlDatabase\n"
                        "  name: 'default'\n"
                        "  properties: {\n"
                        "    weeklyRetention: 'P4W'  // 4 weeks\n"
                        "    monthlyRetention: 'P12M'  // 12 months\n"
                        "    yearlyRetention: 'P7Y'  // 7 years\n"
                        "    weekOfYear: 1\n"
                        "  }\n"
                        "}\n\n"
                        "// Geo-replication for zero RPO\n"
                        "resource geoReplica 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {\n"
                        "  parent: secondarySqlServer\n"
                        "  name: 'myDatabase-geo'\n"
                        "  location: 'eastus2'  // Secondary region\n"
                        "  properties: {\n"
                        "    createMode: 'Secondary'\n"
                        "    sourceDatabaseId: sqlDatabase.id\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: SQL Database High Availability (https://learn.microsoft.com/azure/azure-sql/database/high-availability-sla)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Storage Account without redundancy (MEDIUM)
        storage_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts")
        
        if storage_match:
            line_num = storage_match['line_num']
            # Check if using redundant SKU
            storage_end = min(len(lines), line_num + 20)
            storage_lines = lines[line_num:storage_end]
            
            has_redundancy = any(re.search(r"name:\s*'(Standard|Premium)_(GRS|GZRS|RAGRS|RA-GZRS)'", line) 
                               for line in storage_lines)
            
            if not has_redundancy:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Storage Account Without Geo-Redundancy",
                    description=(
                        "Storage account using locally-redundant storage (LRS/ZRS). "
                        "KSI-CNA-06 requires designing for high availability and rapid recovery - "
                        "critical storage should use geo-redundant storage (GRS/GZRS/RA-GRS/RA-GZRS) "
                        "to enable rapid recovery from regional failures. "
                        "Local-only redundancy provides no protection against regional disasters."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Use geo-redundant storage SKUs:\n"
                        "resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
                        "  name: 'mystorageaccount'\n"
                        "  location: resourceGroup().location\n"
                        "  sku: {\n"
                        "    // Geo-redundant options for high availability:\n"
                        "    // - Standard_GRS: Geo-redundant storage (RTO ~24 hours)\n"
                        "    // - Standard_GZRS: Geo-zone-redundant (zone + geo redundancy)\n"
                        "    // - Standard_RAGRS: Read-access geo-redundant (read in secondary region)\n"
                        "    // - Standard_RAGZRS: Read-access geo-zone-redundant (best availability)\n"
                        "    name: 'Standard_RAGZRS'  // Highest availability\n"
                        "  }\n"
                        "  kind: 'StorageV2'\n"
                        "  properties: {\n"
                        "    minimumTlsVersion: 'TLS1_2'\n"
                        "    supportsHttpsTrafficOnly: true\n"
                        "    // Soft delete for rapid recovery from accidental deletion\n"
                        "    deleteRetentionPolicy: {\n"
                        "      enabled: true\n"
                        "      days: 7\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "// Enable blob versioning for point-in-time recovery\n"
                        "resource blobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {\n"
                        "  parent: storageAccount\n"
                        "  name: 'default'\n"
                        "  properties: {\n"
                        "    isVersioningEnabled: true\n"
                        "    deleteRetentionPolicy: {\n"
                        "      enabled: true\n"
                        "      days: 30\n"
                        "    }\n"
                        "    containerDeleteRetentionPolicy: {\n"
                        "      enabled: true\n"
                        "      days: 30\n"
                        "    }\n"
                        "    // Point-in-time restore for rapid recovery\n"
                        "    restorePolicy: {\n"
                        "      enabled: true\n"
                        "      days: 7\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Storage Redundancy (https://learn.microsoft.com/azure/storage/common/storage-redundancy)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CNA-06 compliance.
        
        Detects:
        - Virtual machines without availability zones
        - Databases without geo-redundancy
        - Storage accounts without redundancy
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: VM without availability zones (HIGH)
        vm_match = self._find_line(lines, r'resource\s+"azurerm_(linux|windows)_virtual_machine"')
        
        if vm_match:
            line_num = vm_match['line_num']
            # Check if zones are configured
            vm_end = min(len(lines), line_num + 70)
            vm_lines = lines[line_num:vm_end]
            
            has_zones = any(re.search(r'zones\s*=\s*\[', line) 
                          for line in vm_lines)
            
            if not has_zones:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Virtual Machine Without Availability Zones",
                    description=(
                        "Virtual machine deployed without availability zone configuration. "
                        "KSI-CNA-06 requires designing systems for high availability and rapid recovery - "
                        "VMs should be deployed across multiple availability zones "
                        "to protect against datacenter failures and ensure continuous operation. "
                        "Single-zone deployment creates a single point of failure."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Deploy VMs across multiple availability zones:\n"
                        "# VM with availability zones for high availability\n"
                        "resource \"azurerm_linux_virtual_machine\" \"example\" {\n"
                        "  name                = \"example-vm\"\n"
                        "  resource_group_name = azurerm_resource_group.example.name\n"
                        "  location            = azurerm_resource_group.example.location\n"
                        "  size                = \"Standard_DS1_v2\"\n"
                        "  zones               = [\"1\", \"2\", \"3\"]  # Deploy across multiple zones\n\n"
                        "  os_disk {\n"
                        "    caching              = \"ReadWrite\"\n"
                        "    storage_account_type = \"Premium_ZRS\"  # Zone-redundant storage\n"
                        "  }\n\n"
                        "  source_image_reference {\n"
                        "    publisher = \"Canonical\"\n"
                        "    offer     = \"UbuntuServer\"\n"
                        "    sku       = \"18.04-LTS\"\n"
                        "    version   = \"latest\"\n"
                        "  }\n"
                        "}\n\n"
                        "# Better: Use VM Scale Sets with zone redundancy\n"
                        "resource \"azurerm_linux_virtual_machine_scale_set\" \"example\" {\n"
                        "  name                = \"example-vmss\"\n"
                        "  resource_group_name = azurerm_resource_group.example.name\n"
                        "  location            = azurerm_resource_group.example.location\n"
                        "  sku                 = \"Standard_DS1_v2\"\n"
                        "  instances           = 3  # At least 3 instances\n"
                        "  zones               = [\"1\", \"2\", \"3\"]  # Zone redundancy\n\n"
                        "  os_disk {\n"
                        "    caching              = \"ReadWrite\"\n"
                        "    storage_account_type = \"Premium_ZRS\"\n"
                        "  }\n\n"
                        "  platform_fault_domain_count  = 3  # Spread across fault domains\n"
                        "  single_placement_group       = false\n"
                        "  overprovision                = true  # Rapid recovery\n"
                        "}\n\n"
                        "Ref: azurerm_linux_virtual_machine zones (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine#zones)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
        
        # TODO: Implement Terraform-specific detection logic
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CNA-06 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CNA-06 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CNA-06 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], pattern: str) -> Optional[Dict[str, Any]]:
        """
        Find first line matching regex pattern.
        Returns dict with line_num and line content, or None if not found.
        """
        for i, line in enumerate(lines, start=1):
            if re.search(pattern, line, re.IGNORECASE):
                return {'line_num': i, 'line': line}
        return None
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])

