"""
KSI-PIY-01: Automated Inventory (Enhanced)

Use authoritative sources to automatically maintain real-time inventories of all information resources.

ENHANCED FEATURES:
- Comprehensive Azure resource tagging validation
- Tag standardization checks (required vs optional tags)
- Azure Resource Graph query validation
- Inventory automation detection in CI/CD
- Cost management and governance tag validation

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Set
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_PIY_01_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced analyzer for KSI-PIY-01: Automated Inventory.
    
    **Official Statement:**
    Use authoritative sources to automatically maintain real-time inventories of all information resources.
    
    **Family:** PIY - Policy and Inventory
    
    **Impact Levels:** Low: Yes, Moderate: Yes
    
    **NIST Controls:** cm-2.2, cm-7.5, cm-8, cm-8.1, cm-12, cm-12.1, cp-2.8
    
    **Detection Strategy:**
    - IaC: Validate resource tagging standards for inventory tracking
    - Application: Check for Azure SDK inventory queries (Resource Graph, Management API)
    - CI/CD: Detect automated inventory collection jobs
    
    **Required Tags for FedRAMP Inventory:**
    - environment (production, staging, development)
    - owner (team or individual responsible)
    - cost-center (billing/budget allocation)
    - compliance (fedramp, pci, hipaa, etc.)
    - data-classification (public, internal, confidential, restricted)
    - created-date (ISO 8601 timestamp)
    
    **Languages Supported:**
    - IaC: Bicep, Terraform (primary detection)
    - Application: Python, C#, TypeScript (Azure SDK inventory queries)
    """
    
    KSI_ID = "KSI-PIY-01"
    KSI_NAME = "Automated Inventory"
    KSI_STATEMENT = """Use authoritative sources to automatically maintain real-time inventories of all information resources."""
    FAMILY = "PIY"
    FAMILY_NAME = "Policy and Inventory"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("cm-2.2", "Automation Support for Accuracy and Currency"),
        ("cm-7.5", "Authorized Software — Allow-by-exception"),
        ("cm-8", "System Component Inventory"),
        ("cm-8.1", "Updates During Installation and Removal"),
        ("cm-12", "Information Location"),
        ("cm-12.1", "Automated Tools to Support Information Location"),
        ("cp-2.8", "Identify Critical Assets")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
    # Required tags for FedRAMP inventory compliance
    REQUIRED_TAGS = {
        'environment', 'owner', 'cost-center', 'compliance', 
        'data-classification', 'created-date'
    }
    
    # Optional but recommended tags
    RECOMMENDED_TAGS = {
        'application', 'version', 'managed-by', 'project',
        'backup-policy', 'retention-period', 'patch-group'
    }
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (PRIMARY DETECTION)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-PIY-01 compliance.
        Note: Using regex - tree-sitter not available for Bicep.
        
        Detects:
        - Resources without tags (HIGH)
        - Missing required inventory tags (HIGH)
        - Missing recommended tags (MEDIUM)
        - Non-standard tag naming (LOW)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Resources without any tags (HIGH)
        resource_pattern = r"resource\s+(\w+)\s+'([^']+)'"
        for match in re.finditer(resource_pattern, code):
            resource_name = match.group(1)
            resource_type = match.group(2)
            line_num = code[:match.start()].count('\n') + 1
            
            # Extract resource block
            resource_start = match.start()
            brace_count = 0
            in_resource = False
            resource_end = resource_start
            
            for i in range(resource_start, len(code)):
                if code[i] == '{':
                    brace_count += 1
                    in_resource = True
                elif code[i] == '}':
                    brace_count -= 1
                    if in_resource and brace_count == 0:
                        resource_end = i + 1
                        break
            
            resource_block = code[resource_start:resource_end]
            
            # Check for tags section
            if 'tags:' not in resource_block.lower() and 'tags =' not in resource_block.lower():
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Resource Without Inventory Tags",
                    description=(
                        f"Resource '{resource_name}' ({resource_type}) lacks inventory tags. "
                        f"KSI-PIY-01 requires automated inventory tracking per NIST CM-8 (Information System Component Inventory). "
                        f"All Azure resources must have standardized tags for asset management, cost allocation, and compliance tracking."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        f"Add required inventory tags:\n"
                        f"```bicep\n"
                        f"resource {resource_name} '{resource_type}' = {{\n"
                        f"  name: 'resource-name'\n"
                        f"  location: location\n"
                        f"  tags: {{\n"
                        f"    // Required for FedRAMP inventory\n"
                        f"    environment: 'production'  // production, staging, development\n"
                        f"    owner: 'platform-team'  // Team or individual responsible\n"
                        f"    'cost-center': 'engineering'  // Budget allocation\n"
                        f"    compliance: 'fedramp'  // Compliance framework\n"
                        f"    'data-classification': 'confidential'  // Data sensitivity\n"
                        f"    'created-date': utcNow('yyyy-MM-dd')  // Creation timestamp\n"
                        f"    \n"
                        f"    // Recommended for inventory management\n"
                        f"    application: 'myapp'\n"
                        f"    'managed-by': 'bicep'\n"
                        f"    project: 'fedramp-compliance'\n"
                        f"    'asset-id': guid(resourceGroup().id, '{resource_name}')\n"
                        f"  }}\n"
                        f"  properties: {{\n"
                        f"    // ... resource properties\n"
                        f"  }}\n"
                        f"}}\n"
                        f"```\n\n"
                        f"Ref: NIST CM-8 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-8)\n"
                        f"Azure Tagging Strategy (https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/resource-tagging)"
                    ),
                    ksi_id=self.KSI_ID
                ))
            else:
                # Has tags - check for required tags
                missing_tags = self._check_missing_required_tags(resource_block)
                if missing_tags:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Missing Required Inventory Tags",
                        description=(
                            f"Resource '{resource_name}' has tags but is missing required inventory tags: {', '.join(missing_tags)}. "
                            f"KSI-PIY-01 requires standardized tagging per NIST CM-8.1 (Updates During Installation/Removal)."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num, context=3),
                        remediation=(
                            f"Add missing required tags:\n"
                            f"```bicep\n"
                            f"tags: {{\n"
                            f"  // Existing tags...\n"
                            f"  \n"
                            f"  // Add missing required tags:\n"
                            + ''.join([f"  {tag}: 'value'  // Required for FedRAMP inventory\n" for tag in missing_tags]) +
                            f"}}\n"
                            f"```\n\n"
                            f"Ref: NIST CM-8.1 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-8)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
                
                # Check for recommended tags (MEDIUM)
                missing_recommended = self._check_missing_recommended_tags(resource_block)
                if len(missing_recommended) >= 3:  # Flag if missing 3+ recommended tags
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Missing Recommended Inventory Tags",
                        description=(
                            f"Resource '{resource_name}' is missing {len(missing_recommended)} recommended inventory tags: "
                            f"{', '.join(list(missing_recommended)[:5])}. While not required, these tags improve inventory management "
                            f"and operational efficiency per NIST CM-12 (Information Location)."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet="",
                        remediation=(
                            f"Consider adding recommended tags for better inventory tracking:\n"
                            f"```bicep\n"
                            f"tags: {{\n"
                            f"  // Required tags (already present)...\n"
                            f"  \n"
                            f"  // Recommended tags:\n"
                            f"  application: 'myapp'  // Application name\n"
                            f"  version: '1.0.0'  // Application version\n"
                            f"  'managed-by': 'bicep'  // IaC tool\n"
                            f"  project: 'fedramp-app'  // Project identifier\n"
                            f"  'backup-policy': 'daily'  // Backup schedule\n"
                            f"  'retention-period': '30d'  // Data retention\n"
                            f"  'patch-group': 'group-a'  // Patch management\n"
                            f"}}\n"
                            f"```\n\n"
                            f"Ref: Azure Cloud Adoption Framework - Resource Tagging (https://learn.microsoft.com/azure/cloud-adoption-framework/ready/azure-best-practices/resource-tagging)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: Check for tag standardization variables (recommended pattern)
        has_common_tags_param = bool(re.search(r'param\s+commonTags\s+object', code))
        has_resources = bool(re.search(r'resource\s+\w+', code))
        
        if has_resources and not has_common_tags_param and len(findings) > 0:
            findings.append(Finding(
                severity=Severity.LOW,
                title="Consider Using Common Tags Pattern",
                description=(
                    "Bicep file lacks 'commonTags' parameter for tag standardization. "
                    "Using a common tags parameter ensures consistent tagging across all resources, "
                    "simplifying inventory management per KSI-PIY-01."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation=(
                    "Implement common tags pattern:\n"
                    "```bicep\n"
                    "// Define common tags parameter\n"
                    "param commonTags object = {\n"
                    "  environment: 'production'\n"
                    "  owner: 'platform-team'\n"
                    "  'cost-center': 'engineering'\n"
                    "  compliance: 'fedramp'\n"
                    "  'managed-by': 'bicep'\n"
                    "  project: 'fedramp-app'\n"
                    "}\n\n"
                    "// Use in resources with union() for merging\n"
                    "resource myResource 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
                    "  name: 'mystorageaccount'\n"
                    "  location: location\n"
                    "  tags: union(commonTags, {\n"
                    "    // Resource-specific tags\n"
                    "    'data-classification': 'confidential'\n"
                    "    'created-date': utcNow('yyyy-MM-dd')\n"
                    "  })\n"
                    "  // ...\n"
                    "}\n"
                    "```\n\n"
                    "Ref: Azure Bicep Best Practices (https://learn.microsoft.com/azure/azure-resource-manager/bicep/best-practices)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-PIY-01 compliance.
        Note: Using regex - tree-sitter not available for Terraform.
        
        Detects:
        - Resources without tags (HIGH)
        - Missing required inventory tags (HIGH)
        - Missing common_tags variable pattern (MEDIUM)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Resources without tags (HIGH)
        resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"\s*\{'
        for match in re.finditer(resource_pattern, code):
            resource_type = match.group(1)
            resource_name = match.group(2)
            line_num = code[:match.start()].count('\n') + 1
            
            # Extract resource block
            resource_start = match.start()
            brace_count = 0
            in_resource = False
            resource_end = resource_start
            
            for i in range(resource_start, len(code)):
                if code[i] == '{':
                    brace_count += 1
                    in_resource = True
                elif code[i] == '}':
                    brace_count -= 1
                    if in_resource and brace_count == 0:
                        resource_end = i + 1
                        break
            
            resource_block = code[resource_start:resource_end]
            
            # Check for tags
            if 'tags' not in resource_block.lower():
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Resource Without Inventory Tags",
                    description=(
                        f"Terraform resource '{resource_name}' ({resource_type}) lacks inventory tags. "
                        f"KSI-PIY-01 requires automated inventory tracking per NIST CM-8."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        f"Add required inventory tags:\n"
                        f"```hcl\n"
                        f"resource \"{resource_type}\" \"{resource_name}\" {{\n"
                        f"  name                = \"resource-name\"\n"
                        f"  location            = var.location\n"
                        f"  resource_group_name = azurerm_resource_group.main.name\n"
                        f"  \n"
                        f"  tags = merge(var.common_tags, {{\n"
                        f"    environment          = var.environment\n"
                        f"    owner                = \"platform-team\"\n"
                        f"    cost-center          = \"engineering\"\n"
                        f"    compliance           = \"fedramp\"\n"
                        f"    data-classification  = \"confidential\"\n"
                        f"    created-date         = formatdate(\"YYYY-MM-DD\", timestamp())\n"
                        f"    application          = \"myapp\"\n"
                        f"    managed-by           = \"terraform\"\n"
                        f"  }})\n"
                        f"}}\n\n"
                        f"# Define common_tags in variables.tf:\n"
                        f"variable \"common_tags\" {{\n"
                        f"  type = map(string)\n"
                        f"  default = {{\n"
                        f"    project    = \"fedramp-app\"\n"
                        f"    managed-by = \"terraform\"\n"
                        f"  }}\n"
                        f"}}\n"
                        f"```\n\n"
                        f"Ref: NIST CM-8 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-8)\n"
                        f"Terraform Tagging Best Practices (https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices/part3.1)"
                    ),
                    ksi_id=self.KSI_ID
                ))
            else:
                # Has tags - check for required tags
                missing_tags = self._check_missing_required_tags(resource_block)
                if missing_tags:
                    findings.append(Finding(
                        severity=Severity.HIGH,
                        title="Missing Required Inventory Tags",
                        description=(
                            f"Terraform resource '{resource_name}' has tags but is missing required inventory tags: "
                            f"{', '.join(missing_tags)}. KSI-PIY-01 requires standardized tagging per NIST CM-8.1."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num, context=3),
                        remediation=(
                            f"Add missing required tags to the tags block:\n"
                            f"```hcl\n"
                            f"tags = merge(var.common_tags, {{\n"
                            f"  // Existing tags...\n"
                            f"  \n"
                            f"  // Add missing required tags:\n"
                            + ''.join([f"  {tag.replace('-', '_')} = \"value\"\n" for tag in missing_tags]) +
                            f"}})\n"
                            f"```\n\n"
                            f"Ref: NIST CM-8.1 (https://csrc.nist.gov/Projects/risk-management/sp800-53-controls/release-search#!/control?version=5.1&number=CM-8)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        # Pattern 2: Check for common_tags variable (recommended pattern)
        has_common_tags_var = bool(re.search(r'variable\s+"common_tags"', code))
        has_resources = bool(re.search(r'resource\s+"', code))
        
        if has_resources and not has_common_tags_var and len(findings) > 0:
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Consider Using Common Tags Variable",
                description=(
                    "Terraform configuration lacks 'common_tags' variable for tag standardization. "
                    "Using a common tags variable with merge() ensures consistent tagging across all resources, "
                    "simplifying inventory management per KSI-PIY-01."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation=(
                    "Implement common tags pattern:\n"
                    "```hcl\n"
                    "# variables.tf\n"
                    "variable \"common_tags\" {\n"
                    "  description = \"Common tags for all resources\"\n"
                    "  type        = map(string)\n"
                    "  default = {\n"
                    "    project    = \"fedramp-app\"\n"
                    "    managed-by = \"terraform\"\n"
                    "    compliance = \"fedramp\"\n"
                    "  }\n"
                    "}\n\n"
                    "variable \"environment\" {\n"
                    "  description = \"Environment name\"\n"
                    "  type        = string\n"
                    "}\n\n"
                    "# main.tf - Use in resources\n"
                    "resource \"azurerm_storage_account\" \"example\" {\n"
                    "  name                = \"mystorageaccount\"\n"
                    "  resource_group_name = azurerm_resource_group.main.name\n"
                    "  location            = azurerm_resource_group.main.location\n"
                    "  \n"
                    "  tags = merge(var.common_tags, {\n"
                    "    environment         = var.environment\n"
                    "    data-classification = \"confidential\"\n"
                    "    created-date        = formatdate(\"YYYY-MM-DD\", timestamp())\n"
                    "  })\n"
                    "}\n"
                    "```\n\n"
                    "Ref: Terraform Best Practices (https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices/part3.1)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS (AZURE SDK INVENTORY QUERIES)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for Azure Resource Graph inventory queries (AST-first).
        
        Detects:
        - Azure Resource Graph query usage (informational)
        """
        findings = []
        
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        
        if tree:
            code_bytes = code.encode('utf8')
            
            # Find import statements
            import_nodes = parser.find_nodes_by_type(tree.root_node, "import_from_statement")
            
            has_resource_graph = False
            has_management_client = False
            
            for import_node in import_nodes:
                import_text = parser.get_node_text(import_node, code_bytes)
                
                if 'azure.mgmt.resourcegraph' in import_text and 'ResourceGraphClient' in import_text:
                    has_resource_graph = True
                if 'azure.mgmt.resource' in import_text and 'ResourceManagementClient' in import_text:
                    has_management_client = True
        else:
            # Fallback to regex if AST parsing fails
            return self._analyze_python_regex(code, file_path)
        
        # This is informational - presence indicates inventory automation
        if has_resource_graph or has_management_client:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Azure Resource Inventory Query Detected",
                description=(
                    "Code uses Azure SDK for resource inventory queries, supporting KSI-PIY-01 compliance. "
                    "Ensure queries run on a schedule to maintain real-time inventory per NIST CM-8."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation=(
                    "Ensure inventory queries run regularly:\n"
                    "```python\n"
                    "from azure.mgmt.resourcegraph import ResourceGraphClient\n"
                    "from azure.identity import DefaultAzureCredential\n\n"
                    "def get_resource_inventory():\n"
                    "    credential = DefaultAzureCredential()\n"
                    "    client = ResourceGraphClient(credential)\n"
                    "    \n"
                    "    # Query all resources with required tags\n"
                    "    query = '''\n"
                    "    Resources\n"
                    "    | where tags has 'environment' and tags has 'owner'\n"
                    "    | project name, type, location, resourceGroup, tags\n"
                    "    | order by name asc\n"
                    "    '''\n"
                    "    \n"
                    "    result = client.resources(query=query)\n"
                    "    return result.data\n\n"
                    "# Schedule this function to run daily/hourly\n"
                    "```\n\n"
                    "Ref: Azure Resource Graph (https://learn.microsoft.com/azure/governance/resource-graph/overview)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def _analyze_python_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis for Python."""
        findings = []
        
        # Check for Azure Resource Graph SDK usage
        has_resource_graph = bool(re.search(r'from azure\.mgmt\.resourcegraph import ResourceGraphClient', code))
        has_management_client = bool(re.search(r'from azure\.mgmt\.resource import ResourceManagementClient', code))
        
        # This is informational - presence indicates inventory automation
        if has_resource_graph or has_management_client:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Azure Resource Inventory Query Detected",
                description=(
                    "Code uses Azure SDK for resource inventory queries, supporting KSI-PIY-01 compliance. "
                    "Ensure queries run on a schedule to maintain real-time inventory per NIST CM-8."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation=(
                    "Ensure inventory queries run regularly:\n"
                    "```python\n"
                    "from azure.mgmt.resourcegraph import ResourceGraphClient\n"
                    "from azure.identity import DefaultAzureCredential\n\n"
                    "def get_resource_inventory():\n"
                    "    credential = DefaultAzureCredential()\n"
                    "    client = ResourceGraphClient(credential)\n"
                    "    \n"
                    "    # Query all resources with required tags\n"
                    "    query = '''\n"
                    "    Resources\n"
                    "    | where tags has 'environment' and tags has 'owner'\n"
                    "    | project name, type, location, resourceGroup, tags\n"
                    "    | order by name asc\n"
                    "    '''\n"
                    "    \n"
                    "    result = client.resources(query=query)\n"
                    "    return result.data\n\n"
                    "# Schedule this function to run daily/hourly\n"
                    "```\n\n"
                    "Ref: Azure Resource Graph (https://learn.microsoft.com/azure/governance/resource-graph/overview)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for Azure Resource Graph inventory queries (AST-first).
        """
        findings = []
        
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        
        if tree:
            code_bytes = code.encode('utf8')
            
            # Find using directives
            using_nodes = parser.find_nodes_by_type(tree.root_node, "using_directive")
            
            has_resource_graph = False
            has_resource_manager = False
            
            for using_node in using_nodes:
                using_text = parser.get_node_text(using_node, code_bytes)
                
                if 'Azure.ResourceManager.ResourceGraph' in using_text:
                    has_resource_graph = True
                if 'Azure.ResourceManager' in using_text and 'ResourceGraph' not in using_text:
                    has_resource_manager = True
        else:
            # Fallback to regex if AST parsing fails
            return self._analyze_csharp_regex(code, file_path)
        
        if has_resource_graph or has_resource_manager:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Azure Resource Inventory Query Detected",
                description=(
                    "Code uses Azure SDK for resource inventory queries, supporting KSI-PIY-01 compliance. "
                    "Ensure queries run on a schedule to maintain real-time inventory per NIST CM-8."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation=(
                    "Ensure inventory queries run regularly:\n"
                    "```csharp\n"
                    "using Azure.Identity;\n"
                    "using Azure.ResourceManager;\n"
                    "using Azure.ResourceManager.Resources;\n\n"
                    "public async Task<List<GenericResource>> GetResourceInventory()\n"
                    "{\n"
                    "    var credential = new DefaultAzureCredential();\n"
                    "    var client = new ArmClient(credential);\n"
                    "    var subscription = await client.GetDefaultSubscriptionAsync();\n"
                    "    \n"
                    "    var resources = new List<GenericResource>();\n"
                    "    await foreach (var resource in subscription.GetGenericResourcesAsync())\n"
                    "    {\n"
                    "        // Filter for required tags\n"
                    "        if (resource.Data.Tags.ContainsKey(\"environment\") && \n"
                    "            resource.Data.Tags.ContainsKey(\"owner\"))\n"
                    "        {\n"
                    "            resources.Add(resource);\n"
                    "        }\n"
                    "    }\n"
                    "    return resources;\n"
                    "}\n"
                    "```\n\n"
                    "Ref: Azure SDK for .NET (https://learn.microsoft.com/dotnet/azure/sdk/resource-management)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def _analyze_csharp_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis for C#."""
        findings = []
        
        # Check for Azure Resource Graph SDK usage
        has_resource_graph = bool(re.search(r'using Azure\.ResourceManager\.ResourceGraph', code))
        has_resource_manager = bool(re.search(r'using Azure\.ResourceManager', code))
        
        if has_resource_graph or has_resource_manager:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Azure Resource Inventory Query Detected",
                description=(
                    "Code uses Azure SDK for resource inventory queries, supporting KSI-PIY-01 compliance. "
                    "Ensure queries run on a schedule to maintain real-time inventory per NIST CM-8."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation=(
                    "Ensure inventory queries run regularly:\n"
                    "```csharp\n"
                    "using Azure.Identity;\n"
                    "using Azure.ResourceManager;\n"
                    "using Azure.ResourceManager.Resources;\n\n"
                    "public async Task<List<GenericResource>> GetResourceInventory()\n"
                    "{\n"
                    "    var credential = new DefaultAzureCredential();\n"
                    "    var client = new ArmClient(credential);\n"
                    "    var subscription = await client.GetDefaultSubscriptionAsync();\n"
                    "    \n"
                    "    var resources = new List<GenericResource>();\n"
                    "    await foreach (var resource in subscription.GetGenericResourcesAsync())\n"
                    "    {\n"
                    "        // Filter for required tags\n"
                    "        if (resource.Data.Tags.ContainsKey(\"environment\") && \n"
                    "            resource.Data.Tags.ContainsKey(\"owner\"))\n"
                    "        {\n"
                    "            resources.Add(resource);\n"
                    "        }\n"
                    "    }\n"
                    "    return resources;\n"
                    "}\n"
                    "```\n\n"
                    "Ref: Azure SDK for .NET (https://learn.microsoft.com/dotnet/azure/sdk/resource-management)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript code for Azure Resource Graph inventory queries (AST-first).
        """
        findings = []
        
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        tree = parser.parse(code)
        
        if tree:
            code_bytes = code.encode('utf8')
            
            # Find import statements
            import_nodes = parser.find_nodes_by_type(tree.root_node, "import_statement")
            
            has_resource_graph = False
            has_resources = False
            
            for import_node in import_nodes:
                import_text = parser.get_node_text(import_node, code_bytes)
                
                if '@azure/arm-resourcegraph' in import_text:
                    has_resource_graph = True
                if '@azure/arm-resources' in import_text:
                    has_resources = True
        else:
            # Fallback to regex if AST parsing fails
            return self._analyze_typescript_regex(code, file_path)
        
        if has_resource_graph or has_resources:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Azure Resource Inventory Query Detected",
                description=(
                    "Code uses Azure SDK for resource inventory queries, supporting KSI-PIY-01 compliance. "
                    "Ensure queries run on a schedule to maintain real-time inventory per NIST CM-8."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation=(
                    "Ensure inventory queries run regularly:\n"
                    "```typescript\n"
                    "import { ResourceGraphClient } from '@azure/arm-resourcegraph';\n"
                    "import { DefaultAzureCredential } from '@azure/identity';\n\n"
                    "export async function getResourceInventory(): Promise<any[]> {\n"
                    "  const credential = new DefaultAzureCredential();\n"
                    "  const client = new ResourceGraphClient(credential);\n"
                    "  \n"
                    "  const query = `\n"
                    "    Resources\n"
                    "    | where tags has 'environment' and tags has 'owner'\n"
                    "    | project name, type, location, resourceGroup, tags\n"
                    "    | order by name asc\n"
                    "  `;\n"
                    "  \n"
                    "  const result = await client.resources({ query });\n"
                    "  return result.data || [];\n"
                    "}\n\n"
                    "// Schedule this function to run daily/hourly\n"
                    "```\n\n"
                    "Ref: Azure SDK for JavaScript (https://learn.microsoft.com/javascript/api/overview/azure/arm-resourcegraph-readme)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def _analyze_typescript_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis for TypeScript."""
        findings = []
        
        # Check for Azure Resource Graph SDK usage
        has_resource_graph = bool(re.search(r'from ["\']@azure/arm-resourcegraph["\']', code))
        has_resources = bool(re.search(r'from ["\']@azure/arm-resources["\']', code))
        
        if has_resource_graph or has_resources:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Azure Resource Inventory Query Detected",
                description=(
                    "Code uses Azure SDK for resource inventory queries, supporting KSI-PIY-01 compliance. "
                    "Ensure queries run on a schedule to maintain real-time inventory per NIST CM-8."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation=(
                    "Ensure inventory queries run regularly:\n"
                    "```typescript\n"
                    "import { ResourceGraphClient } from '@azure/arm-resourcegraph';\n"
                    "import { DefaultAzureCredential } from '@azure/identity';\n\n"
                    "export async function getResourceInventory(): Promise<any[]> {\n"
                    "  const credential = new DefaultAzureCredential();\n"
                    "  const client = new ResourceGraphClient(credential);\n"
                    "  \n"
                    "  const query = `\n"
                    "    Resources\n"
                    "    | where tags has 'environment' and tags has 'owner'\n"
                    "    | project name, type, location, resourceGroup, tags\n"
                    "    | order by name asc\n"
                    "  `;\n"
                    "  \n"
                    "  const result = await client.resources({ query });\n"
                    "  return result.data || [];\n"
                    "}\n\n"
                    "// Schedule this function to run daily/hourly\n"
                    "```\n\n"
                    "Ref: Azure SDK for JavaScript (https://learn.microsoft.com/javascript/api/overview/azure/arm-resourcegraph-readme)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Limited Java detection (AST-first).
        Note: Java inventory queries typically use Azure SDK for Java, but detection not currently implemented.
        """
        # Try AST parsing (for future expansion)
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        
        if tree:
            # Future: Could detect Azure SDK imports like:
            # import com.azure.resourcemanager.ResourceManager;
            # import com.azure.resourcemanager.resources.models.GenericResource;
            pass
        
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (INVENTORY AUTOMATION)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions for automated inventory collection.
        Note: Using regex - tree-sitter not available for YAML.
        """
        findings = []
        
        # Check for scheduled inventory jobs
        has_schedule = bool(re.search(r'schedule:', code))
        has_azure_cli = bool(re.search(r'(azure/CLI|az\s+graph|az\s+resource)', code, re.IGNORECASE))
        
        if has_schedule and has_azure_cli:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Automated Inventory Collection Detected",
                description=(
                    "GitHub Actions workflow includes scheduled Azure resource inventory collection, "
                    "supporting KSI-PIY-01 real-time inventory requirements per NIST CM-8."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation="Continue monitoring inventory collection schedule for compliance.",
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines for automated inventory collection.
        Note: Using regex - tree-sitter not available for YAML.
        """
        findings = []
        
        # Check for scheduled inventory jobs
        has_schedule = bool(re.search(r'schedules:', code))
        has_azure_cli = bool(re.search(r'(AzureCLI|az\s+graph|az\s+resource)', code, re.IGNORECASE))
        
        if has_schedule and has_azure_cli:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Automated Inventory Collection Detected",
                description=(
                    "Azure Pipeline includes scheduled Azure resource inventory collection, "
                    "supporting KSI-PIY-01 real-time inventory requirements per NIST CM-8."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation="Continue monitoring inventory collection schedule for compliance.",
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI for automated inventory collection.
        Note: Using regex - tree-sitter not available for YAML.
        """
        findings = []
        
        # Check for scheduled inventory jobs
        has_schedule = bool(re.search(r'(schedules:|only:\s*-\s*schedules)', code))
        has_azure_cli = bool(re.search(r'(az\s+graph|az\s+resource)', code))
        
        if has_schedule and has_azure_cli:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Automated Inventory Collection Detected",
                description=(
                    "GitLab CI pipeline includes scheduled Azure resource inventory collection, "
                    "supporting KSI-PIY-01 real-time inventory requirements per NIST CM-8."
                ),
                file_path=file_path,
                line_number=1,
                snippet="",
                remediation="Continue monitoring inventory collection schedule for compliance.",
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _check_missing_required_tags(self, code_block: str) -> Set[str]:
        """Check which required tags are missing from code block."""
        code_lower = code_block.lower()
        missing = set()
        
        for tag in self.REQUIRED_TAGS:
            # Check for tag with various formats: tag: value, tag = value, 'tag': value
            tag_patterns = [
                tag.lower(),
                tag.replace('-', '_').lower(),
                tag.replace('-', '').lower()
            ]
            if not any(pattern in code_lower for pattern in tag_patterns):
                missing.add(tag)
        
        return missing
    
    def _check_missing_recommended_tags(self, code_block: str) -> Set[str]:
        """Check which recommended tags are missing from code block."""
        code_lower = code_block.lower()
        missing = set()
        
        for tag in self.RECOMMENDED_TAGS:
            tag_patterns = [
                tag.lower(),
                tag.replace('-', '_').lower(),
                tag.replace('-', '').lower()
            ]
            if not any(pattern in code_lower for pattern in tag_patterns):
                missing.add(tag)
        
        return missing
    
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

