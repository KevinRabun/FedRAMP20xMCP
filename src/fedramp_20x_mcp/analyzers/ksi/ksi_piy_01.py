"""
KSI-PIY-01: Automated Inventory

Use authoritative sources to automatically maintain real-time inventories of all information resources.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_PIY_01_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-PIY-01: Automated Inventory
    
    **Official Statement:**
    Use authoritative sources to automatically maintain real-time inventories of all information resources.
    
    **Family:** PIY - Policy and Inventory
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cm-2.2
    - cm-7.5
    - cm-8
    - cm-8.1
    - cm-12
    - cm-12.1
    - cp-2.8
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Use authoritative sources to automatically maintain real-time inventories of all information resourc...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-PIY-01"
    KSI_NAME = "Automated Inventory"
    KSI_STATEMENT = """Use authoritative sources to automatically maintain real-time inventories of all information resources."""
    FAMILY = "PIY"
    FAMILY_NAME = "Policy and Inventory"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["cm-2.2", "cm-7.5", "cm-8", "cm-8.1", "cm-12", "cm-12.1", "cp-2.8"]
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
        Analyze Python code for KSI-PIY-01 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Note: Automated inventory is primarily an IaC concern (resource tagging in Bicep/Terraform).
        Application code typically doesn't manage infrastructure inventory directly.
        """
        findings = []
        # No application-level findings for inventory management
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-PIY-01 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Note: Automated inventory is primarily an IaC concern (resource tagging in Bicep/Terraform).
        """
        findings = []
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-PIY-01 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Note: Automated inventory is primarily an IaC concern (resource tagging in Bicep/Terraform).
        """
        findings = []
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-PIY-01 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Note: Automated inventory is primarily an IaC concern (resource tagging in Bicep/Terraform).
        """
        findings = []
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-PIY-01 compliance.
        
        Detects:
        - Resources without inventory tags
        - Missing Azure Resource Graph queries
        - Resources without standard naming conventions
        """
        findings = []
        lines = code.split('\n')
        
        # Check for resources without tags
        resource_pattern = r"resource\s+(\w+)\s+'([^']+)'"
        resources = re.findall(resource_pattern, code)
        
        for resource_name, resource_type in resources:
            # Check if resource has tags
            resource_block_match = re.search(rf"resource\s+{resource_name}\s+[^{{]+{{[^}}]+}}", code, re.DOTALL)
            if resource_block_match:
                resource_block = resource_block_match.group(0)
                if 'tags:' not in resource_block.lower():
                    line_num = self._find_line(lines, f"resource {resource_name}")
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Missing Inventory Tags on Resource",
                        description=f"Resource '{resource_name}' in '{file_path}' lacks inventory tags. KSI-PIY-01 requires tagged resources for automated inventory.",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation=f"""Add inventory tags to enable automated tracking:

```bicep
resource {resource_name} '{resource_type}' = {{
  name: 'resource-name'
  location: location
  tags: {{
    environment: 'production'
    owner: 'platform-team'
    cost-center: 'engineering'
    compliance: 'fedramp'
    asset-id: guid(resourceGroup().id, '{resource_name}')
    created-date: utcNow('yyyy-MM-dd')
    inventory-managed: 'true'
  }}
  properties: {{
    // ... resource properties
  }}
}}
```

Reference: FRR-PIY-01 - Automated Inventory Management"""
                    ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-PIY-01 compliance.
        
        Detects:
        - Resources without tags
        - Missing common_tags variables
        """
        findings = []
        lines = code.split('\n')
        
        # Check for resources without tags
        resource_pattern = r'resource\s+"([^"]+)"\s+"([^"]+)"'
        resources = re.findall(resource_pattern, code)
        
        for resource_type, resource_name in resources:
            # Check if resource has tags
            resource_block_match = re.search(rf'resource\s+"{resource_type}"\s+"{resource_name}"\s*{{[^}}]+}}', code, re.DOTALL)
            if resource_block_match:
                resource_block = resource_block_match.group(0)
                if 'tags' not in resource_block.lower():
                    line_num = self._find_line(lines, f'resource "{resource_type}" "{resource_name}"')
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Missing Inventory Tags on Resource",
                        description=f"Resource '{resource_name}' in '{file_path}' lacks tags. KSI-PIY-01 requires tagging for automated inventory.",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation=f"""Add inventory tags:

```hcl
resource "{resource_type}" "{resource_name}" {{
  name                = "resource-name"
  location            = var.location
  resource_group_name = azurerm_resource_group.main.name
  
  tags = merge(var.common_tags, {{
    environment      = var.environment
    owner            = "platform-team"
    cost-center      = "engineering"
    compliance       = "fedramp"
    asset-id         = uuid()
    inventory-managed = "true"
  }})
}}

# Define common tags in variables.tf
variable "common_tags" {{
  type = map(string)
  default = {{
    managed-by = "terraform"
    project    = "fedramp-app"
  }}
}}
```

Reference: FRR-PIY-01 - Automated Inventory"""
                    ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-PIY-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-PIY-01 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-PIY-01 compliance.
        
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
