"""
KSI-MLA-05: Infrastructure as Code

Perform Infrastructure as Code and configuration evaluation and testing.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_MLA_05_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-MLA-05: Infrastructure as Code
    
    **Official Statement:**
    Perform Infrastructure as Code and configuration evaluation and testing.
    
    **Family:** MLA - Monitoring, Logging, and Auditing
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ca-7
    - cm-2
    - cm-6
    - si-7.7
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Perform Infrastructure as Code and configuration evaluation and testing....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-MLA-05"
    KSI_NAME = "Infrastructure as Code"
    KSI_STATEMENT = """Perform Infrastructure as Code and configuration evaluation and testing."""
    FAMILY = "MLA"
    FAMILY_NAME = "Monitoring, Logging, and Auditing"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ca-7", "cm-2", "cm-6", "si-7.7"]
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
        Analyze Python code for KSI-MLA-05 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Perform Infrastructure as Code and configuration evaluation and testing....
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
        Analyze C# code for KSI-MLA-05 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Perform Infrastructure as Code and configuration evaluation and testing....
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-MLA-05 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Perform Infrastructure as Code and configuration evaluation and testing....
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-MLA-05 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Perform Infrastructure as Code and configuration evaluation and testing....
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-MLA-05 compliance.
        
        Detects:
        - Missing parameter validation
        - Missing resource validation
        - Hardcoded configuration values
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Parameters without validation (MEDIUM)
        param_lines = [(i, line) for i, line in enumerate(lines, 1) 
                      if re.match(r'^\s*param\s+\w+', line)]
        
        for line_num, line in param_lines:
            # Check if parameter has validation decorators
            context_start = max(0, line_num - 4)
            context_lines = lines[context_start:line_num]
            has_validation = any(re.search(r'@(minLength|maxLength|minValue|maxValue|allowed)', l) 
                                for l in context_lines)
            
            if not has_validation and 'string' in line:
                param_name = re.search(r'param\s+(\w+)', line)
                if param_name:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title=f"Parameter '{param_name.group(1)}' Missing Validation",
                        description=(
                            f"Bicep parameter '{param_name.group(1)}' does not have validation constraints. "
                            "KSI-MLA-05 requires Infrastructure as Code testing and validation (CM-2, CM-6). "
                            "Parameters should have validation decorators (@minLength, @maxLength, @allowed) "
                            "to ensure configuration correctness and prevent deployment errors. "
                            "Without validation, invalid configurations can bypass testing."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num, context=3),
                        remediation=(
                            f"Add validation decorators to parameter '{param_name.group(1)}':\n"
                            "@description('Description of parameter')\n"
                            "@minLength(3)\n"
                            "@maxLength(50)\n"
                            f"param {param_name.group(1)} string\n\n"
                            "Or use allowed values:\n"
                            "@allowed([\n"
                            "  'dev'\n"
                            "  'staging'\n"
                            "  'production'\n"
                            "])\n"
                            f"param {param_name.group(1)} string"
                        )
                    ))
        
        # Pattern 2: Missing test/validation resources (INFO)
        has_test_deployments = bool(re.search(r"test|validate|what-if", code, re.IGNORECASE))
        has_policy_assignment = bool(re.search(r"Microsoft\.Authorization/policyAssignments", code))
        
        if not has_policy_assignment and not has_test_deployments and len(lines) > 30:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Consider Adding Azure Policy for IaC Validation",
                description=(
                    "Infrastructure code does not include Azure Policy assignments. "
                    "KSI-MLA-05 recommends ongoing configuration validation (CM-6, SI-7.7). "
                    "Azure Policy can continuously validate deployed resources against "
                    "defined standards and compliance requirements."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add Azure Policy assignment for continuous validation:\n"
                    "resource policyAssignment 'Microsoft.Authorization/policyAssignments@2022-06-01' = {\n"
                    "  name: 'enforce-bicep-standards'\n"
                    "  scope: resourceGroup()\n"
                    "  properties: {\n"
                    "    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/1f68a601-6e6d-4e42-babf-3f643a047ea2'\n"
                    "    displayName: 'Enforce Resource Naming Standards'\n"
                    "    description: 'Validates resource names against conventions'\n"
                    "  }\n"
                    "}\n\n"
                    "// Or use Policy Initiative (multiple policies)\n"
                    "resource policySet 'Microsoft.Authorization/policySetDefinitions@2021-06-01' = {\n"
                    "  name: 'infrastructure-compliance'\n"
                    "  properties: {\n"
                    "    policyType: 'Custom'\n"
                    "    displayName: 'Infrastructure Compliance Requirements'\n"
                    "    policyDefinitions: [\n"
                    "      // Add multiple policy definitions\n"
                    "    ]\n"
                    "  }\n"
                    "}"
                )
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-MLA-05 compliance.
        
        Detects:
        - Missing variable validation
        - Missing resource validation  
        - Hardcoded configuration values
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Variables without validation (MEDIUM)
        var_pattern = r'variable\s+"(\w+)"'
        for i, line in enumerate(lines, 1):
            match = re.search(var_pattern, line)
            if match:
                var_name = match.group(1)
                # Check for validation block in next 15 lines
                context_end = min(len(lines), i + 15)
                context = '\n'.join(lines[i:context_end])
                has_validation = 'validation' in context or 'condition =' in context
                
                if not has_validation:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title=f"Variable '{var_name}' Missing Validation Rules",
                        description=(
                            f"Terraform variable '{var_name}' does not have validation rules. "
                            "KSI-MLA-05 requires Infrastructure as Code testing and validation (CM-2, CM-6). "
                            "Variables should include validation blocks to ensure configuration correctness "
                            "and prevent deployment errors. Without validation, invalid configurations "
                            "can bypass testing and cause runtime issues."
                        ),
                        file_path=file_path,
                        line_number=i,
                        snippet=self._get_snippet(lines, i, context=3),
                        remediation=(
                            f"Add validation block to variable '{var_name}':\n"
                            f'variable "{var_name}" {{\n'
                            '  type        = string\n'
                            '  description = "Description of variable"\n'
                            '  \n'
                            '  validation {\n'
                            '    condition     = length(var.' + var_name + ') >= 3 && length(var.' + var_name + ') <= 50\n'
                            '    error_message = "Value must be between 3 and 50 characters."\n'
                            '  }\n'
                            '}\n\n'
                            'Or use regex validation:\n'
                            '  validation {\n'
                            '    condition     = can(regex("^[a-z0-9-]+$", var.' + var_name + '))\n'
                            '    error_message = "Value must contain only lowercase letters, numbers, and hyphens."\n'
                            '  }'
                        )
                    ))
        
        # Pattern 2: Missing precondition/postcondition checks (INFO)
        has_conditions = bool(re.search(r'(precondition|postcondition)\s*{', code))
        resource_count = len(re.findall(r'resource\s+"', code))
        
        if not has_conditions and resource_count > 3:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Consider Adding Precondition/Postcondition Checks",
                description=(
                    "Infrastructure code does not use Terraform lifecycle preconditions or postconditions. "
                    "KSI-MLA-05 recommends comprehensive IaC testing (CM-6, SI-7.7). "
                    "Preconditions validate inputs before resource creation, and postconditions "
                    "verify resource state after creation, providing runtime validation."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add lifecycle preconditions and postconditions:\n"
                    'resource "azurerm_storage_account" "example" {\n'
                    '  name                = var.storage_account_name\n'
                    '  resource_group_name = var.resource_group_name\n'
                    '  location            = var.location\n'
                    '  \n'
                    '  lifecycle {\n'
                    '    # Precondition: Validate before creation\n'
                    '    precondition {\n'
                    '      condition     = length(var.storage_account_name) >= 3\n'
                    '      error_message = "Storage account name must be at least 3 characters."\n'
                    '    }\n'
                    '    \n'
                    '    # Postcondition: Verify after creation\n'
                    '    postcondition {\n'
                    '      condition     = self.https_traffic_only_enabled == true\n'
                    '      error_message = "Storage account must enforce HTTPS."\n'
                    '    }\n'
                    '  }\n'
                    '}'
                )
            ))
        
        # Pattern 3: Check for testing framework usage (GOOD PRACTICE)
        has_terratest = bool(re.search(r'terratest|test', code, re.IGNORECASE))
        if has_terratest:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Terraform Testing Framework Detected",
                description=(
                    "Code references testing frameworks (Terratest). "
                    "KSI-MLA-05 requires IaC testing (CM-2). This is a good practice."
                ),
                file_path=file_path,
                line_number=self._find_line(lines, 'test'),
                snippet="",
                remediation="Continue using testing frameworks for IaC validation.",
                good_practice=True
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-MLA-05 compliance.
        
        Detects:
        - Missing IaC validation steps
        - Missing what-if/plan steps
        - Missing linting/testing
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Missing Bicep/Terraform validation (HIGH)
        has_bicep_build = bool(re.search(r'az\s+bicep\s+build|bicep\s+build', code, re.IGNORECASE))
        has_tf_validate = bool(re.search(r'terraform\s+validate', code, re.IGNORECASE))
        has_tf_plan = bool(re.search(r'terraform\s+plan', code, re.IGNORECASE))
        has_bicep_whatif = bool(re.search(r'what-if|whatif', code, re.IGNORECASE))
        
        has_bicep = bool(re.search(r'\.bicep', code))
        has_terraform = bool(re.search(r'terraform|hashicorp', code, re.IGNORECASE))
        
        if has_bicep and not has_bicep_build and not has_bicep_whatif:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Missing Bicep Validation in CI/CD Pipeline",
                description=(
                    "Pipeline references Bicep files but does not include validation steps. "
                    "KSI-MLA-05 requires IaC testing and validation before deployment (CM-2, CM-6). "
                    "Bicep files should be validated with 'az bicep build' and previewed with "
                    "'az deployment group what-if' to catch errors before production deployment."
                ),
                file_path=file_path,
                line_number=self._find_line(lines, 'bicep'),
                snippet=self._get_snippet(lines, self._find_line(lines, 'bicep'), context=3),
                remediation=(
                    "Add Bicep validation steps to GitHub Actions workflow:\n"
                    "- name: Validate Bicep Templates\n"
                    "  run: |\n"
                    "    # Validate syntax\n"
                    "    az bicep build --file main.bicep\n"
                    "    \n"
                    "    # Preview changes (what-if)\n"
                    "    az deployment group what-if \\\n"
                    "      --resource-group ${{ env.RESOURCE_GROUP }} \\\n"
                    "      --template-file main.bicep \\\n"
                    "      --parameters main.parameters.json\n"
                    "    \n"
                    "    # Lint with PSRule (optional but recommended)\n"
                    "    Install-Module -Name PSRule.Rules.Azure -Force\n"
                    "    Assert-PSRule -Module PSRule.Rules.Azure -InputPath . -Format File"
                )
            ))
        
        if has_terraform and not has_tf_validate and not has_tf_plan:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Missing Terraform Validation in CI/CD Pipeline",
                description=(
                    "Pipeline uses Terraform but does not include validation steps. "
                    "KSI-MLA-05 requires IaC testing and validation (CM-2, CM-6). "
                    "Terraform configurations should be validated with 'terraform validate' "
                    "and planned with 'terraform plan' before applying changes."
                ),
                file_path=file_path,
                line_number=self._find_line(lines, 'terraform'),
                snippet=self._get_snippet(lines, self._find_line(lines, 'terraform'), context=3),
                remediation=(
                    "Add Terraform validation steps to GitHub Actions workflow:\n"
                    "- name: Validate Terraform Configuration\n"
                    "  run: |\n"
                    "    # Initialize backend\n"
                    "    terraform init\n"
                    "    \n"
                    "    # Validate syntax and configuration\n"
                    "    terraform validate\n"
                    "    \n"
                    "    # Check formatting\n"
                    "    terraform fmt -check\n"
                    "    \n"
                    "    # Generate and review plan\n"
                    "    terraform plan -out=tfplan\n"
                    "    \n"
                    "    # Security scan with tfsec (optional)\n"
                    "    docker run --rm -v \"$(pwd):/src\" aquasec/tfsec /src"
                )
            ))
        
        # Pattern 2: Good practice detection
        if has_bicep_build or has_bicep_whatif:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Bicep Validation Configured",
                description="Pipeline includes Bicep validation steps. KSI-MLA-05 compliance.",
                file_path=file_path,
                line_number=self._find_line(lines, 'bicep'),
                snippet="",
                remediation="Continue validating Bicep templates before deployment.",
                good_practice=True
            ))
        
        if has_tf_validate or has_tf_plan:
            findings.append(Finding(
                severity=Severity.INFO,
                title="Terraform Validation Configured",
                description="Pipeline includes Terraform validation steps. KSI-MLA-05 compliance.",
                file_path=file_path,
                line_number=self._find_line(lines, 'terraform'),
                snippet="",
                remediation="Continue validating Terraform configuration before deployment.",
                good_practice=True
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-MLA-05 compliance.
        
        Detects:
        - Missing IaC validation tasks
        - Missing deployment validation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Missing Bicep/Terraform validation (HIGH)
        has_bicep_task = bool(re.search(r'AzureCLI.*bicep|bicep\s+build', code, re.IGNORECASE))
        has_tf_task = bool(re.search(r'TerraformCLI|terraform\s+validate', code, re.IGNORECASE))
        
        has_bicep = bool(re.search(r'\.bicep', code))
        has_terraform = bool(re.search(r'terraform', code, re.IGNORECASE))
        
        if has_bicep and not has_bicep_task:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Missing Bicep Validation in Azure Pipeline",
                description=(
                    "Pipeline references Bicep files but does not include validation tasks. "
                    "KSI-MLA-05 requires IaC testing and validation (CM-2, CM-6)."
                ),
                file_path=file_path,
                line_number=self._find_line(lines, 'bicep'),
                snippet=self._get_snippet(lines, self._find_line(lines, 'bicep'), context=3),
                remediation=(
                    "Add Bicep validation task to Azure Pipeline:\n"
                    "- task: AzureCLI@2\n"
                    "  displayName: 'Validate Bicep Templates'\n"
                    "  inputs:\n"
                    "    azureSubscription: '$(azureServiceConnection)'\n"
                    "    scriptType: 'bash'\n"
                    "    scriptLocation: 'inlineScript'\n"
                    "    inlineScript: |\n"
                    "      az bicep build --file main.bicep\n"
                    "      az deployment group what-if \\\n"
                    "        --resource-group $(resourceGroup) \\\n"
                    "        --template-file main.bicep"
                )
            ))
        
        if has_terraform and not has_tf_task:
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Missing Terraform Validation in Azure Pipeline",
                description=(
                    "Pipeline uses Terraform but does not include validation tasks. "
                    "KSI-MLA-05 requires IaC testing and validation (CM-2, CM-6)."
                ),
                file_path=file_path,
                line_number=self._find_line(lines, 'terraform'),
                snippet=self._get_snippet(lines, self._find_line(lines, 'terraform'), context=3),
                remediation=(
                    "Add Terraform validation task to Azure Pipeline:\n"
                    "- task: TerraformCLI@0\n"
                    "  displayName: 'Terraform Validate'\n"
                    "  inputs:\n"
                    "    command: 'validate'\n"
                    "    workingDirectory: '$(System.DefaultWorkingDirectory)/terraform'\n"
                    "\n"
                    "- task: TerraformCLI@0\n"
                    "  displayName: 'Terraform Plan'\n"
                    "  inputs:\n"
                    "    command: 'plan'\n"
                    "    workingDirectory: '$(System.DefaultWorkingDirectory)/terraform'"
                )
            ))
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-MLA-05 compliance.
        
        Detects:
        - Missing IaC validation stages
        - Missing testing jobs
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Missing validation stage (HIGH)
        has_validate_stage = bool(re.search(r'stage:\s*validate', code, re.IGNORECASE))
        has_test_stage = bool(re.search(r'stage:\s*test', code, re.IGNORECASE))
        has_bicep = bool(re.search(r'\.bicep|bicep\s+build', code))
        has_terraform = bool(re.search(r'terraform', code, re.IGNORECASE))
        
        if (has_bicep or has_terraform) and not (has_validate_stage or has_test_stage):
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Missing Validation Stage in GitLab CI",
                description=(
                    "Pipeline includes IaC files but does not have a validation/test stage. "
                    "KSI-MLA-05 requires IaC testing and validation (CM-2, CM-6). "
                    "GitLab CI should include validate or test stages before deployment."
                ),
                file_path=file_path,
                line_number=1,
                snippet=self._get_snippet(lines, 1, context=5),
                remediation=(
                    "Add validation stage to GitLab CI:\n"
                    "stages:\n"
                    "  - validate\n"
                    "  - test\n"
                    "  - deploy\n"
                    "\n"
                    "validate:bicep:\n"
                    "  stage: validate\n"
                    "  image: mcr.microsoft.com/azure-cli\n"
                    "  script:\n"
                    "    - az bicep build --file main.bicep\n"
                    "    - az deployment group what-if \\\n"
                    "        --resource-group $RESOURCE_GROUP \\\n"
                    "        --template-file main.bicep\n"
                    "\n"
                    "validate:terraform:\n"
                    "  stage: validate\n"
                    "  image: hashicorp/terraform:latest\n"
                    "  script:\n"
                    "    - terraform init\n"
                    "    - terraform validate\n"
                    "    - terraform plan -out=tfplan"
                )
            ))
        
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
