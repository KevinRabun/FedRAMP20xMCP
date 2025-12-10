"""
KSI-MLA-05: Infrastructure as Code (Enhanced with AST Analysis)

Perform Infrastructure as Code and configuration evaluation and testing.

ENHANCED FEATURES:
- AST-based analysis for Python, C#, Java, JavaScript/TypeScript
- Detects missing IaC testing frameworks (pytest-terraform, Pester, Terratest)
- Validates CI/CD pipeline IaC testing stages
- Checks for infrastructure validation gates
- Bicep/Terraform parameter validation and policy enforcement
- Configuration drift detection patterns

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity, AnalysisResult
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage
from ..semantic_analysis import SemanticAnalyzer


class KSI_MLA_05_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced analyzer for KSI-MLA-05: Infrastructure as Code testing and validation.
    
    **Official Statement:**
    Perform Infrastructure as Code and configuration evaluation and testing.
    
    **Family:** MLA - Monitoring, Logging, and Auditing
    
    **Impact Levels:** Low: Yes, Moderate: Yes
    
    **NIST Controls:** ca-7, cm-2, cm-6, si-7.7
    
    **Detection Strategy:**
    - Application code: Detect IaC testing frameworks (pytest-terraform, Pester, Terratest, InSpec)
    - IaC: Validate parameter constraints, policy assignments, testing resources
    - CI/CD: Validate IaC testing stages, validation gates, what-if deployments
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    """
    
    KSI_ID = "KSI-MLA-05"
    KSI_NAME = "Infrastructure as Code"
    KSI_STATEMENT = "Perform Infrastructure as Code and configuration evaluation and testing"
    FAMILY = "MLA"
    FAMILY_NAME = "Monitoring, Logging, and Auditing"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ca-7", "Continuous Monitoring"),
        ("cm-2", "Baseline Configuration"),
        ("cm-6", "Configuration Settings"),
        ("si-7.7", "Integration of Detection and Response")
    ]
    
    # IaC Testing Frameworks
    IAC_TESTING_FRAMEWORKS = {
        "pytest-terraform",  # Python Terraform testing
        "terraform-compliance",  # Python BDD-style testing
        "terratest",  # Go-based infrastructure testing
        "kitchen-terraform",  # Ruby Test Kitchen integration
        "inspec",  # Chef InSpec for infrastructure testing
        "pester",  # PowerShell testing framework
        "checkov",  # Static analysis for IaC
        "tflint",  # Terraform linter
        "terrascan",  # Security scanner for IaC
        "serverspec",  # Ruby-based infrastructure testing
    }
    
    # CI/CD IaC Testing Keywords
    IAC_TESTING_KEYWORDS = {
        "terraform validate",
        "terraform plan",
        "terraform test",
        "bicep build",
        "what-if",
        "test-azresourcegroup",
        "pester",
        "invoke-pester",
        "terratest",
        "kitchen test",
    }
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language

    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Python code for IaC testing framework usage."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        
        # Create parser
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        if not tree:
            return findings
        
        # Check if code/file appears infrastructure-related (BEFORE checking imports)
        file_lower = file_path.lower()
        code_lower = code.lower()
        
        is_infra_file = any(keyword in file_lower for keyword in ["infra", "terraform", "deploy"])
        is_test_file = ("test" in file_lower or "test_" in code_lower)
        has_infra_code = ("terraform" in code_lower or "subprocess" in code_lower)
        
        # Check for IaC testing framework imports
        has_iac_testing = False
        has_generic_test_framework = False  # pytest, unittest, etc.
        iac_frameworks_found = []
        
        imports = parser.find_nodes_by_type(tree.root_node, "import_statement")
        imports.extend(parser.find_nodes_by_type(tree.root_node, "import_from_statement"))
        
        for imp in imports:
            imp_text = parser.get_node_text(imp, code_bytes).lower()
            # Check for dedicated IaC testing frameworks
            for framework in self.IAC_TESTING_FRAMEWORKS:
                if framework in imp_text:
                    has_iac_testing = True
                    if framework not in iac_frameworks_found:
                        iac_frameworks_found.append(framework)
            
            # Check for generic testing frameworks (pytest, unittest)
            if any(fw in imp_text for fw in ["pytest", "unittest", "from unittest"]):
                has_generic_test_framework = True
                if is_test_file and (is_infra_file or has_infra_code):
                    # In infrastructure context, pytest/unittest count as IAC testing
                    has_iac_testing = True
                    if "pytest" not in iac_frameworks_found and "pytest" in imp_text:
                        iac_frameworks_found.append("pytest")
                    if "unittest" not in iac_frameworks_found and "unittest" in imp_text:
                        iac_frameworks_found.append("unittest")
        
        # Scenario 1: Infrastructure deployment file without testing framework
        if is_infra_file and "deploy" in file_lower and not is_test_file:
            if not has_iac_testing:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Infrastructure Deployment Without Testing Framework",
                    description=f"File '{file_path}' performs infrastructure deployment but lacks testing framework imports. KSI-MLA-05 requires Infrastructure as Code evaluation and testing (NIST CM-2, CM-6).",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet=self._get_snippet(lines, 1),
                    recommendation=(
                        "Import IaC testing framework:\n"
                        "import pytest\n"
                        "from python_terraform import Terraform\n\n"
                        "# Or:\n"
                        "from terraform_compliance.main import cli\n\n"
                        "Then implement validation tests."
                    )
                ))
        
        # Scenario 2: Test file with IaC framework but no test functions
        elif is_test_file and has_iac_testing:
            # Check for test functions
            has_test_funcs = False
            for node in parser.find_nodes_by_type(tree.root_node, "function_definition"):
                func_name = None
                for child in node.children:
                    if child.type == "identifier":
                        func_name = parser.get_node_text(child, code_bytes)
                        break
                
                if func_name and ("test_" in func_name.lower() or "validate_" in func_name.lower()):
                    func_body = parser.get_node_text(node, code_bytes).lower()
                    if any(kw in func_body for kw in ["config", "infrastructure", "terraform", "assert", "validate"]):
                        has_test_funcs = True
                        break
            
            if not has_test_funcs:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="IaC Framework Imported But No Tests Found",
                    description=f"IaC testing frameworks imported ({', '.join(iac_frameworks_found)}) but no test functions detected. KSI-MLA-05 requires actual configuration evaluation.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet=self._get_snippet(lines, 1),
                    recommendation=(
                        "Implement IaC tests:\n"
                        "def test_infrastructure_compliance():\n"
                        "    terraform = Terraform(working_dir='./infra')\n"
                        "    ret_code, stdout, stderr = terraform.validate()\n"
                        "    assert ret_code == 0"
                    )
                ))
        
        # Scenario 3: Test file that appears IaC-related but no framework
        elif is_test_file and (is_infra_file or has_infra_code):
            if not has_iac_testing:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Infrastructure Test Without Testing Framework",
                    description=f"File '{file_path}' appears to test infrastructure but lacks IaC testing framework imports. KSI-MLA-05 requires Infrastructure as Code evaluation and testing.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet=self._get_snippet(lines, 1),
                    recommendation=(
                        "Import IaC testing framework:\n"
                        "import pytest\n"
                        "from python_terraform import Terraform\n\n"
                        "@pytest.fixture\n"
                        "def terraform():\n"
                        "    return Terraform(working_dir='./infra')\n\n"
                        "def test_terraform_plan(terraform):\n"
                        "    ret_code, stdout, stderr = terraform.plan()\n"
                        "    assert ret_code == 0"
                    )
                ))
        
        return findings

    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze C# code for IaC testing patterns (Pester via PowerShell Core)."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        if not tree:
            return findings
        
        # Check for PowerShell/Pester invocation or Azure.ResourceManager.Bicep references
        has_iac_testing = False
        
        using_directives = parser.find_nodes_by_type(tree.root_node, "using_directive")
        for using in using_directives:
            using_text = parser.get_node_text(using, code_bytes)
            if any(framework in using_text for framework in ["Azure.ResourceManager", "Azure.Deployment", "Pester"]):
                has_iac_testing = True
        
        # Check for ProcessStartInfo with Pester/Bicep/Terraform
        string_literals = parser.find_nodes_by_type(tree.root_node, "string_literal")
        has_pester_invocation = False
        for lit in string_literals:
            text = parser.get_node_text(lit, code_bytes).lower()
            if any(kw in text for kw in ["invoke-pester", "bicep build", "terraform validate"]):
                has_pester_invocation = True
        
        if any(keyword in file_path.lower() for keyword in ["infra", "iac", "deploy", "bicep"]):
            if not has_iac_testing and not has_pester_invocation:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Infrastructure Deployment Without Testing",
                    description=f"File '{file_path}' appears to handle infrastructure but does not invoke IaC testing tools. KSI-MLA-05 requires Infrastructure as Code evaluation and testing.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet=self._get_snippet(lines, 1),
                    recommendation=(
                        "Add IaC testing via Pester or Azure SDK:\n"
                        "// Using Pester (PowerShell Core):\n"
                        "var psi = new ProcessStartInfo\n"
                        "{\n"
                        "    FileName = \"pwsh\",\n"
                        "    Arguments = \"-Command Invoke-Pester -Path ./infra/tests -PassThru\",\n"
                        "    RedirectStandardOutput = true\n"
                        "};\n"
                        "var process = Process.Start(psi);\n"
                        "// Check exit code and output for test results\n\n"
                        "// Or using Azure SDK for validation:\n"
                        "using Azure.ResourceManager;\n"
                        "var client = new ArmClient(credential);\n"
                        "var deployment = await client.ValidateDeploymentAsync(templateContent);\n"
                        "Assert.Equal(\"Succeeded\", deployment.Value.Properties.ProvisioningState);"
                    )
                ))
        
        return findings

    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java code for Terratest or infrastructure testing patterns."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        if not tree:
            return findings
        
        # Check if code/file appears infrastructure-related (BEFORE checking imports)
        file_lower = file_path.lower()
        code_lower = code.lower()
        
        is_infra_file = any(keyword in file_lower for keyword in ["infra", "terraform", "deploy", "iac"])
        is_test_file = ("test" in file_lower or "@test" in code_lower or "import org.junit" in code_lower)
        has_infra_code = ("terraform" in code_lower or "processbuilder" in code_lower or "runtime.getruntime().exec" in code_lower)
        
        # Check for IaC testing frameworks or validation commands
        has_iac_testing = False
        has_generic_test_framework = False
        
        imports = parser.find_nodes_by_type(tree.root_node, "import_declaration")
        for imp in imports:
            imp_text = parser.get_node_text(imp, code_bytes).lower()
            if any(framework in imp_text for framework in ["terratest", "inspec", "awaitility"]):
                has_iac_testing = True
            # Check for JUnit/TestNG
            if any(fw in imp_text for fw in ["org.junit", "org.testng", "jupiter"]):
                has_generic_test_framework = True
                if is_test_file and (is_infra_file or has_infra_code):
                    # In infrastructure context, JUnit/TestNG count as IAC testing
                    has_iac_testing = True
        
        # Check for terraform validate/plan commands in string literals
        string_literals = parser.find_nodes_by_type(tree.root_node, "string_literal")
        has_iac_command = False
        for lit in string_literals:
            text = parser.get_node_text(lit, code_bytes).lower()
            if any(kw in text for kw in ["terraform validate", "terraform plan", "bicep build", "az deployment"]):
                has_iac_command = True
                has_iac_testing = True  # Validation commands count as testing
        
        # Scenario 1: Infrastructure deployment file without testing framework
        if is_infra_file and not is_test_file and has_infra_code:
            if not has_iac_testing:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Infrastructure Deployment Without Testing Framework",
                    description=f"File '{file_path}' performs infrastructure deployment but lacks testing framework imports or validation. KSI-MLA-05 requires Infrastructure as Code evaluation and testing (NIST CM-2, CM-6).",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet=self._get_snippet(lines, 1),
                    recommendation=(
                        "Add IaC validation before deployment:\n"
                        "@Test\n"
                        "public void testTerraformValidate() throws Exception {\n"
                        "    ProcessBuilder pb = new ProcessBuilder(\"terraform\", \"validate\");\n"
                        "    pb.directory(new File(\"./infra\"));\n"
                        "    Process process = pb.start();\n"
                        "    int exitCode = process.waitFor();\n"
                        "    assertEquals(0, exitCode, \"Terraform validation should succeed\");\n"
                        "}"
                    )
                ))
        
        # Scenario 2: Test file with framework but no IaC validation
        elif is_test_file and (is_infra_file or has_infra_code) and has_generic_test_framework:
            if not has_iac_command:
                # Check for test methods
                has_test_methods = False
                for node in parser.find_nodes_by_type(tree.root_node, "method_declaration"):
                    method_text = parser.get_node_text(node, code_bytes)
                    if "@Test" in method_text or "@org.junit.Test" in method_text:
                        has_test_methods = True
                        break
                
                if not has_test_methods:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="IaC Framework Imported But No Tests Found",
                        description=f"JUnit/TestNG framework imported but no infrastructure test methods detected. KSI-MLA-05 requires actual configuration evaluation.",
                        severity=Severity.MEDIUM,
                        file_path=file_path,
                        line_number=1,
                        code_snippet=self._get_snippet(lines, 1),
                        recommendation=(
                            "Implement IaC validation tests:\n"
                            "@Test\n"
                            "public void testTerraformPlan() throws Exception {\n"
                            "    ProcessBuilder pb = new ProcessBuilder(\"terraform\", \"plan\");\n"
                            "    int exitCode = pb.start().waitFor();\n"
                            "    assertEquals(0, exitCode);\n"
                            "}"
                        )
                    ))
        
        # Scenario 3: Test file that appears IaC-related but no framework
        elif is_test_file and (is_infra_file or has_infra_code):
            if not has_iac_testing:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Infrastructure Test Without Testing Framework",
                    description=f"File '{file_path}' appears to test infrastructure but lacks testing framework imports. KSI-MLA-05 requires Infrastructure as Code evaluation and testing.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet=self._get_snippet(lines, 1),
                    recommendation=(
                        "Import testing framework:\n"
                        "import org.junit.Test;\n"
                        "import static org.junit.Assert.*;\n\n"
                        "@Test\n"
                        "public void testTerraformValidate() throws Exception {\n"
                        "    ProcessBuilder pb = new ProcessBuilder(\"terraform\", \"validate\");\n"
                        "    assertEquals(0, pb.start().waitFor());\n"
                        "}"
                    )
                ))
        
        return findings

    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze TypeScript/JavaScript for infrastructure testing patterns."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        tree = parser.parse(code)
        if not tree:
            return findings
        
        # Check if code/file appears infrastructure-related (BEFORE checking imports)
        file_lower = file_path.lower()
        code_lower = code.lower()
        
        is_infra_file = any(keyword in file_lower for keyword in ["infra", "iac", "cdk", "terraform", "deploy"])
        is_test_file = (".test." in file_lower or ".spec." in file_lower or "describe(" in code or "it(" in code)
        has_infra_code = ("@cdktf" in code or "pulumi" in code_lower or "terraform" in code_lower or "@azure/arm" in code_lower)
        
        # Check for IaC testing library imports
        has_iac_testing = False
        has_generic_test_framework = False
        iac_frameworks_found = []
        
        imports = parser.find_nodes_by_type(tree.root_node, "import_statement")
        for imp in imports:
            imp_text = parser.get_node_text(imp, code_bytes).lower()
            # Check for dedicated IaC frameworks
            if any(framework in imp_text for framework in ["cdktf", "terraform", "pulumi", "@azure/arm", "checkov"]):
                has_iac_testing = True
                for framework in self.IAC_TESTING_FRAMEWORKS:
                    if framework in imp_text:
                        iac_frameworks_found.append(framework)
            
            # Check for generic testing frameworks (jest, mocha, jasmine)
            if any(fw in imp_text for fw in ["jest", "mocha", "jasmine", "@jest", "chai"]):
                has_generic_test_framework = True
                if is_test_file and (is_infra_file or has_infra_code):
                    # In infrastructure context, Jest/Mocha count as IAC testing
                    has_iac_testing = True
        
        # Scenario 1: Infrastructure deployment file without testing framework
        if is_infra_file and not is_test_file and has_infra_code:
            if not has_iac_testing:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Infrastructure Deployment Without Testing Framework",
                    description=f"File '{file_path}' performs infrastructure deployment but lacks testing framework imports. KSI-MLA-05 requires Infrastructure as Code evaluation and testing (NIST CM-2, CM-6).",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet=self._get_snippet(lines, 1),
                    recommendation=(
                        "Import IaC testing framework:\n"
                        "import { Testing } from 'cdktf';\n"
                        "// Or:\n"
                        "import { Testing } from '@pulumi/pulumi';\n\n"
                        "Then implement validation tests."
                    )
                ))
        
        # Scenario 2: Test file with framework but no test functions
        elif is_test_file and (is_infra_file or has_infra_code) and has_generic_test_framework:
            # Check for test functions
            has_test_funcs = False
            call_expressions = parser.find_nodes_by_type(tree.root_node, "call_expression")
            for node in call_expressions:
                node_text = parser.get_node_text(node, code_bytes)
                if any(pattern in node_text for pattern in ["describe(", "it(", "test("]):
                    # Check if the test block has meaningful content
                    if any(kw in node_text.lower() for kw in ["infrastructure", "terraform", "validate", "config", "expect", "assert"]):
                        has_test_funcs = True
                        break
            
            if not has_test_funcs:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="IaC Framework Imported But No Tests Found",
                    description=f"Testing framework imported but no infrastructure test functions detected. KSI-MLA-05 requires actual configuration evaluation.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet=self._get_snippet(lines, 1),
                    recommendation=(
                        "Implement IaC tests:\n"
                        "describe('Infrastructure Tests', () => {\n"
                        "  it('should validate terraform configuration', () => {\n"
                        "    const stack = Testing.app().synth();\n"
                        "    expect(stack).toBeDefined();\n"
                        "  });\n"
                        "});"
                    )
                ))
        
        # Scenario 3: Test file that appears IaC-related but no framework
        elif is_test_file and (is_infra_file or has_infra_code):
            if not has_iac_testing:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Infrastructure Test Without Testing Framework",
                    description=f"File '{file_path}' appears to test infrastructure but lacks testing framework imports. KSI-MLA-05 requires Infrastructure as Code evaluation and testing.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet=self._get_snippet(lines, 1),
                    recommendation=(
                        "Import testing framework:\n"
                        "import { Testing } from 'cdktf';\n\n"
                        "describe('Infrastructure Tests', () => {\n"
                        "  it('should validate configuration', () => {\n"
                        "    const stack = Testing.app().synth();\n"
                        "    expect(stack).toBeDefined();\n"
                        "  });\n"
                        "});"
                    )
                ))
        
        return findings

    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Bicep for parameter validation and policy enforcement."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Parameters without validation decorators
        param_pattern = re.compile(r'^\s*param\s+(\w+)\s+(\w+)', re.MULTILINE)
        params = param_pattern.finditer(code)
        
        for match in params:
            param_name = match.group(1)
            param_type = match.group(2)
            line_num = code[:match.start()].count('\n') + 1
            
            # Check for validation decorators before parameter
            context_start = max(0, match.start() - 200)
            context = code[context_start:match.start()]
            
            has_validation = bool(re.search(r'@(minLength|maxLength|minValue|maxValue|allowed|description)', context))
            
            if not has_validation and param_type in ('string', 'int', 'array'):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title=f"Bicep Parameter '{param_name}' Missing Validation",
                    description=f"Parameter '{param_name}' of type '{param_type}' lacks validation decorators. KSI-MLA-05 requires Infrastructure as Code testing and validation (NIST CM-2, CM-6). Without validation, invalid configurations can bypass testing.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        f"Add validation decorators:\n"
                        f"@description('Description of {param_name}')\n" +
                        ("@minLength(1)\n@maxLength(100)\n" if param_type == 'string' else "") +
                        ("@minValue(0)\n@maxValue(1000)\n" if param_type == 'int' else "") +
                        f"param {param_name} {param_type}\n\n"
                        "Or restrict to allowed values:\n"
                        "@allowed([\n"
                        "  'option1'\n"
                        "  'option2'\n"
                        "])\n"
                        f"param {param_name} {param_type}"
                    )
                ))
        
        # Pattern 2: Missing Azure Policy assignment
        has_policy = bool(re.search(r'Microsoft\.Authorization/policyAssignments', code))
        has_test_comments = bool(re.search(r'(test|validate|what-if)', code, re.IGNORECASE))
        
        if not has_policy and len(lines) > 30:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Consider Azure Policy for Continuous Validation",
                description="Bicep template does not include Azure Policy assignments. KSI-MLA-05 recommends ongoing configuration validation (CM-6, SI-7.7). Azure Policy provides continuous compliance checking.",
                severity=Severity.INFO,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1),
                recommendation=(
                    "Add Azure Policy assignment:\n"
                    "resource policyAssignment 'Microsoft.Authorization/policyAssignments@2022-06-01' = {\n"
                    "  name: 'infrastructure-compliance'\n"
                    "  scope: resourceGroup()\n"
                    "  properties: {\n"
                    "    policyDefinitionId: '<policy-definition-id>'\n"
                    "    displayName: 'Enforce Infrastructure Standards'\n"
                    "  }\n"
                    "}\n\n"
                    "// Deploy with what-if validation:\n"
                    "// az deployment group create --what-if --template-file main.bicep"
                )
            ))
        
        return findings

    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Terraform for variable validation and testing resources."""
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Variables without validation blocks
        variable_pattern = re.compile(r'variable\s+"(\w+)"\s*\{', re.MULTILINE)
        variables = list(variable_pattern.finditer(code))
        
        for match in variables:
            var_name = match.group(1)
            line_num = code[:match.start()].count('\n') + 1
            
            # Find variable block end
            block_start = match.end()
            brace_count = 1
            block_end = block_start
            
            for i in range(block_start, len(code)):
                if code[i] == '{':
                    brace_count += 1
                elif code[i] == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        block_end = i
                        break
            
            var_block = code[block_start:block_end]
            has_validation = 'validation' in var_block
            
            if not has_validation:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title=f"Terraform Variable '{var_name}' Missing Validation",
                    description=f"Variable '{var_name}' lacks validation block. KSI-MLA-05 requires Infrastructure as Code testing and validation. Terraform 0.13+ supports custom validation rules.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    recommendation=(
                        f"Add validation block to variable '{var_name}':\n"
                        f"variable \"{var_name}\" {{\n"
                        "  type        = string\n"
                        "  description = \"Description of variable\"\n"
                        "  \n"
                        "  validation {\n"
                        "    condition     = length(var." + var_name + ") > 3\n"
                        "    error_message = \"Variable must be at least 3 characters.\"\n"
                        "  }\n"
                        "}\n\n"
                        "// Or use regex validation:\n"
                        "validation {\n"
                        "  condition     = can(regex(\"^[a-z0-9-]+$\", var." + var_name + "))\n"
                        "  error_message = \"Variable must contain only lowercase letters, numbers, and hyphens.\"\n"
                        "}"
                    )
                ))
        
        # Pattern 2: Missing sentinel policy or testing
        has_sentinel = bool(re.search(r'sentinel\.hcl', code))
        has_testing = bool(re.search(r'(terraform_validate|tftest)', code))
        
        if not has_sentinel and not has_testing and len(lines) > 30:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Consider Policy-as-Code for Validation",
                description="Terraform configuration lacks policy enforcement or testing framework references. KSI-MLA-05 recommends ongoing validation (CM-6, SI-7.7). Sentinel or OPA provides policy-as-code.",
                severity=Severity.INFO,
                file_path=file_path,
                line_number=1,
                code_snippet=self._get_snippet(lines, 1),
                recommendation=(
                    "Add Sentinel policy:\n"
                    "# sentinel.hcl\n"
                    "policy \"require-tags\" {\n"
                    "  source            = \"./policies/require-tags.sentinel\"\n"
                    "  enforcement_level = \"hard\"\n"
                    "}\n\n"
                    "# Or use terraform test (Terraform 1.6+):\n"
                    "# tests/main.tftest.hcl\n"
                    "run \"validate_configuration\" {\n"
                    "  command = plan\n"
                    "  assert {\n"
                    "    condition     = length(azurerm_resource_group.main.tags) > 0\n"
                    "    error_message = \"Resource group must have tags\"\n"
                    "  }\n"
                    "}\n\n"
                    "# Run with: terraform test"
                )
            ))
        
        return findings
    

        """Get code snippet around line number."""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        snippet_lines = []
        for i in range(start, end):
            prefix = "→ " if i == line_num - 1 else "  "
            snippet_lines.append(f"{i+1:4d} {prefix}{lines[i]}")
        return "\n".join(snippet_lines)
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get Azure-specific recommendations for automating evidence collection for KSI-MLA-05.
        
        **KSI-MLA-05: Infrastructure as Code**
        Perform Infrastructure as Code and configuration evaluation and testing.
        
        Returns:
            Dictionary with automation recommendations
        """
        return {
            "ksi_id": "KSI-MLA-05",
            "ksi_name": "Infrastructure as Code Testing",
            "azure_services": [
                {
                    "service": "Azure DevOps",
                    "purpose": "IaC pipeline testing and validation evidence",
                    "capabilities": [
                        "Pipeline test results for IaC validation",
                        "Test execution history and trends",
                        "Code coverage for infrastructure tests",
                        "Pre-deployment validation gates"
                    ]
                },
                {
                    "service": "Azure Policy",
                    "purpose": "Policy-driven IaC validation and compliance testing",
                    "capabilities": [
                        "Policy compliance testing before deployment",
                        "Guest Configuration for validation",
                        "What-if deployment analysis",
                        "Remediation task tracking"
                    ]
                },
                {
                    "service": "Azure Resource Manager",
                    "purpose": "Template validation and what-if analysis",
                    "capabilities": [
                        "ARM template validation API",
                        "What-if deployment previews",
                        "Resource change impact analysis",
                        "Deployment preflight checks"
                    ]
                },
                {
                    "service": "Microsoft Defender for DevOps",
                    "purpose": "Security scanning of IaC templates",
                    "capabilities": [
                        "IaC security misconfiguration detection",
                        "Template hardening recommendations",
                        "Pull request security checks",
                        "Compliance validation"
                    ]
                },
                {
                    "service": "Azure Monitor",
                    "purpose": "IaC testing metrics and deployment validation logs",
                    "capabilities": [
                        "Test execution logs",
                        "Deployment validation results",
                        "Configuration drift detection",
                        "Test coverage metrics"
                    ]
                }
            ],
            "collection_methods": [
                {
                    "method": "IaC Test Execution Evidence",
                    "description": "Export pipeline test results showing IaC validation and testing (Terratest, Pester, pytest-terraform)",
                    "automation": "Azure DevOps Test Results API",
                    "frequency": "Per deployment",
                    "evidence_produced": "Test execution reports with pass/fail status and coverage"
                },
                {
                    "method": "Policy Validation Results",
                    "description": "What-if deployment analysis and policy compliance validation before deployment",
                    "automation": "Azure Policy what-if API and compliance scans",
                    "frequency": "Per deployment",
                    "evidence_produced": "Policy compliance report and what-if analysis results"
                },
                {
                    "method": "Template Security Scan Results",
                    "description": "Security scanning results from Defender for DevOps for IaC templates",
                    "automation": "Defender for DevOps integration in pipelines",
                    "frequency": "Per commit",
                    "evidence_produced": "SARIF security scan results for Bicep/Terraform templates"
                },
                {
                    "method": "Configuration Drift Detection",
                    "description": "Detect and report configuration drift from IaC definitions",
                    "automation": "Terraform state comparison or Azure Resource Graph",
                    "frequency": "Daily",
                    "evidence_produced": "Configuration drift report with remediation actions"
                }
            ],
            "automation_feasibility": "high",
            "evidence_types": ["log-based", "config-based"],
            "implementation_guidance": {
                "quick_start": "Enable IaC testing in CI/CD pipelines, configure Policy what-if validation, enable Defender for DevOps, implement drift detection",
                "azure_well_architected": "Follows Azure WAF operational excellence for IaC testing and DevSecOps practices",
                "compliance_mapping": "Addresses NIST controls ca-7, cm-2, cm-6, si-7.7"
            }
        }
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """
        Get specific Azure queries for collecting KSI-MLA-05 evidence.
        """
        return {
            "ksi_id": "KSI-MLA-05",
            "queries": [
                {
                    "name": "IaC Pipeline Test Results",
                    "type": "azure_devops_api",
                    "endpoint": "https://dev.azure.com/{org}/{project}/_apis/test/runs?api-version=7.1",
                    "method": "GET",
                    "purpose": "Retrieve test execution results for IaC validation",
                    "expected_result": "Test runs showing IaC validation with high pass rate"
                },
                {
                    "name": "Policy What-If Deployment Results",
                    "type": "azure_rest_api",
                    "endpoint": "/subscriptions/{subscriptionId}/providers/Microsoft.Resources/deployments/{deploymentName}/whatIf?api-version=2021-04-01",
                    "method": "POST",
                    "purpose": "Show policy validation before deployment",
                    "expected_result": "What-if analysis with policy compliance validation"
                },
                {
                    "name": "IaC Security Scan Findings",
                    "type": "github_api",
                    "endpoint": "/repos/{owner}/{repo}/code-scanning/alerts",
                    "method": "GET",
                    "purpose": "Retrieve security findings from IaC template scanning",
                    "expected_result": "Security scan results showing IaC template validation"
                },
                {
                    "name": "Configuration Drift Detection",
                    "type": "kql",
                    "workspace": "Log Analytics workspace with change tracking",
                    "query": """
                        ConfigurationChange
                        | where TimeGenerated > ago(7d)
                        | where ConfigChangeType == 'Files' or ConfigChangeType == 'Software'
                        | summarize ChangeCount = count() by Computer, ConfigChangeType
                        | where ChangeCount > 0
                        """,
                    "purpose": "Detect configuration drift from IaC baseline",
                    "expected_result": "Minimal drift with documented exceptions"
                },
                {
                    "name": "Deployment Validation History",
                    "type": "azure_rest_api",
                    "endpoint": "/subscriptions/{subscriptionId}/providers/Microsoft.Resources/deployments?api-version=2021-04-01",
                    "method": "GET",
                    "purpose": "Show deployment validation and pre-flight checks",
                    "expected_result": "Successful validation before deployments"
                }
            ],
            "query_execution_guidance": {
                "authentication": "Use Azure CLI or Managed Identity",
                "permissions_required": [
                    "DevOps Project Reader for test results",
                    "Policy Reader for what-if analysis",
                    "GitHub read:security_events for security scanning",
                    "Log Analytics Reader for drift detection"
                ],
                "automation_tools": [
                    "Azure CLI (az deployment, az policy)",
                    "PowerShell Az.Resources module",
                    "GitHub CLI for security scanning results"
                ]
            }
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """
        Get descriptions of evidence artifacts for KSI-MLA-05.
        """
        return {
            "ksi_id": "KSI-MLA-05",
            "artifacts": [
                {
                    "name": "IaC Test Execution Reports",
                    "description": "Pipeline test results showing IaC validation testing (unit, integration, security)",
                    "source": "Azure DevOps test results or GitHub Actions",
                    "format": "JUnit XML or JSON test results",
                    "collection_frequency": "Per deployment",
                    "retention_period": "1 year",
                    "automation": "Pipeline artifacts with test results"
                },
                {
                    "name": "Policy Validation Reports",
                    "description": "What-if deployment analysis and policy compliance checks",
                    "source": "Azure Policy what-if API",
                    "format": "JSON what-if results",
                    "collection_frequency": "Per deployment",
                    "retention_period": "1 year",
                    "automation": "Pipeline stage output"
                },
                {
                    "name": "IaC Security Scan Results",
                    "description": "Security scanning results for Bicep/Terraform templates",
                    "source": "Defender for DevOps or GitHub Advanced Security",
                    "format": "SARIF format scan results",
                    "collection_frequency": "Per commit",
                    "retention_period": "1 year",
                    "automation": "CI pipeline integration"
                },
                {
                    "name": "Configuration Drift Report",
                    "description": "Detected drift from IaC baseline with remediation tracking",
                    "source": "Terraform state diff or Azure Resource Graph",
                    "format": "CSV or JSON drift report",
                    "collection_frequency": "Daily",
                    "retention_period": "1 year",
                    "automation": "Scheduled drift detection job"
                },
                {
                    "name": "Deployment Validation Evidence",
                    "description": "Pre-flight validation results and deployment history",
                    "source": "Azure Resource Manager deployment logs",
                    "format": "JSON deployment results",
                    "collection_frequency": "Per deployment",
                    "retention_period": "3 years",
                    "automation": "ARM deployment API query"
                }
            ],
            "artifact_storage": {
                "primary": "Azure Blob Storage with immutable storage",
                "backup": "Azure Backup with GRS replication",
                "access_control": "Azure RBAC with audit trail"
            },
            "compliance_mapping": {
                "fedramp_controls": ["ca-7", "cm-2", "cm-6", "si-7.7"],
                "evidence_purpose": "Demonstrate IaC is tested, validated, and monitored for drift"
            }
        }


def get_factory():
    """Get KSI analyzer factory instance."""
    from .factory import KSIAnalyzerFactory
    return KSIAnalyzerFactory()

