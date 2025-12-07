"""
KSI-CMT-03: Automated Testing and Validation

Automate persistent testing and validation of changes throughout deployment.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CMT_03_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CMT-03: Automated Testing and Validation
    
    **Official Statement:**
    Automate persistent testing and validation of changes throughout deployment.
    
    **Family:** CMT - Change Management
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cm-3
    - cm-3.2
    - cm-4.2
    - si-2
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Automate persistent testing and validation of changes throughout deployment....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CMT-03"
    KSI_NAME = "Automated Testing and Validation"
    KSI_STATEMENT = """Automate persistent testing and validation of changes throughout deployment."""
    FAMILY = "CMT"
    FAMILY_NAME = "Change Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["cm-3", "cm-3.2", "cm-4.2", "si-2"]
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
        Analyze Python code for KSI-CMT-03 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Missing test files/functions
        - Missing test assertions
        - Missing test frameworks (pytest, unittest)
        """
        findings = []
        lines = code.split('\n')
        
        # Check if this is a test file
        is_test_file = bool(re.search(r'(test_.*\.py|.*_test\.py|tests/)', file_path, re.IGNORECASE))
        
        if is_test_file:
            # Verify test framework imports
            has_test_framework = bool(re.search(r'(import pytest|import unittest|from unittest|from pytest)', code, re.IGNORECASE))
            if not has_test_framework:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing Test Framework Import",
                    description=f"Test file '{file_path}' does not import pytest or unittest. KSI-CMT-03 requires automated testing framework.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="""Import a test framework:

```python
import pytest
# or
import unittest

class TestMyFeature(unittest.TestCase):
    def test_something(self):
        assert True
```"""
                ))
            
            # Check for test functions/methods
            has_test_functions = bool(re.search(r'(def test_|class Test)', code, re.IGNORECASE))
            if not has_test_functions:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Test Functions Found",
                    description=f"Test file '{file_path}' does not contain test functions. Add test_* functions or Test* classes.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="""Add test functions:

```python
def test_user_authentication():
    user = authenticate("user@example.com", "password")
    assert user is not None
    assert user.is_authenticated

def test_data_validation():
    result = validate_input("test data")
    assert result.is_valid
```"""
                ))
            
            # Check for assertions
            has_assertions = bool(re.search(r'(assert |self\.assert)', code, re.IGNORECASE))
            if not has_assertions:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing Test Assertions",
                    description=f"Test file '{file_path}' does not contain assertions. Tests must validate expected behavior.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="""Add assertions to validate behavior:

```python
def test_calculation():
    result = calculate(2, 3)
    assert result == 5, "Expected 2 + 3 = 5"
    
def test_error_handling():
    with pytest.raises(ValueError):
        process_invalid_input("")
```"""
                ))
        else:
            # For non-test files, check if there's a corresponding test file mentioned
            # This is informational only
            if not re.search(r'test', file_path, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Consider Adding Test Coverage",
                    description=f"Source file '{file_path}' may need test coverage. KSI-CMT-03 requires persistent testing and validation.",
                    severity=Severity.INFO,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation=f"""Create a corresponding test file (e.g., test_{file_path.split('/')[-1]}) with comprehensive tests:

```python
# tests/test_module.py
import pytest
from module import function_to_test

def test_function_success():
    result = function_to_test("valid input")
    assert result is not None

def test_function_error_handling():
    with pytest.raises(ValueError):
        function_to_test("invalid input")
```

Run tests with coverage: `pytest --cov=. --cov-report=html`"""
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-CMT-03 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Missing test attributes ([Test], [Fact])
        - Missing test frameworks (xUnit, NUnit, MSTest)
        - Missing assertions
        """
        findings = []
        lines = code.split('\n')
        
        # Check if this is a test file
        is_test_file = bool(re.search(r'(Tests?\.cs|Test\.cs|\.Tests\\)', file_path, re.IGNORECASE))
        
        if is_test_file:
            # Check for test framework using statements
            has_test_framework = bool(re.search(r'(using Xunit|using NUnit|using Microsoft\.VisualStudio\.TestTools\.UnitTesting)', code, re.IGNORECASE))
            if not has_test_framework:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing Test Framework Reference",
                    description=f"Test file '{file_path}' does not reference xUnit, NUnit, or MSTest. KSI-CMT-03 requires automated testing framework.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="""Add test framework reference:

```csharp
using Xunit;  // or using NUnit.Framework; or using Microsoft.VisualStudio.TestTools.UnitTesting;

public class UserServiceTests
{
    [Fact]
    public void AuthenticateUser_ValidCredentials_ReturnsUser()
    {
        // Arrange, Act, Assert
    }
}
```"""
                ))
            
            # Check for test attributes
            has_test_attributes = bool(re.search(r'(\[Fact\]|\[Test\]|\[TestMethod\])', code, re.IGNORECASE))
            if not has_test_attributes:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Test Methods Found",
                    description=f"Test file '{file_path}' does not contain test method attributes. Add [Fact], [Test], or [TestMethod] attributes.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="""Add test methods with attributes:

```csharp
[Fact]
public void CalculateTotal_ValidInput_ReturnsCorrectSum()
{
    var result = Calculator.Add(2, 3);
    Assert.Equal(5, result);
}

[Theory]
[InlineData(2, 3, 5)]
[InlineData(0, 0, 0)]
public void Add_VariousInputs_ReturnsExpectedResult(int a, int b, int expected)
{
    var result = Calculator.Add(a, b);
    Assert.Equal(expected, result);
}
```"""
                ))
            
            # Check for assertions
            has_assertions = bool(re.search(r'(Assert\.|Should\.)', code, re.IGNORECASE))
            if not has_assertions:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing Test Assertions",
                    description=f"Test file '{file_path}' does not contain assertions. Tests must validate expected behavior.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="""Add assertions to validate behavior:

```csharp
[Fact]
public void ProcessData_ValidInput_ReturnsSuccess()
{
    var result = service.ProcessData("test");
    Assert.NotNull(result);
    Assert.True(result.IsSuccess);
}

[Fact]
public void ValidateInput_InvalidData_ThrowsException()
{
    Assert.Throws<ArgumentException>(() => service.ValidateInput(""));
}
```"""
                ))
        else:
            # For non-test files, suggest test coverage
            if not re.search(r'test', file_path, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Consider Adding Test Coverage",
                    description=f"Source file '{file_path}' may need test coverage. KSI-CMT-03 requires persistent testing and validation.",
                    severity=Severity.INFO,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation=f"""Create a corresponding test project with xUnit:

```csharp
// {file_path.replace('.cs', 'Tests.cs')}
using Xunit;

public class ModuleTests
{{
    [Fact]
    public void Method_ValidInput_ReturnsExpectedResult()
    {{
        // Arrange
        var service = new Service();
        
        // Act
        var result = service.Method("test");
        
        // Assert
        Assert.NotNull(result);
    }}
}}
```

Run tests with coverage: `dotnet test --collect:"XPlat Code Coverage"`"""
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CMT-03 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Missing JUnit/TestNG annotations
        - Missing test frameworks
        - Missing assertions
        """
        findings = []
        lines = code.split('\n')
        
        # Check if this is a test file
        is_test_file = bool(re.search(r'(Test\.java|Tests\.java|src/test/)', file_path, re.IGNORECASE))
        
        if is_test_file:
            # Check for test framework imports
            has_test_framework = bool(re.search(r'(import org\.junit|import org\.testng|@Test)', code, re.IGNORECASE))
            if not has_test_framework:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing Test Framework Import",
                    description=f"Test file '{file_path}' does not import JUnit or TestNG. KSI-CMT-03 requires automated testing framework.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="""Add test framework import:

```java
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;
// or
import org.testng.annotations.Test;
import org.testng.Assert;

public class UserServiceTest {
    @Test
    public void testAuthenticateUser() {
        // Test implementation
    }
}
```"""
                ))
            
            # Check for @Test annotations
            has_test_annotations = bool(re.search(r'@Test', code))
            if not has_test_annotations:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Test Methods Found",
                    description=f"Test file '{file_path}' does not contain @Test annotations. Add test methods with @Test.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="""Add test methods with @Test annotation:

```java
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class CalculatorTest {
    @Test
    public void testAddition() {
        assertEquals(5, Calculator.add(2, 3));
    }
    
    @Test
    public void testInvalidInput() {
        assertThrows(IllegalArgumentException.class, () -> {
            Calculator.divide(10, 0);
        });
    }
}
```"""
                ))
            
            # Check for assertions
            has_assertions = bool(re.search(r'(assert(Equals|True|False|NotNull|Throws)|Assert\.)', code, re.IGNORECASE))
            if not has_assertions:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing Test Assertions",
                    description=f"Test file '{file_path}' does not contain assertions. Tests must validate expected behavior.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="""Add assertions to validate behavior:

```java
@Test
public void testUserCreation() {
    User user = userService.createUser("test@example.com");
    assertNotNull(user);
    assertEquals("test@example.com", user.getEmail());
    assertTrue(user.isActive());
}
```"""
                ))
        else:
            # For non-test files, suggest test coverage
            if not re.search(r'test', file_path, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Consider Adding Test Coverage",
                    description=f"Source file '{file_path}' may need test coverage. KSI-CMT-03 requires persistent testing and validation.",
                    severity=Severity.INFO,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation=f"""Create a corresponding test class in src/test/java:

```java
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class ModuleTest {{
    @Test
    public void testMethod_ValidInput_ReturnsExpected() {{
        // Arrange
        var service = new Service();
        
        // Act
        var result = service.process("test");
        
        // Assert
        assertNotNull(result);
        assertTrue(result.isValid());
    }}
}}
```

Run tests with coverage: `mvn test jacoco:report`"""
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CMT-03 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Missing test frameworks (Jest, Mocha, Jasmine)
        - Missing test blocks (describe, it, test)
        - Missing assertions (expect, assert)
        """
        findings = []
        lines = code.split('\n')
        
        # Check if this is a test file
        is_test_file = bool(re.search(r'(\.test\.(ts|js|tsx|jsx)|\.spec\.(ts|js|tsx|jsx)|__tests__/)', file_path, re.IGNORECASE))
        
        if is_test_file:
            # Check for test framework imports
            has_test_framework = bool(re.search(r'(from [\'"]jest|from [\'"]mocha|from [\'"]@testing-library|from [\'"]chai|describe\(|it\(|test\()', code, re.IGNORECASE))
            if not has_test_framework:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing Test Framework",
                    description=f"Test file '{file_path}' does not use Jest, Mocha, or another test framework. KSI-CMT-03 requires automated testing.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="""Add test framework usage:

```typescript
import { describe, it, expect } from '@jest/globals';
// or
import { expect } from 'chai';
import { describe, it } from 'mocha';

describe('UserService', () => {
    it('should authenticate valid user', () => {
        // Test implementation
    });
});
```"""
                ))
            
            # Check for test blocks
            has_test_blocks = bool(re.search(r'(describe\(|it\(|test\()', code))
            if not has_test_blocks:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Test Blocks Found",
                    description=f"Test file '{file_path}' does not contain test blocks (describe/it/test). Add test cases.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="""Add test blocks:

```typescript
describe('Calculator', () => {
    test('adds two numbers correctly', () => {
        expect(add(2, 3)).toBe(5);
    });
    
    it('should throw error for invalid input', () => {
        expect(() => divide(10, 0)).toThrow();
    });
});
```"""
                ))
            
            # Check for assertions
            has_assertions = bool(re.search(r'(expect\(|assert\(|should\.)', code, re.IGNORECASE))
            if not has_assertions:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing Test Assertions",
                    description=f"Test file '{file_path}' does not contain assertions. Tests must validate expected behavior.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="""Add assertions to validate behavior:

```typescript
test('user creation', async () => {
    const user = await createUser('test@example.com');
    expect(user).toBeDefined();
    expect(user.email).toBe('test@example.com');
    expect(user.isActive).toBe(true);
});

test('error handling', async () => {
    await expect(createUser('')).rejects.toThrow('Invalid email');
});
```"""
                ))
        else:
            # For non-test files, suggest test coverage
            if not re.search(r'(test|spec)', file_path, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Consider Adding Test Coverage",
                    description=f"Source file '{file_path}' may need test coverage. KSI-CMT-03 requires persistent testing and validation.",
                    severity=Severity.INFO,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation=f"""Create a corresponding test file (e.g., {file_path.replace('.ts', '.test.ts').replace('.js', '.test.js')}):

```typescript
import {{ describe, it, expect }} from '@jest/globals';
import {{ functionToTest }} from './module';

describe('Module', () => {{
    it('should process valid input', () => {{
        const result = functionToTest('test');
        expect(result).toBeDefined();
    }});
    
    it('should handle errors', () => {{
        expect(() => functionToTest('')).toThrow();
    }});
}});
```

Run tests with coverage: `npm test -- --coverage`"""
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CMT-03 compliance.
        
        Detects:
        - Missing test resources (Container Instances for testing)
        - Missing validation/testing infrastructure
        
        Note: IaC testing is primarily done via CI/CD pipelines.
        """
        findings = []
        
        # Check for test-related infrastructure
        has_test_infra = bool(re.search(r'(Microsoft\.ContainerInstance|Microsoft\.DevTestLab|test|validation)', code, re.IGNORECASE))
        
        if not has_test_infra:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Consider Adding Test Infrastructure",
                description=f"Bicep template '{file_path}' does not include test or validation infrastructure. KSI-CMT-03 recommends automated testing infrastructure.",
                severity=Severity.INFO,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Consider adding test infrastructure resources:

```bicep
// Container Instance for running automated tests
resource testRunner 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: 'test-runner'
  location: location
  properties: {
    containers: [
      {
        name: 'test-container'
        properties: {
          image: 'mcr.microsoft.com/azure-cli'
          command: ['/bin/bash', '-c', 'pytest --cov=.']
          resources: {
            requests: {
              cpu: 1
              memoryInGB: 2
            }
          }
        }
      }
    ]
    osType: 'Linux'
  }
  tags: {
    purpose: 'automated-testing'
  }
}
```

Note: Primary testing validation should be in CI/CD pipelines (see analyze_github_actions, analyze_azure_pipelines)."""
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CMT-03 compliance.
        
        Detects:
        - Missing test/validation infrastructure
        
        Note: IaC testing is primarily done via CI/CD pipelines.
        """
        findings = []
        
        # Check for test-related infrastructure
        has_test_infra = bool(re.search(r'(azurerm_container_group|azurerm_dev_test|test|validation)', code, re.IGNORECASE))
        
        if not has_test_infra:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Consider Adding Test Infrastructure",
                description=f"Terraform configuration '{file_path}' does not include test or validation infrastructure. KSI-CMT-03 recommends automated testing infrastructure.",
                severity=Severity.INFO,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Consider adding test infrastructure resources:

```hcl
resource "azurerm_container_group" "test_runner" {
  name                = "test-runner"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  os_type             = "Linux"

  container {
    name   = "test-container"
    image  = "mcr.microsoft.com/azure-cli"
    cpu    = "1"
    memory = "2"

    commands = ["/bin/bash", "-c", "pytest --cov=."]
  }

  tags = {
    purpose = "automated-testing"
  }
}
```

Note: Primary testing validation should be in CI/CD pipelines (see analyze_github_actions, analyze_azure_pipelines)."""
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CMT-03 compliance.
        
        Detects:
        - Missing test automation steps
        - Missing code coverage validation
        - Missing security scanning steps
        - Missing automated validation
        """
        findings = []
        lines = code.split('\n')
        
        # Check for test automation
        has_test_step = bool(re.search(r'(run:\s*.*test|pytest|jest|mvn test|dotnet test|npm test)', code, re.IGNORECASE))
        if not has_test_step:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Automated Testing in CI/CD Pipeline",
                description=f"GitHub Actions workflow '{file_path}' does not include automated test execution steps. FedRAMP 20x KSI-CMT-03 requires persistent testing throughout deployment.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add automated testing to your GitHub Actions workflow:

```yaml
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Unit Tests
        run: |
          # Python
          pytest --cov=. --cov-report=xml
          # .NET
          dotnet test --collect:"XPlat Code Coverage"
          # Java
          mvn test
          # Node.js
          npm test -- --coverage
      
      - name: Upload Coverage Reports
        uses: codecov/codecov-action@v3
        with:
          files: ./coverage.xml
```

Reference: FRR-CMT-03 - Automated Testing and Validation"""
            ))
        
        # Check for code coverage validation
        has_coverage = bool(re.search(r'(coverage|codecov|coveralls|--cov)', code, re.IGNORECASE))
        if not has_coverage:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Code Coverage Validation",
                description=f"GitHub Actions workflow '{file_path}' does not validate code coverage. Automated testing should include coverage metrics per KSI-CMT-03.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add code coverage validation:

```yaml
- name: Check Code Coverage
  run: |
    pytest --cov=. --cov-report=term --cov-fail-under=80
    
- name: Upload Coverage to Codecov
  uses: codecov/codecov-action@v3
  with:
    fail_ci_if_error: true
```"""
            ))
        
        # Check for security scanning
        has_security_scan = bool(re.search(r'(snyk|trivy|bandit|safety|owasp|dependency-check|semgrep)', code, re.IGNORECASE))
        if not has_security_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Automated Security Scanning",
                description=f"GitHub Actions workflow '{file_path}' does not include automated security scanning. FedRAMP 20x requires persistent validation including security checks.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add security scanning steps:

```yaml
- name: Run Security Scan (Python)
  run: |
    pip install bandit safety
    bandit -r . -f json -o bandit-report.json
    safety check --json > safety-report.json

- name: Run Security Scan (Node.js)
  run: npm audit

- name: Run Security Scan (Containers)
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: 'fs'
    scan-ref: '.'
```"""
            ))
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CMT-03 compliance.
        
        Detects:
        - Missing test tasks
        - Missing code quality gates
        - Missing security validation
        """
        findings = []
        lines = code.split('\n')
        
        # Check for test tasks
        has_test_task = bool(re.search(r'(DotNetCoreCLI@2.*command:\s*test|VSTest@2|Maven@3.*goal:\s*test|Npm@1.*command:\s*test)', code, re.IGNORECASE | re.DOTALL))
        if not has_test_task:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Automated Testing in Azure Pipeline",
                description=f"Azure Pipeline '{file_path}' does not include automated test execution tasks. KSI-CMT-03 requires persistent testing throughout deployment.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add automated testing tasks:

```yaml
- task: DotNetCoreCLI@2
  displayName: 'Run Unit Tests'
  inputs:
    command: 'test'
    projects: '**/*Tests.csproj'
    arguments: '--configuration $(BuildConfiguration) --collect:"XPlat Code Coverage"'
    publishTestResults: true

- task: PublishCodeCoverageResults@1
  inputs:
    codeCoverageTool: 'Cobertura'
    summaryFileLocation: '$(Agent.TempDirectory)/**/coverage.cobertura.xml'
```"""
            ))
        
        # Check for code quality/coverage validation
        has_coverage = bool(re.search(r'(PublishCodeCoverageResults|SonarQube|coverage)', code, re.IGNORECASE))
        if not has_coverage:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Code Coverage Validation",
                description=f"Azure Pipeline '{file_path}' does not validate code coverage. Automated testing should include coverage metrics.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add code coverage publishing:

```yaml
- task: PublishCodeCoverageResults@1
  displayName: 'Publish Code Coverage'
  inputs:
    codeCoverageTool: 'Cobertura'
    summaryFileLocation: '$(System.DefaultWorkingDirectory)/**/coverage.xml'
    failIfCoverageEmpty: true
```"""
            ))
        
        # Check for security scanning
        has_security_scan = bool(re.search(r'(CredScan|Snyk|WhiteSource|SecurityCodeScan|SonarQube)', code, re.IGNORECASE))
        if not has_security_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Automated Security Scanning",
                description=f"Azure Pipeline '{file_path}' does not include security scanning. FedRAMP 20x requires persistent validation including security checks.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add security scanning tasks:

```yaml
- task: SnykSecurityScan@1
  displayName: 'Snyk Security Scan'
  inputs:
    serviceConnectionEndpoint: 'SnykConnection'
    testType: 'app'
    failOnIssues: true

- task: SonarQubePrepare@5
  inputs:
    SonarQube: 'SonarQubeConnection'
    scannerMode: 'MSBuild'
```"""
            ))
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CMT-03 compliance.
        
        Detects:
        - Missing test jobs
        - Missing code quality checks
        - Missing security scanning stages
        """
        findings = []
        lines = code.split('\n')
        
        # Check for test stage/job
        has_test_job = bool(re.search(r'(stage:\s*test|pytest|jest|mvn test|dotnet test|npm test)', code, re.IGNORECASE))
        if not has_test_job:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Automated Testing in GitLab CI",
                description=f"GitLab CI configuration '{file_path}' does not include automated test execution. KSI-CMT-03 requires persistent testing throughout deployment.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add automated testing stage:

```yaml
stages:
  - test
  - build
  - deploy

test:unit:
  stage: test
  script:
    - pytest --cov=. --cov-report=xml --cov-report=term
  coverage: '/(?i)total.*? (100(?:\\.0+)?\\%|[1-9]?\\d(?:\\.\\d+)?\\%)$/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml
```"""
            ))
        
        # Check for code coverage
        has_coverage = bool(re.search(r'(coverage:|--cov|coverage_report)', code, re.IGNORECASE))
        if not has_coverage:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Code Coverage Validation",
                description=f"GitLab CI configuration '{file_path}' does not validate code coverage. Automated testing should include coverage metrics.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add coverage validation:

```yaml
test:coverage:
  stage: test
  script:
    - pytest --cov=. --cov-report=xml --cov-fail-under=80
  coverage: '/TOTAL.*\\s+(\\d+%)$/'
  artifacts:
    reports:
      coverage_report:
        coverage_format: cobertura
        path: coverage.xml
```"""
            ))
        
        # Check for security scanning
        has_security_scan = bool(re.search(r'(security_scan|include:.*Security|dependency_scanning|sast)', code, re.IGNORECASE))
        if not has_security_scan:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Automated Security Scanning",
                description=f"GitLab CI configuration '{file_path}' does not include security scanning. FedRAMP 20x requires persistent validation including security checks.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add security scanning:

```yaml
include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Security/Dependency-Scanning.gitlab-ci.yml
  - template: Security/Secret-Detection.gitlab-ci.yml

security:scan:
  stage: test
  script:
    - bandit -r . -f json -o bandit-report.json
    - safety check --json > safety-report.json
  artifacts:
    reports:
      sast: bandit-report.json
```"""
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
