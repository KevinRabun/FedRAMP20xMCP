"""
KSI-CMT-03: Automated Testing and Validation

Automate persistent testing and validation of changes throughout deployment.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import ast
import re
from typing import List, Dict, Any
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
    NIST_CONTROLS = [
        ("cm-3", "Configuration Change Control"),
        ("cm-3.2", "Testing, Validation, and Documentation of Changes"),
        ("cm-4.2", "Verification of Controls"),
        ("si-2", "Flaw Remediation")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
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
        Analyze Python code for KSI-CMT-03 compliance using AST.
        
        Frameworks: Flask, Django, FastAPI, pytest, unittest
        
        Detects:
        - Missing test files/functions
        - Missing test assertions
        - Missing test frameworks (pytest, unittest)
        """
        findings = []
        lines = code.split('\n')
        
        # Check if this is a test file
        is_test_file = bool(re.search(r'(test_.*\.py|.*_test\.py|tests/)', file_path, re.IGNORECASE))
        
        try:
            tree = ast.parse(code)
        except SyntaxError:
            # Fallback to regex if AST parsing fails
            return self._python_regex_fallback(code, lines, file_path, is_test_file)
        
        if is_test_file:
            # Check for test framework imports using AST
            has_test_framework = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        if alias.name in ('pytest', 'unittest'):
                            has_test_framework = True
                            break
                elif isinstance(node, ast.ImportFrom):
                    if node.module in ('pytest', 'unittest'):
                        has_test_framework = True
                        break
            
            if not has_test_framework:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Test File Without Testing Framework",
                    description=(
                        f"Test file '{file_path}' does not import pytest or unittest. "
                        f"KSI-CMT-03 requires automated testing framework (CM-3, CM-4.2, SI-2) - "
                        f"proper test frameworks enable persistent validation of changes."
                    ),
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    remediation=(
                        "Import a test framework:\n\n"
                        "import pytest\n"
                        "# or\n"
                        "import unittest\n\n"
                        "class TestMyFeature(unittest.TestCase):\n"
                        "    def test_something(self):\n"
                        "        assert True"
                    )
                ))
            
            # Check for test functions/classes using AST
            test_functions = []
            test_classes = []
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    if node.name.startswith('test_'):
                        test_functions.append((node.name, node.lineno))
                elif isinstance(node, ast.ClassDef):
                    if node.name.startswith('Test'):
                        test_classes.append((node.name, node.lineno))
            
            if not test_functions and not test_classes:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Test Functions Found",
                    description=(
                        f"Test file '{file_path}' does not contain test functions or classes. "
                        f"KSI-CMT-03 requires automated testing (CM-3, CM-4.2) - "
                        f"add test_* functions or Test* classes to validate changes."
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    remediation=(
                        "Add test functions:\n\n"
                        "def test_user_authentication():\n"
                        "    user = authenticate('user@example.com', 'password')\n"
                        "    assert user is not None\n"
                        "    assert user.is_authenticated\n\n"
                        "def test_data_validation():\n"
                        "    result = validate_input('test data')\n"
                        "    assert result.is_valid"
                    )
                ))
            
            # Check for assertions using AST
            has_assertions = False
            for node in ast.walk(tree):
                if isinstance(node, ast.Assert):
                    has_assertions = True
                    break
                # Also check for unittest assertions (self.assert*)
                elif isinstance(node, ast.Expr):
                    if isinstance(node.value, ast.Call):
                        if isinstance(node.value.func, ast.Attribute):
                            if node.value.func.attr.startswith('assert'):
                                has_assertions = True
                                break
            
            if not has_assertions and (test_functions or test_classes):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Test Function Without Assertions",
                    description=(
                        f"Test file '{file_path}' contains test functions but no assertions. "
                        f"KSI-CMT-03 requires validation of expected behavior (CM-3.2, SI-2) - "
                        f"tests must include assertions to verify correctness."
                    ),
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=test_functions[0][1] if test_functions else test_classes[0][1],
                    code_snippet=self._get_snippet(lines, test_functions[0][1] if test_functions else test_classes[0][1]),
                    remediation=(
                        "Add assertions to validate behavior:\n\n"
                        "def test_calculation():\n"
                        "    result = calculate(2, 3)\n"
                        "    assert result == 5, 'Expected 2 + 3 = 5'\n\n"
                        "def test_error_handling():\n"
                        "    with pytest.raises(ValueError):\n"
                        "        process_invalid_input('')"
                    )
                ))
        else:
            # For non-test files, provide informational guidance
            if not re.search(r'test', file_path, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Consider Adding Test Coverage",
                    description=(
                        f"Source file '{file_path}' may need test coverage. "
                        f"KSI-CMT-03 requires persistent testing and validation (CM-3, CM-4.2, SI-2)."
                    ),
                    severity=Severity.INFO,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="",
                    remediation=(
                        f"Create a corresponding test file (e.g., test_{file_path.split('/')[-1]}) with comprehensive tests:\n\n"
                        "# tests/test_module.py\n"
                        "import pytest\n"
                        "from module import function_to_test\n\n"
                        "def test_function_success():\n"
                        "    result = function_to_test('valid input')\n"
                        "    assert result is not None\n\n"
                        "def test_function_error_handling():\n"
                        "    with pytest.raises(ValueError):\n"
                        "        function_to_test('invalid input')\n\n"
                        "Run tests with coverage: pytest --cov=. --cov-report=html"
                    )
                ))
        
        return findings
    
    def _python_regex_fallback(self, code: str, lines: List[str], file_path: str, is_test_file: bool) -> List[Finding]:
        """Fallback regex-based analysis when AST parsing fails."""
        findings = []
        
        if is_test_file:
            # Verify test framework imports
            has_test_framework = bool(re.search(r'(import pytest|import unittest|from unittest|from pytest)', code, re.IGNORECASE))
            if not has_test_framework:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing Test Framework Import (Regex Fallback)",
                    description=f"Test file '{file_path}' does not import pytest or unittest.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="Import a test framework: import pytest or import unittest"
                ))
            
            # Check for test functions/methods
            has_test_functions = bool(re.search(r'(def test_|class Test)', code, re.IGNORECASE))
            if not has_test_functions:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="No Test Functions Found (Regex Fallback)",
                    description=f"Test file '{file_path}' does not contain test functions.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="Add test functions starting with test_ or Test classes"
                ))
            
            # Check for assertions
            has_assertions = bool(re.search(r'(assert |self\.assert)', code, re.IGNORECASE))
            if not has_assertions:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Missing Test Assertions (Regex Fallback)",
                    description=f"Test file '{file_path}' does not contain assertions.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=0,
                    code_snippet="",
                    remediation="Add assertions to validate behavior"
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
                    title="Test File Without Testing Framework",
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
            # Only check for test methods if framework is present
            elif has_test_framework:
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
                    title="Test Function Without Assertions",
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
                    title="Test File Without Testing Framework",
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
            # Only check for test methods if framework is present
            elif has_test_framework:
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
                    title="Test Function Without Assertions",
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
            # Check for test framework imports (not just usage)
            has_test_framework = bool(re.search(r'(from [\'"]jest|from [\'"]mocha|from [\'"]@testing-library|from [\'"]chai|from [\'"]vitest|import .* from [\'"]jest|import .* from [\'"]mocha)', code, re.IGNORECASE))
            if not has_test_framework:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Test File Without Testing Framework",
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
            
            # Only check for test blocks if framework is present
            elif has_test_framework:
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
                else:
                    # Use AST to find individual test blocks and check for assertions
                    from fedramp_20x_mcp.analyzers.ast_utils import ASTParser, CodeLanguage
                    
                    try:
                        parser = ASTParser(CodeLanguage.JAVASCRIPT)
                        tree = parser.parse(code)
                        
                        # Find all call expressions that might be test blocks
                        call_expressions = parser.find_nodes_by_type(tree.root_node, "call_expression")
                        
                        code_bytes = code.encode('utf8')
                        for call_expr in call_expressions:
                            # Get the function being called
                            identifier_node = None
                            for child in call_expr.children:
                                if child.type == "identifier":
                                    identifier_node = child
                                    break
                            
                            if identifier_node:
                                func_name = parser.get_node_text(identifier_node, code_bytes)
                                
                                # Check if it's a test block (describe, it, test)
                                if func_name in ['describe', 'it', 'test']:
                                    # Get the function body (arrow function or regular function)
                                    has_assertions_in_block = False
                                    block_code = parser.get_node_text(call_expr, code_bytes)
                                    
                                    # Check for assertions in this specific block
                                    if re.search(r'(expect\(|assert\(|should\.)', block_code, re.IGNORECASE):
                                        has_assertions_in_block = True
                                    
                                    if not has_assertions_in_block:
                                        line_num = call_expr.start_point[0] + 1
                                        findings.append(Finding(
                                            ksi_id=self.KSI_ID,
                                            title="Test Function Without Assertions",
                                            description=f"Test block '{func_name}' at line {line_num} does not contain assertions. Tests must validate expected behavior.",
                                            severity=Severity.HIGH,
                                            file_path=file_path,
                                            line_number=line_num,
                                            code_snippet=block_code[:100] + "..." if len(block_code) > 100 else block_code,
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
                    except Exception:
                        # Fallback to regex if AST parsing fails
                        has_assertions = bool(re.search(r'(expect\(|assert\(|should\.)', code, re.IGNORECASE))
                        if not has_assertions:
                            findings.append(Finding(
                                ksi_id=self.KSI_ID,
                                title="Test Function Without Assertions",
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
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-CMT-03.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Automated Testing and Validation",
            "evidence_type": "log-based",
            "automation_feasibility": "high",
            "azure_services": [
                "Azure DevOps Test Plans",
                "Azure Pipelines",
                "Azure Monitor",
                "Microsoft Defender for Cloud",
                "Azure Application Insights"
            ],
            "collection_methods": [
                "Azure DevOps Test Plans to track test execution history with pass/fail rates and code coverage metrics",
                "Azure Pipelines test results publishing to aggregate unit, integration, and security test outcomes",
                "Azure Monitor Application Insights to track runtime validation and performance regression tests",
                "Microsoft Defender for Cloud DevOps security scanning results (SAST, dependency scanning, secret detection)",
                "Azure Artifacts to store and version test reports, coverage reports, and validation artifacts"
            ],
            "implementation_steps": [
                "1. Configure Azure Pipelines with comprehensive test stages: (a) Unit tests (pytest, jest, xunit) with code coverage >= 80%, (b) Integration tests against Azure Test environment, (c) Security tests (SAST, dependency scanning, secret detection), (d) Performance regression tests with Application Insights",
                "2. Enable Azure DevOps Test Plans reporting: (a) Publish test results to Test Plans after every pipeline run, (b) Track test pass rates, code coverage trends, and flaky tests, (c) Link test cases to user stories/requirements, (d) Generate monthly test execution reports",
                "3. Integrate Microsoft Defender for DevOps: (a) Enable GitHub Advanced Security or Azure DevOps security scanning, (b) Configure SAST with Semgrep/CodeQL, (c) Enable dependency scanning with OWASP Dependency-Check, (d) Configure secret scanning with TruffleHog/Gitleaks, (e) Fail pipelines on HIGH/CRITICAL findings",
                "4. Configure Azure Application Insights for runtime validation: (a) Synthetic monitoring with availability tests, (b) Performance regression detection with baseline metrics, (c) Custom validation metrics tracking business logic correctness, (d) Alert on validation failures",
                "5. Build Azure Monitor workbook 'Testing and Validation Dashboard': (a) Test pass rate trends by pipeline and test type, (b) Code coverage trends over time, (c) Security scanning results (SAST, dependency, secret findings), (d) Performance regression detection, (e) Test execution duration and flakiness",
                "6. Generate monthly evidence package: (a) Export Azure DevOps test execution logs with pass/fail details, (b) Export code coverage reports from Azure Artifacts, (c) Export Defender for DevOps scanning results, (d) Export Application Insights validation metrics"
            ],
            "evidence_artifacts": [
                "Azure DevOps Test Execution Logs showing automated test results (unit, integration, security) with pass/fail rates",
                "Code Coverage Reports from Azure Pipelines demonstrating >= 80% coverage requirement for critical code paths",
                "Microsoft Defender for DevOps Scanning Results including SAST, dependency scanning, and secret detection findings",
                "Azure Application Insights Runtime Validation Metrics tracking synthetic monitoring and performance regression tests",
                "Testing and Validation Dashboard from Azure Monitor with monthly snapshots of test quality and security scanning coverage"
            ],
            "update_frequency": "monthly",
            "responsible_party": "DevOps Team / Quality Assurance Team"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "Azure DevOps REST API",
                "query_name": "Test execution history with pass/fail rates",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/test/runs?api-version=7.0&includeRunDetails=true&$top=100",
                "purpose": "Retrieve test execution history from Azure DevOps Test Plans showing automated test results and trends"
            },
            {
                "query_type": "Azure DevOps REST API",
                "query_name": "Code coverage trends from pipelines",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/test/codecoverage?api-version=7.0-preview.1&buildId={buildId}",
                "purpose": "Retrieve code coverage metrics from Azure Pipelines to demonstrate testing thoroughness (target >= 80%)"
            },
            {
                "query_type": "Microsoft Defender for Cloud REST API",
                "query_name": "DevOps security scanning results (SAST, dependencies, secrets)",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/securityConnectors?api-version=2023-03-01",
                "purpose": "Retrieve Defender for DevOps scanning results including SAST, dependency scanning, and secret detection"
            },
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "Application Insights runtime validation and performance tests",
                "query": """availabilityResults
| where timestamp > ago(30d)
| extend TestName = name, Success = tostring(success), Duration = duration
| summarize TotalTests = count(), PassedTests = countif(Success == 'True'), AvgDuration = avg(Duration), MaxDuration = max(Duration) by TestName
| extend PassRate = round((todouble(PassedTests) / TotalTests) * 100, 2)
| order by PassRate asc, TotalTests desc""",
                "purpose": "Track synthetic monitoring and runtime validation tests from Application Insights to ensure persistent validation"
            },
            {
                "query_type": "Azure Pipelines REST API",
                "query_name": "Pipeline test results aggregation",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/build/builds/{buildId}/Timeline?api-version=7.0",
                "purpose": "Aggregate test results from pipeline runs including unit, integration, and security test outcomes"
            }
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        """
        Get descriptions of evidence artifacts to collect.
        
        Returns:
            List of artifact dictionaries
        """
        return [
            {
                "artifact_name": "Azure DevOps Test Execution Report",
                "artifact_type": "Test Plans Export",
                "description": "Comprehensive test execution logs showing automated test results (unit, integration, security) with pass/fail rates and trends",
                "collection_method": "Azure DevOps REST API to retrieve test runs and aggregate pass/fail statistics by test type",
                "storage_location": "Azure DevOps Test Plans with monthly reports exported to Azure Storage Account"
            },
            {
                "artifact_name": "Code Coverage Trend Report",
                "artifact_type": "Pipeline Artifacts",
                "description": "Code coverage metrics from Azure Pipelines demonstrating >= 80% coverage for critical code paths",
                "collection_method": "Azure DevOps REST API to retrieve code coverage data from pipeline builds and track trends",
                "storage_location": "Azure Artifacts with coverage reports published as pipeline artifacts and archived monthly"
            },
            {
                "artifact_name": "Defender for DevOps Security Scanning Report",
                "artifact_type": "Security Scan Results",
                "description": "Aggregated security scanning results including SAST findings, dependency vulnerabilities, and secrets detected",
                "collection_method": "Microsoft Defender for Cloud REST API to export DevOps security scanning results by repository",
                "storage_location": "Azure Storage Account with JSON exports organized by severity (CRITICAL, HIGH, MEDIUM, LOW)"
            },
            {
                "artifact_name": "Application Insights Validation Metrics",
                "artifact_type": "Azure Monitor Logs",
                "description": "Runtime validation metrics including synthetic monitoring results and performance regression test data",
                "collection_method": "Azure Monitor KQL query retrieving availability results and custom validation metrics from Application Insights",
                "storage_location": "Azure Log Analytics workspace with 12-month retention and alerting for validation failures"
            },
            {
                "artifact_name": "Testing and Validation Dashboard",
                "artifact_type": "Azure Monitor Workbook",
                "description": "Comprehensive dashboard showing test pass rates, code coverage trends, security scanning results, and runtime validation metrics",
                "collection_method": "Azure Monitor workbook aggregating data from DevOps, Defender, and Application Insights",
                "storage_location": "Azure Monitor Workbooks with monthly PDF snapshots archived for compliance auditing"
            }
        ]

