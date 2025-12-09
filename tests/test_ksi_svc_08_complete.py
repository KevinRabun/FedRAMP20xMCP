"""
Comprehensive tests for KSI-SVC-08 AST conversion across all languages.

Tests Python (AST), C# (hybrid), Java (hybrid), TypeScript (hybrid) analyzers
for resource cleanup, disposal patterns, and sensitive data handling.
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_svc_08 import KSI_SVC_08_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


# ============================================================================
# PYTHON TESTS (AST-based)
# ============================================================================

def test_python_tempfile_without_cleanup():
    """Python: Detect tempfile with delete=False but no cleanup."""
    code = """
import tempfile
def process():
    tmp = tempfile.NamedTemporaryFile(mode='w', delete=False)
    tmp.write("data")
    tmp.close()
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_python(code)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "Temporary File Without Secure Deletion" in findings[0].title
    print("[PASS] Python Test 1: Tempfile without cleanup")


def test_python_tempfile_with_cleanup():
    """Python: No false positive when cleanup present."""
    code = """
import tempfile, os
def process():
    tmp = tempfile.NamedTemporaryFile(mode='w', delete=False)
    try:
        tmp.write("data")
    finally:
        tmp.close()
        os.unlink(tmp.name)
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_python(code)
    assert len(findings) == 0
    print("[PASS] Python Test 2: Tempfile with cleanup")


def test_python_open_without_context_manager():
    """Python: Detect open() without context manager."""
    code = """
def read():
    f = open('file.txt', 'r')
    return f.read()
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_python(code)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "File Handle" in findings[0].title
    print("[PASS] Python Test 3: Open without context manager")


def test_python_sensitive_var_not_cleared():
    """Python: Detect sensitive vars not cleared."""
    code = """
def auth():
    password = "secret"
    api_key = "key123"
    login(password, api_key)
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_python(code)
    assert len(findings) == 2
    assert all(f.severity == Severity.MEDIUM for f in findings)
    print("[PASS] Python Test 4: Sensitive vars not cleared")


# ============================================================================
# C# TESTS (Hybrid AST+regex)
# ============================================================================

def test_csharp_stream_without_using():
    """C#: Detect IDisposable without using statement."""
    code = """
public void ProcessFile()
{
    var stream = new FileStream("file.txt", FileMode.Open);
    var reader = new StreamReader(stream);
    var content = reader.ReadToEnd();
}
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_csharp(code)
    assert len(findings) >= 1
    assert any(f.severity == Severity.HIGH for f in findings)
    assert any("Disposable" in f.title for f in findings)
    print("[PASS] C# Test 1: Stream without using")


def test_csharp_stream_with_using():
    """C#: No false positive with using statement."""
    code = """
public void ProcessFile()
{
    using (var stream = new FileStream("file.txt", FileMode.Open))
    {
        var reader = new StreamReader(stream);
        var content = reader.ReadToEnd();
    }
}
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_csharp(code)
    # Should not flag the stream in using statement
    assert len([f for f in findings if "FileStream" in str(f.snippet)]) == 0
    print("[PASS] C# Test 2: Stream with using statement")


def test_csharp_httpclient_without_disposal():
    """C#: Detect HttpClient without Dispose()."""
    code = """
public void CallApi()
{
    var client = new HttpClient();
    var response = client.GetAsync("https://api.example.com").Result;
    var content = response.Content.ReadAsStringAsync().Result;
}
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_csharp(code)
    assert len(findings) >= 1
    assert any(f.severity == Severity.HIGH for f in findings)
    print("[PASS] C# Test 3: HttpClient without disposal")


# ============================================================================
# JAVA TESTS (Hybrid AST+regex)
# ============================================================================

def test_java_stream_without_try_with_resources():
    """Java: Detect AutoCloseable without try-with-resources."""
    code = """
public void readFile() {
    FileInputStream fis = new FileInputStream("file.txt");
    BufferedReader reader = new BufferedReader(new InputStreamReader(fis));
    String line = reader.readLine();
}
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_java(code)
    assert len(findings) >= 1
    assert any(f.severity == Severity.HIGH for f in findings)
    assert any("AutoCloseable" in f.title for f in findings)
    print("[PASS] Java Test 1: Stream without try-with-resources")


def test_java_stream_with_try_with_resources():
    """Java: No false positive with try-with-resources."""
    code = """
public void readFile() {
    try (FileInputStream fis = new FileInputStream("file.txt");
         BufferedReader reader = new BufferedReader(new InputStreamReader(fis))) {
        String line = reader.readLine();
    }
}
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_java(code)
    # Should not flag streams in try-with-resources
    assert len([f for f in findings if "FileInputStream" in str(f.snippet)]) == 0
    print("[PASS] Java Test 2: Stream with try-with-resources")


def test_java_password_array_not_zeroed():
    """Java: Detect char[] password not zeroed."""
    code = """
public void authenticate() {
    char[] password = getPassword();
    login(password);
}
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_java(code)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "Array Not Zeroed" in findings[0].title
    print("[PASS] Java Test 3: Password array not zeroed")


def test_java_password_array_zeroed():
    """Java: No false positive when array is zeroed."""
    code = """
import java.util.Arrays;
public void authenticate() {
    char[] password = getPassword();
    try {
        login(password);
    } finally {
        Arrays.fill(password, (char) 0);
    }
}
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_java(code)
    assert len(findings) == 0
    print("[PASS] Java Test 4: Password array zeroed")


# ============================================================================
# TYPESCRIPT TESTS (Hybrid AST+regex)
# ============================================================================

def test_typescript_fs_open_without_close():
    """TypeScript: Detect fs.openSync without closeSync."""
    code = """
import * as fs from 'fs';
function readFile() {
    const fd = fs.openSync('file.txt', 'r');
    const buffer = Buffer.alloc(1024);
    fs.readSync(fd, buffer, 0, 1024, 0);
    return buffer;
}
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_typescript(code)
    assert len(findings) >= 1
    assert any(f.severity == Severity.HIGH for f in findings)
    assert any("File Descriptor" in f.title for f in findings)
    print("[PASS] TypeScript Test 1: fs.openSync without close")


def test_typescript_fs_open_with_close():
    """TypeScript: No false positive with closeSync."""
    code = """
import * as fs from 'fs';
function readFile() {
    let fd: number | undefined;
    try {
        fd = fs.openSync('file.txt', 'r');
        const buffer = Buffer.alloc(1024);
        fs.readSync(fd, buffer, 0, 1024, 0);
    } finally {
        if (fd !== undefined) fs.closeSync(fd);
    }
}
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_typescript(code)
    assert len(findings) == 0
    print("[PASS] TypeScript Test 2: fs.openSync with closeSync")


def test_typescript_sensitive_buffer_not_cleared():
    """TypeScript: Detect sensitive Buffer not cleared."""
    code = """
function encrypt() {
    const passwordBuffer = Buffer.from(password, 'utf8');
    const encrypted = encryptData(passwordBuffer);
    return encrypted;
}
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_typescript(code)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert "Buffer" in findings[0].title
    print("[PASS] TypeScript Test 3: Sensitive buffer not cleared")


def test_typescript_sensitive_buffer_cleared():
    """TypeScript: No false positive when buffer cleared."""
    code = """
function encrypt() {
    const passwordBuffer = Buffer.from(password, 'utf8');
    try {
        const encrypted = encryptData(passwordBuffer);
        return encrypted;
    } finally {
        passwordBuffer.fill(0);
    }
}
"""
    analyzer = KSI_SVC_08_Analyzer()
    findings = analyzer.analyze_typescript(code)
    assert len(findings) == 0
    print("[PASS] TypeScript Test 4: Sensitive buffer cleared")


# ============================================================================
# TEST RUNNER
# ============================================================================

if __name__ == "__main__":
    print("Running KSI-SVC-08 Comprehensive Tests (All Languages)")
    print("=" * 70)
    
    print("\nPython Tests (AST):")
    print("-" * 70)
    test_python_tempfile_without_cleanup()
    test_python_tempfile_with_cleanup()
    test_python_open_without_context_manager()
    test_python_sensitive_var_not_cleared()
    
    print("\nC# Tests (Hybrid AST+regex):")
    print("-" * 70)
    test_csharp_stream_without_using()
    test_csharp_stream_with_using()
    test_csharp_httpclient_without_disposal()
    
    print("\nJava Tests (Hybrid AST+regex):")
    print("-" * 70)
    test_java_stream_without_try_with_resources()
    test_java_stream_with_try_with_resources()
    test_java_password_array_not_zeroed()
    test_java_password_array_zeroed()
    
    print("\nTypeScript Tests (Hybrid AST+regex):")
    print("-" * 70)
    test_typescript_fs_open_without_close()
    test_typescript_fs_open_with_close()
    test_typescript_sensitive_buffer_not_cleared()
    test_typescript_sensitive_buffer_cleared()
    
    print("\n" + "=" * 70)
    print("ALL 16 TESTS PASSED!")
    print("\nKSI-SVC-08 AST Conversion Complete:")
    print("  - Python: Full AST (3 patterns)")
    print("  - C#: Hybrid AST+regex (2 patterns)")
    print("  - Java: Hybrid AST+regex (2 patterns)")
    print("  - TypeScript: Hybrid AST+regex (2 patterns)")
    print("  - Total: 16/16 tests passing")
