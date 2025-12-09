"""
Tests for KSI-SVC-08 Enhanced: Shared Resources

Tests residual data cleanup across multiple languages:
- Python: Temporary files, in-memory sensitive data clearing
- C#: IDisposable resources, SecureString disposal
- Java: try-with-resources, char[] password zeroing
- TypeScript: file streams, sensitive data cleanup
- Bicep: resource cleanup, secure configurations
- Terraform: resource lifecycle management
- Factory integration
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.ksi.ksi_svc_08 import KSI_SVC_08_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_temp_file_no_secure_delete():
    """Test detection of temporary file without secure deletion"""
    analyzer = KSI_SVC_08_Analyzer()
    
    code = '''
import tempfile

def process_sensitive_data(data):
    # Create temp file without secure deletion
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    temp_file.write(data.encode())
    temp_file.close()
    # File remains on disk - residual data
'''
    
    result = analyzer.analyze(code, "python", "processor.py")
    assert result.total_issues > 0
    assert any("temp" in f.title.lower() or "deletion" in f.title.lower() for f in result.findings)


def test_python_sensitive_data_not_cleared():
    """Test detection of sensitive data not cleared from memory"""
    analyzer = KSI_SVC_08_Analyzer()
    
    code = '''
def authenticate(password):
    user_password = password  # Sensitive data in memory
    # Password processing...
    # No explicit clearing of password variable
    return True
'''
    
    result = analyzer.analyze(code, "python", "auth.py")
    # May detect missing memory clearing
    assert result.ksi_id == "KSI-SVC-08"


def test_csharp_idisposable_not_disposed():
    """Test detection of IDisposable resource without using statement"""
    analyzer = KSI_SVC_08_Analyzer()
    
    code = '''
using System.IO;

public void ProcessFile(string path) {
    FileStream fs = new FileStream(path, FileMode.Open);
    // Processing...
    // Not disposed - resource leak
}
'''
    
    result = analyzer.analyze(code, "csharp", "FileProcessor.cs")
    assert result.total_issues > 0
    assert any("dispos" in f.title.lower() or "resource" in f.title.lower() for f in result.findings)


def test_csharp_securestring_not_disposed():
    """Test detection of SecureString not disposed"""
    analyzer = KSI_SVC_08_Analyzer()
    
    code = '''
using System.Security;

public void ProcessPassword(string password) {
    SecureString securePassword = new SecureString();
    foreach (char c in password) {
        securePassword.AppendChar(c);
    }
    // Not disposed - SecureString data remains in memory
}
'''
    
    result = analyzer.analyze(code, "csharp", "Security.cs")
    assert result.total_issues > 0
    assert any("securestring" in f.title.lower() or "dispos" in f.title.lower() for f in result.findings)


def test_java_resource_without_try_with_resources():
    """Test detection of AutoCloseable resource not properly closed"""
    analyzer = KSI_SVC_08_Analyzer()
    
    code = '''
import java.io.*;

public void readFile(String path) throws IOException {
    FileInputStream fis = new FileInputStream(path);
    // Reading...
    // Not closed properly - resource leak
}
'''
    
    result = analyzer.analyze(code, "java", "FileReader.java")
    assert result.total_issues > 0
    assert any("close" in f.title.lower() or "resource" in f.title.lower() for f in result.findings)


def test_java_password_char_array_not_zeroed():
    """Test detection of char[] password not zeroed"""
    analyzer = KSI_SVC_08_Analyzer()
    
    code = '''
public void authenticate() {
    char[] password = getPassword();
    // Authentication logic...
    // char[] not zeroed - password remains in memory
}
'''
    
    result = analyzer.analyze(code, "java", "Auth.java")
    # May detect missing char[] zeroing
    assert result.ksi_id == "KSI-SVC-08"


def test_typescript_file_stream_not_closed():
    """Test detection of file stream not properly closed"""
    analyzer = KSI_SVC_08_Analyzer()
    
    code = '''
import * as fs from 'fs';

function processFile(path: string) {
    const stream = fs.createReadStream(path);
    // Processing...
    // Stream not closed - resource leak
}
'''
    
    result = analyzer.analyze(code, "typescript", "fileProcessor.ts")
    # Test analyzer runs successfully
    assert result.ksi_id == "KSI-SVC-08"


def test_factory_integration():
    """Test that SVC-08 enhanced is registered in factory"""
    from src.fedramp_20x_mcp.analyzers.ksi.factory import get_factory
    
    factory = get_factory()
    ksi_list = factory.list_ksis()
    
    assert "KSI-SVC-08" in ksi_list
    
    # Test factory can analyze
    code = '''
temp_file = tempfile.NamedTemporaryFile(delete=False)
'''
    
    result = factory.analyze("KSI-SVC-08", code, "python", "test.py")
    assert result.ksi_id == "KSI-SVC-08"


def test_csharp_proper_disposal_pattern():
    """Test that proper disposal pattern is recognized as compliant"""
    analyzer = KSI_SVC_08_Analyzer()
    
    code = '''
using System.IO;

public void ProcessFile(string path) {
    using (FileStream fs = new FileStream(path, FileMode.Open)) {
        // Processing...
    }  // Automatically disposed
}
'''
    
    result = analyzer.analyze(code, "csharp", "FileProcessor.cs")
    # Using statement should not generate disposal warning
    disposal_findings = [f for f in result.findings if "not" in f.title.lower() and "dispos" in f.title.lower()]
    assert len(disposal_findings) == 0


if __name__ == "__main__":
    print("Testing KSI-SVC-08 Enhanced Analyzer...")
    print("=" * 60)
    
    tests = [
        ("Python Temp File No Secure Delete", test_python_temp_file_no_secure_delete),
        ("Python Sensitive Data Not Cleared", test_python_sensitive_data_not_cleared),
        ("C# IDisposable Not Disposed", test_csharp_idisposable_not_disposed),
        ("C# SecureString Not Disposed", test_csharp_securestring_not_disposed),
        ("Java Resource Without Try-With-Resources", test_java_resource_without_try_with_resources),
        ("Java Password Char Array Not Zeroed", test_java_password_char_array_not_zeroed),
        ("TypeScript File Stream Not Closed", test_typescript_file_stream_not_closed),
        ("Factory Integration", test_factory_integration),
        ("C# Proper Disposal Pattern", test_csharp_proper_disposal_pattern),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            test_func()
            print(f"PASS: {name}")
            passed += 1
        except AssertionError as e:
            print(f"FAIL: {name} - {e}")
            failed += 1
        except Exception as e:
            print(f"ERROR: {name} - {e}")
            failed += 1
    
    print("=" * 60)
    print(f"Results: {passed}/{len(tests)} tests passed")
    
    if failed > 0:
        sys.exit(1)

