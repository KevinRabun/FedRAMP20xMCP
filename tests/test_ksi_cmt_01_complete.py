"""
Test suite for KSI-CMT-01: Version Control and Change Logging

Validates detection of file operations and database modifications without audit logging:
- Python: open(), shutil operations without logging
- C#: File operations, Entity Framework SaveChanges without logging
- Java: File I/O, JPA persist/merge without logging  
- TypeScript: fs operations, database operations without logging
- Bicep: Missing Activity Log diagnostic settings
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_cmt_01 import KSI_CMT_01_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity

def test_python_open_without_logging():
    """Test detection of open() for writing without audit logging."""
    code = """
def save_config(filename, data):
    with open(filename, 'w') as f:
        f.write(data)
"""
    
    analyzer = KSI_CMT_01_Analyzer()
    result = analyzer.analyze(code, "python", "config.py")
    findings = result.findings
    
    # Should detect open() with 'w' mode without logging
    open_findings = [f for f in findings if "open()" in f.title or "File write" in f.title]
    assert len(open_findings) > 0, "Should detect open() without logging"
    assert open_findings[0].severity == Severity.MEDIUM
    assert "KSI-CMT-01" in open_findings[0].ksi_id
    assert "AU-2" in open_findings[0].description or "CM-3" in open_findings[0].description
    print("[PASS] Python: Detects open() for writing without audit logging")


def test_python_open_with_logging():
    """Test that open() with logging is accepted."""
    code = """
import logging

logger = logging.getLogger(__name__)

def save_config(filename, data):
    logger.info(f'Writing config to {filename}')
    with open(filename, 'w') as f:
        f.write(data)
"""
    
    analyzer = KSI_CMT_01_Analyzer()
    result = analyzer.analyze(code, "python", "config.py")
    findings = result.findings
    
    # Should NOT detect issue (logging is present)
    open_findings = [f for f in findings if "open()" in f.title]
    assert len(open_findings) == 0, "Should accept open() with logging"
    print("[PASS] Python: Accepts open() with audit logging")


def test_python_shutil_without_logging():
    """Test detection of shutil.copy without audit logging."""
    code = """
import shutil

def backup_file(source, dest):
    shutil.copy(source, dest)
"""
    
    analyzer = KSI_CMT_01_Analyzer()
    result = analyzer.analyze(code, "python", "backup.py")
    findings = result.findings
    
    # Should detect shutil.copy without logging
    shutil_findings = [f for f in findings if "shutil" in f.title.lower()]
    assert len(shutil_findings) > 0, "Should detect shutil.copy without logging"
    assert shutil_findings[0].severity == Severity.MEDIUM
    print("[PASS] Python: Detects shutil.copy without audit logging")


def test_csharp_file_write_without_logging():
    """Test detection of File.Write* without ILogger."""
    code = """
public class FileService
{
    public void SaveData(string path, string data)
    {
        File.WriteAllText(path, data);
    }
}
"""
    
    analyzer = KSI_CMT_01_Analyzer()
    result = analyzer.analyze(code, "csharp", "FileService.cs")
    findings = result.findings
    
    # Should detect File.WriteAllText without logging
    file_findings = [f for f in findings if "File" in f.title and "operation" in f.title.lower()]
    assert len(file_findings) > 0, "Should detect File.WriteAllText without logging"
    assert file_findings[0].severity == Severity.MEDIUM
    print("[PASS] C#: Detects File.WriteAllText without ILogger")


def test_csharp_savechanges_without_logging():
    """Test detection of SaveChanges() without audit logging."""
    code = """
public class UserRepository
{
    private readonly DbContext _context;
    
    public async Task UpdateUser(User user)
    {
        _context.Users.Update(user);
        await _context.SaveChanges();
    }
}
"""
    
    analyzer = KSI_CMT_01_Analyzer()
    result = analyzer.analyze(code, "csharp", "UserRepository.cs")
    findings = result.findings
    
    # Should detect SaveChanges without logging
    db_findings = [f for f in findings if "SaveChanges" in f.title or "Database" in f.title]
    assert len(db_findings) > 0, "Should detect SaveChanges without logging"
    assert db_findings[0].severity == Severity.HIGH
    print("[PASS] C#: Detects SaveChanges without audit logging")


def test_java_filewriter_without_logging():
    """Test detection of FileWriter without Logger."""
    code = """
public class ConfigWriter {
    public void saveConfig(String filename, String data) throws IOException {
        FileWriter writer = new FileWriter(filename);
        writer.write(data);
        writer.close();
    }
}
"""
    
    analyzer = KSI_CMT_01_Analyzer()
    result = analyzer.analyze(code, "java", "ConfigWriter.java")
    findings = result.findings
    
    # Should detect FileWriter without Logger
    file_findings = [f for f in findings if "File" in f.title]
    assert len(file_findings) > 0, "Should detect FileWriter without logging"
    assert file_findings[0].severity == Severity.MEDIUM
    print("[PASS] Java: Detects FileWriter without Logger")


def test_java_persist_without_logging():
    """Test detection of EntityManager.persist without Logger."""
    code = """
public class UserService {
    @PersistenceContext
    private EntityManager em;
    
    public void createUser(User user) {
        em.persist(user);
    }
}
"""
    
    analyzer = KSI_CMT_01_Analyzer()
    result = analyzer.analyze(code, "java", "UserService.java")
    findings = result.findings
    
    # Should detect persist() without Logger
    persist_findings = [f for f in findings if "persist" in f.title.lower() or "Database" in f.title]
    assert len(persist_findings) > 0, "Should detect persist() without logging"
    assert persist_findings[0].severity == Severity.HIGH
    print("[PASS] Java: Detects EntityManager.persist without Logger")


def test_typescript_fs_write_without_logging():
    """Test detection of fs.write* without logger."""
    code = """
import fs from 'fs';

export function saveData(filename: string, data: string) {
    fs.writeFileSync(filename, data);
}
"""
    
    analyzer = KSI_CMT_01_Analyzer()
    result = analyzer.analyze(code, "typescript", "fileService.ts")
    findings = result.findings
    
    # Should detect fs.writeFileSync without logger
    fs_findings = [f for f in findings if "File operation" in f.title]
    assert len(fs_findings) > 0, "Should detect fs.writeFileSync without logging"
    assert fs_findings[0].severity == Severity.MEDIUM
    print("[PASS] TypeScript: Detects fs.writeFileSync without logger")


def test_typescript_db_save_without_logging():
    """Test detection of database .save() without logger."""
    code = """
export class UserService {
    async createUser(user: User) {
        await user.save();
    }
}
"""
    
    analyzer = KSI_CMT_01_Analyzer()
    result = analyzer.analyze(code, "typescript", "userService.ts")
    findings = result.findings
    
    # Should detect .save() without logger
    db_findings = [f for f in findings if "save()" in f.title.lower() or "Database" in f.title]
    assert len(db_findings) > 0, "Should detect .save() without logging"
    assert db_findings[0].severity == Severity.HIGH
    print("[PASS] TypeScript: Detects database .save() without logger")


def test_bicep_missing_activity_log():
    """Test detection of missing Activity Log diagnostic settings."""
    code = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: resourceGroup().location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
}
"""
    
    analyzer = KSI_CMT_01_Analyzer()
    result = analyzer.analyze(code, "bicep", "storage.bicep")
    findings = result.findings
    
    # Should detect missing Activity Log
    activity_log_findings = [f for f in findings if "Activity Log" in f.title]
    assert len(activity_log_findings) > 0, "Should detect missing Activity Log"
    assert activity_log_findings[0].severity == Severity.HIGH
    print("[PASS] Bicep: Detects missing Activity Log diagnostic settings")


def test_python_regex_fallback():
    """Test regex fallback when AST parsing fails."""
    code = """
# Malformed Python to trigger regex fallback
def save_config(filename, data):
    with open(filename, 'w') as f
# Missing colon
"""
    
    analyzer = KSI_CMT_01_Analyzer()
    result = analyzer.analyze(code, "python", "config.py")
    findings = result.findings
    
    # Should detect via regex fallback
    fallback_findings = [f for f in findings if "Regex Fallback" in f.title or "open" in f.title.lower()]
    assert len(fallback_findings) > 0, "Should detect via regex fallback"
    print("[PASS] Python: Regex fallback works on syntax error")


def run_all_tests():
    """Run all KSI-CMT-01 tests."""
    print("\n" + "="*70)
    print("KSI-CMT-01: Version Control and Change Logging")
    print("Testing file/database operations without audit logging")
    print("="*70 + "\n")
    
    tests = [
        ("Python open() without logging", test_python_open_without_logging),
        ("Python open() with logging", test_python_open_with_logging),
        ("Python shutil without logging", test_python_shutil_without_logging),
        ("C# File.Write without logging", test_csharp_file_write_without_logging),
        ("C# SaveChanges without logging", test_csharp_savechanges_without_logging),
        ("Java FileWriter without logging", test_java_filewriter_without_logging),
        ("Java persist() without logging", test_java_persist_without_logging),
        ("TypeScript fs.write without logging", test_typescript_fs_write_without_logging),
        ("TypeScript database save without logging", test_typescript_db_save_without_logging),
        ("Bicep missing Activity Log", test_bicep_missing_activity_log),
        ("Python regex fallback", test_python_regex_fallback),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test_name}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test_name}: {e}")
            failed += 1
    
    print("\n" + "="*70)
    print(f"Test Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    if failed == 0:
        print("ALL TESTS PASSED!")
    print("="*70 + "\n")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
