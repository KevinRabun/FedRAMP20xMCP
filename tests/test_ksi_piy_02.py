"""Tests for KSI-PIY-02 Enhanced: Data Minimization"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_piy_02 import KSI_PIY_02_Analyzer
from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_select_star():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
def get_all_users():
    query = "SELECT * FROM users"
    return db.execute(query)
"""
    result = analyzer.analyze(code, "python", "queries.py")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] Python SELECT *")


def test_python_query_all():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
def get_users():
    return User.query.all()
"""
    result = analyzer.analyze(code, "python", "models.py")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] Python query.all()")


def test_python_unnecessary_pii():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
class User(db.Model):
    name = db.Column(db.String)
    ssn = db.Column(db.String)
    email = db.Column(db.String)
"""
    result = analyzer.analyze(code, "python", "models.py")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Python unnecessary PII")


def test_python_justified_pii():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
class User(db.Model):
    name = db.Column(db.String)
    # Required for tax compliance
    ssn = db.Column(db.String)
    email = db.Column(db.String)
"""
    result = analyzer.analyze(code, "python", "models.py")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Python justified PII")


def test_csharp_tolist_without_filter():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
public List<User> GetUsers()
{
    return _context.Users.ToList();
}
"""
    result = analyzer.analyze(code, "csharp", "UserService.cs")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] C# ToList without filter")


def test_csharp_unnecessary_pii():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
public class User
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string SocialSecurityNumber { get; set; }
}
"""
    result = analyzer.analyze(code, "csharp", "User.cs")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] C# unnecessary PII")


def test_csharp_justified_pii():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
public class User
{
    public int Id { get; set; }
    /// Required for compliance
    public string SocialSecurityNumber { get; set; }
}
"""
    result = analyzer.analyze(code, "csharp", "User.cs")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] C# justified PII")


def test_java_findall_without_pagination():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
public List<User> getAllUsers() {
    return userRepository.findAll();
}
"""
    result = analyzer.analyze(code, "java", "UserService.java")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] Java findAll without pagination")


def test_java_unnecessary_pii():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
@Entity
public class User {
    private Long id;
    private String name;
    private String socialSecurityNumber;
}
"""
    result = analyzer.analyze(code, "java", "User.java")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Java unnecessary PII")


def test_java_justified_pii():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
@Entity
public class User {
    private Long id;
    // Required for tax compliance
    private String socialSecurityNumber;
}
"""
    result = analyzer.analyze(code, "java", "User.java")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Java justified PII")


def test_typescript_find_empty():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
async getAllUsers() {
    return this.userModel.find({});
}
"""
    result = analyzer.analyze(code, "typescript", "user.service.ts")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] TypeScript find empty")


def test_typescript_unnecessary_pii():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
interface User {
    id: number;
    name: string;
    socialSecurityNumber: string;
}
"""
    result = analyzer.analyze(code, "typescript", "user.interface.ts")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] TypeScript unnecessary PII")


def test_typescript_justified_pii():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
interface User {
    id: number;
    // Required for compliance
    socialSecurityNumber: string;
}
"""
    result = analyzer.analyze(code, "typescript", "user.interface.ts")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] TypeScript justified PII")


def test_bicep_storage_without_lifecycle():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
    name: 'stdata'
    location: location
    sku: { name: 'Standard_LRS' }
}
"""
    result = analyzer.analyze(code, "bicep", "storage.bicep")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] Bicep storage without lifecycle")


def test_bicep_database_without_retention():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
    name: 'sql-prod'
}

resource sqlDb 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
    parent: sqlServer
    name: 'mydb'
}
"""
    result = analyzer.analyze(code, "bicep", "sql.bicep")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] Bicep database without retention")


def test_terraform_storage_without_lifecycle():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
resource "azurerm_storage_account" "main" {
    name                     = "stdata"
    resource_group_name      = azurerm_resource_group.main.name
    location                 = azurerm_resource_group.main.location
    account_tier             = "Standard"
    account_replication_type = "LRS"
}
"""
    result = analyzer.analyze(code, "terraform", "storage.tf")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] Terraform storage without lifecycle")


def test_terraform_database_without_retention():
    analyzer = KSI_PIY_02_Analyzer()
    code = """
resource "azurerm_mssql_database" "main" {
    name      = "mydb"
    server_id = azurerm_mssql_server.main.id
    sku_name  = "S0"
}
"""
    result = analyzer.analyze(code, "terraform", "database.tf")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] Terraform database without retention")


def test_factory():
    factory = get_factory()
    analyzer = KSI_PIY_02_Analyzer()
    factory.register(analyzer)
    
    code = """
def get_users():
    return User.query.all()
"""
    result = factory.analyze("KSI-PIY-02", code, "python", "models.py")
    assert result.ksi_id == "KSI-PIY-02"
    assert len(result.findings) >= 1
    print("[PASS] Factory integration")


def run_all():
    tests = [
        test_python_select_star,
        test_python_query_all,
        test_python_unnecessary_pii,
        test_python_justified_pii,
        test_csharp_tolist_without_filter,
        test_csharp_unnecessary_pii,
        test_csharp_justified_pii,
        test_java_findall_without_pagination,
        test_java_unnecessary_pii,
        test_java_justified_pii,
        test_typescript_find_empty,
        test_typescript_unnecessary_pii,
        test_typescript_justified_pii,
        test_bicep_storage_without_lifecycle,
        test_bicep_database_without_retention,
        test_terraform_storage_without_lifecycle,
        test_terraform_database_without_retention,
        test_factory,
    ]
    
    print("\nKSI-PIY-02 Enhanced Tests")
    print("="*60)
    passed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] FAIL: {test.__name__}: {e}")
        except Exception as e:
            print(f"[FAIL] ERROR: {test.__name__}: {e}")
    
    print("="*60)
    print(f"Results: {passed}/{len(tests)} passed")
    return passed == len(tests)


if __name__ == "__main__":
    sys.exit(0 if run_all() else 1)

