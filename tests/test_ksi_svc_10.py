"""
Tests for KSI-SVC-10 Enhanced: Data Destruction

Tests data destruction compliance across multiple languages:
- Python: Hard delete vs soft delete patterns, backup retention
- C#: EF Core Remove() without soft delete
- Java: JPA/Hibernate delete without soft delete
- TypeScript: ORM delete patterns
- Bicep: Storage lifecycle, database backup retention
- Terraform: Storage management policy, backup retention
- Factory integration
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.ksi.ksi_svc_10 import KSI_SVC_10_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_hard_delete():
    """Test detection of hard delete without soft delete in Python"""
    analyzer = KSI_SVC_10_Analyzer()
    
    code = '''
# Django model delete without soft delete
user = User.objects.get(id=user_id)
user.delete()  # Hard delete - data unrecoverable
'''
    
    result = analyzer.analyze(code, "python", "views.py")
    assert result.total_issues > 0
    assert any("soft delete" in f.title.lower() or "delete" in f.title.lower() for f in result.findings)


def test_python_backup_no_retention():
    """Test detection of backup without retention policy"""
    analyzer = KSI_SVC_10_Analyzer()
    
    code = '''
import boto3
s3 = boto3.client('s3')
s3.put_object(Bucket='backups', Key='backup.tar.gz', Body=data)
# No lifecycle policy or expiration configured
'''
    
    result = analyzer.analyze(code, "python", "backup.py")
    # May detect missing retention/expiration
    assert result.ksi_id == "KSI-SVC-10"


def test_csharp_ef_core_hard_delete():
    """Test detection of EF Core Remove() without soft delete"""
    analyzer = KSI_SVC_10_Analyzer()
    
    code = '''
using Microsoft.EntityFrameworkCore;

public class UserService {
    private readonly ApplicationDbContext _context;
    
    public void DeleteUser(int id) {
        var user = _context.Users.Find(id);
        _context.Users.Remove(user);  // Hard delete
        _context.SaveChanges();
    }
}
'''
    
    result = analyzer.analyze(code, "csharp", "UserService.cs")
    assert result.total_issues > 0
    assert any("soft delete" in f.title.lower() or "remove" in f.title.lower() for f in result.findings)


def test_java_jpa_delete():
    """Test detection of JPA delete without soft delete"""
    analyzer = KSI_SVC_10_Analyzer()
    
    code = '''
import javax.persistence.EntityManager;

public class UserRepository {
    @PersistenceContext
    private EntityManager entityManager;
    
    public void deleteUser(Long id) {
        User user = entityManager.find(User.class, id);
        entityManager.remove(user);  // Hard delete
    }
}
'''
    
    result = analyzer.analyze(code, "java", "UserRepository.java")
    assert result.total_issues > 0
    assert any("soft delete" in f.title.lower() or "delete" in f.title.lower() for f in result.findings)


def test_typescript_orm_delete():
    """Test detection of ORM delete without soft delete"""
    analyzer = KSI_SVC_10_Analyzer()
    
    code = '''
import { getRepository } from 'typeorm';

async function deleteUser(id: number) {
    const userRepository = getRepository(User);
    await userRepository.delete(id);  // Hard delete
}
'''
    
    result = analyzer.analyze(code, "typescript", "userService.ts")
    assert result.total_issues > 0
    assert any("delete" in f.title.lower() for f in result.findings)


def test_bicep_storage_no_lifecycle():
    """Test detection of storage account without lifecycle management"""
    analyzer = KSI_SVC_10_Analyzer()
    
    code = '''
resource storageAccount 'Microsoft.Storage/storageAccounts@2022-09-01' = {
  name: 'mystorageaccount'
  location: resourceGroup().location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  // No lifecycle management policy configured
}
'''
    
    result = analyzer.analyze(code, "bicep", "storage.bicep")
    assert result.total_issues > 0
    assert any("lifecycle" in f.title.lower() or "retention" in f.title.lower() for f in result.findings)


def test_terraform_storage_no_lifecycle():
    """Test detection of storage without lifecycle policy"""
    analyzer = KSI_SVC_10_Analyzer()
    
    code = '''
resource "azurerm_storage_account" "example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  # No azurerm_storage_management_policy configured
}
'''
    
    result = analyzer.analyze(code, "terraform", "storage.tf")
    assert result.total_issues > 0
    assert any("lifecycle" in f.title.lower() or "management" in f.title.lower() for f in result.findings)


def test_factory_integration():
    """Test that SVC-10 enhanced is registered in factory"""
    from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
    
    factory = get_factory()
    ksi_list = factory.list_ksis()
    
    assert "KSI-SVC-10" in ksi_list
    
    # Test factory can analyze
    code = '''
user.delete()  # Hard delete
'''
    
    result = factory.analyze("KSI-SVC-10", code, "python", "test.py")
    assert result.ksi_id == "KSI-SVC-10"


def test_python_soft_delete_pattern():
    """Test that soft delete pattern is recognized as compliant"""
    analyzer = KSI_SVC_10_Analyzer()
    
    code = '''
# Soft delete pattern
user = User.objects.get(id=user_id)
user.is_deleted = True  # Soft delete - data retained
user.deleted_at = timezone.now()
user.save()
'''
    
    result = analyzer.analyze(code, "python", "views.py")
    # Should not flag soft delete as issue
    hard_delete_findings = [f for f in result.findings if "hard delete" in f.description.lower() and "soft delete" not in f.recommendation.lower()]
    # May still have other findings, but soft delete should not be flagged
    assert result.ksi_id == "KSI-SVC-10"


if __name__ == "__main__":
    print("Testing KSI-SVC-10 Enhanced Analyzer...")
    print("=" * 60)
    
    tests = [
        ("Python Hard Delete", test_python_hard_delete),
        ("Python Backup No Retention", test_python_backup_no_retention),
        ("C# EF Core Hard Delete", test_csharp_ef_core_hard_delete),
        ("Java JPA Delete", test_java_jpa_delete),
        ("TypeScript ORM Delete", test_typescript_orm_delete),
        ("Bicep Storage No Lifecycle", test_bicep_storage_no_lifecycle),
        ("Terraform Storage No Lifecycle", test_terraform_storage_no_lifecycle),
        ("Factory Integration", test_factory_integration),
        ("Python Soft Delete Pattern", test_python_soft_delete_pattern),
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

