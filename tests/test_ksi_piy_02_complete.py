"""
Comprehensive tests for KSI-PIY-02: Data Minimization (AST-based)

Tests cover:
- Python: SELECT *, .all() queries, PII fields
- C#: .ToList() without filters, PII properties
- Java: findAll() without pagination, PII fields
- TypeScript: .find({}) queries, PII fields
- Bicep: Storage/database retention policies
- Terraform: Storage/database retention policies
"""

import sys
from pathlib import Path

# Add src to path
src_path = Path(__file__).parent.parent / "src"
sys.path.insert(0, str(src_path))

from fedramp_20x_mcp.analyzers.ksi.ksi_piy_02 import KSI_PIY_02_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_select_star():
    """Test detection of SELECT * queries"""
    code = '''
import sqlite3

def get_users():
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_python(code, "test.py")
    
    assert len(findings) == 1
    assert findings[0].title == "Overly broad data query"
    assert findings[0].severity == Severity.MEDIUM
    assert "SELECT *" in findings[0].description
    print("[PASS] Python with SELECT * detected")


def test_python_query_all():
    """Test detection of .query.all() without filters"""
    code = '''
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

def get_all_users():
    users = db.session.query(User).all()
    return users
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_python(code, "test.py")
    
    assert len(findings) == 1
    assert findings[0].title == "Unfiltered data retrieval"
    assert findings[0].severity == Severity.MEDIUM
    assert "without filters" in findings[0].description
    print("[PASS] Python with .query.all() detected")


def test_python_pii_without_justification():
    """Test detection of PII fields without justification"""
    code = '''
from sqlalchemy import Column, String

class User(Base):
    __tablename__ = 'users'
    
    ssn = Column(String)
    date_of_birth = Column(String)
    drivers_license = Column(String)
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_python(code, "test.py")
    
    assert len(findings) >= 3  # Multiple PII fields detected
    assert all(f.title == "Unnecessary PII collection" for f in findings)
    assert all(f.severity == Severity.HIGH for f in findings)
    print("[PASS] Python with PII fields without justification detected")


def test_python_pii_with_justification():
    """Test PII fields with justification comments are allowed"""
    code = '''
from sqlalchemy import Column, String

class User(Base):
    __tablename__ = 'users'
    
    # Required for compliance with federal regulations
    ssn = Column(String)
    
    # Necessary for age verification
    date_of_birth = Column(String)
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_python(code, "test.py")
    
    assert len(findings) == 0  # No findings when justified
    print("[PASS] Python with justified PII fields passes")


def test_csharp_tolist_without_filter():
    """Test detection of .ToList() without Where clause"""
    code = '''
using Microsoft.EntityFrameworkCore;

public class UserService
{
    private readonly AppDbContext _context;
    
    public List<User> GetAllUsers()
    {
        return _context.Users.ToList();
    }
}
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_csharp(code, "test.cs")
    
    assert len(findings) == 1
    assert findings[0].title == "Unfiltered data retrieval"
    assert findings[0].severity == Severity.MEDIUM
    assert "ToList()" in findings[0].description
    print("[PASS] C# with .ToList() without filter detected")


def test_csharp_pii_without_justification():
    """Test detection of PII properties without justification"""
    code = '''
public class User
{
    public int Id { get; set; }
    public string Name { get; set; }
    public string SocialSecurityNumber { get; set; }
    public DateTime DateOfBirth { get; set; }
    public string DriversLicense { get; set; }
}
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_csharp(code, "test.cs")
    
    assert len(findings) >= 3  # Multiple PII properties detected
    assert all(f.title == "Unnecessary PII property" for f in findings)
    assert all(f.severity == Severity.HIGH for f in findings)
    print("[PASS] C# with PII properties without justification detected")


def test_csharp_pii_with_justification():
    """Test PII properties with justification comments are allowed"""
    code = '''
public class User
{
    public int Id { get; set; }
    
    /// <summary>
    /// Required for compliance with federal regulations
    /// </summary>
    public string SocialSecurityNumber { get; set; }
    
    // Necessary for age verification
    public DateTime DateOfBirth { get; set; }
}
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_csharp(code, "test.cs")
    
    assert len(findings) == 0  # No findings when justified
    print("[PASS] C# with justified PII properties passes")


def test_java_findall_without_pagination():
    """Test detection of findAll() without pagination"""
    code = '''
import org.springframework.data.jpa.repository.JpaRepository;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;
    
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
}
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_java(code, "test.java")
    
    assert len(findings) == 1
    assert findings[0].title == "Unfiltered data retrieval"
    assert findings[0].severity == Severity.MEDIUM
    assert "findAll()" in findings[0].description
    print("[PASS] Java with findAll() without pagination detected")


def test_java_pii_without_justification():
    """Test detection of PII fields without justification"""
    code = '''
import javax.persistence.*;

@Entity
public class User {
    @Id
    private Long id;
    
    private String name;
    private String socialSecurityNumber;
    private LocalDate dateOfBirth;
    private String driversLicense;
}
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_java(code, "test.java")
    
    assert len(findings) >= 3  # Multiple PII fields detected
    assert all(f.title == "Unnecessary PII field" for f in findings)
    assert all(f.severity == Severity.HIGH for f in findings)
    print("[PASS] Java with PII fields without justification detected")


def test_java_pii_with_justification():
    """Test PII fields with justification comments are allowed"""
    code = '''
import javax.persistence.*;

@Entity
public class User {
    @Id
    private Long id;
    
    // Required for compliance with federal regulations
    private String socialSecurityNumber;
    
    /* Necessary for age verification and compliance */
    private LocalDate dateOfBirth;
}
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_java(code, "test.java")
    
    assert len(findings) == 0  # No findings when justified
    print("[PASS] Java with justified PII fields passes")


def test_typescript_find_empty_object():
    """Test detection of .find({}) queries"""
    code = '''
import { MongoClient } from 'mongodb';

async function getAllUsers() {
    const client = await MongoClient.connect(url);
    const db = client.db('myapp');
    const users = await db.collection('users').find({}).toArray();
    return users;
}
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_typescript(code, "test.ts")
    
    assert len(findings) == 1
    assert findings[0].title == "Unfiltered data query"
    assert findings[0].severity == Severity.MEDIUM
    assert "find()" in findings[0].description
    print("[PASS] TypeScript with .find({}) detected")


def test_typescript_pii_without_justification():
    """Test detection of PII fields in interfaces"""
    code = '''
interface User {
    id: string;
    name: string;
    socialSecurityNumber: string;
    dateOfBirth: Date;
    driversLicense?: string;
    passportNumber: string;
}
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_typescript(code, "test.ts")
    
    assert len(findings) >= 3  # Multiple PII fields detected
    assert all(f.title == "Unnecessary PII field" for f in findings)
    assert all(f.severity == Severity.HIGH for f in findings)
    print("[PASS] TypeScript with PII fields without justification detected")


def test_typescript_pii_with_justification():
    """Test PII fields with justification comments are allowed"""
    code = '''
interface User {
    id: string;
    
    // Required for compliance with federal regulations
    socialSecurityNumber: string;
    
    /* Necessary for age verification */
    dateOfBirth: Date;
}
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_typescript(code, "test.ts")
    
    assert len(findings) == 0  # No findings when justified
    print("[PASS] TypeScript with justified PII fields passes")


def test_bicep_storage_without_lifecycle():
    """Test detection of storage account without lifecycle policy"""
    code = '''
resource storageAccount 'Microsoft.Storage/storageAccounts@2021-04-01' = {
  name: 'mystorageaccount'
  location: 'eastus'
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
}
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_bicep(code, "test.bicep")
    
    assert len(findings) == 1
    assert findings[0].title == "Storage without lifecycle policy"
    assert findings[0].severity == Severity.MEDIUM
    print("[PASS] Bicep storage without lifecycle policy detected")


def test_bicep_storage_with_lifecycle():
    """Test storage account with lifecycle policy passes"""
    code = '''
resource storageAccount 'Microsoft.Storage/storageAccounts@2021-04-01' = {
  name: 'mystorageaccount'
  location: 'eastus'
}

resource managementPolicy 'Microsoft.Storage/storageAccounts/managementPolicies@2021-04-01' = {
  name: '${storageAccount.name}/default'
  properties: {
    policy: {
      rules: [
        {
          enabled: true
          name: 'deleteOldData'
        }
      ]
    }
  }
}
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_bicep(code, "test.bicep")
    
    assert len(findings) == 0  # Should pass with lifecycle policy
    print("[PASS] Bicep storage with lifecycle policy passes")


def test_terraform_storage_without_lifecycle():
    """Test detection of storage account without lifecycle management"""
    code = '''
resource "azurerm_storage_account" "example" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_terraform(code, "test.tf")
    
    assert len(findings) == 1
    assert findings[0].title == "Storage without lifecycle policy"
    assert findings[0].severity == Severity.MEDIUM
    print("[PASS] Terraform storage without lifecycle policy detected")


def test_terraform_storage_with_lifecycle():
    """Test storage account with lifecycle management passes"""
    code = '''
resource "azurerm_storage_account" "example" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_management_policy" "example" {
  storage_account_id = azurerm_storage_account.example.id

  rule {
    name    = "deleteOldData"
    enabled = true
  }
}
'''
    analyzer = KSI_PIY_02_Analyzer()
    findings = analyzer.analyze_terraform(code, "test.tf")
    
    assert len(findings) == 0  # Should pass with lifecycle policy
    print("[PASS] Terraform storage with lifecycle policy passes")


if __name__ == "__main__":
    print("Testing KSI-PIY-02: Data Minimization (AST-based)\n")
    
    # Python tests
    test_python_select_star()
    test_python_query_all()
    test_python_pii_without_justification()
    test_python_pii_with_justification()
    
    # C# tests
    test_csharp_tolist_without_filter()
    test_csharp_pii_without_justification()
    test_csharp_pii_with_justification()
    
    # Java tests
    test_java_findall_without_pagination()
    test_java_pii_without_justification()
    test_java_pii_with_justification()
    
    # TypeScript tests
    test_typescript_find_empty_object()
    test_typescript_pii_without_justification()
    test_typescript_pii_with_justification()
    
    # Bicep tests
    test_bicep_storage_without_lifecycle()
    test_bicep_storage_with_lifecycle()
    
    # Terraform tests
    test_terraform_storage_without_lifecycle()
    test_terraform_storage_with_lifecycle()
    
    print("\n" + "=" * 50)
    print("ALL KSI-PIY-02 TESTS PASSED [PASS]")
    print("=" * 50)
