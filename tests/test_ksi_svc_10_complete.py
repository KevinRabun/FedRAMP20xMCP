#!/usr/bin/env python3
"""
Comprehensive tests for KSI-SVC-10 (Data Destruction - Soft Delete)

Tests AST-first analysis for:
- Python: .delete()/.remove() without soft delete mechanism
- C#: Entity Framework Remove() without soft delete
- Java: JPA delete() without @SQLDelete
- TypeScript: ORM delete() without deletedAt field
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / 'src'))

from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_hard_delete():
    """Test Python hard delete without soft delete (MEDIUM)"""
    code = """
def delete_user(user_id):
    user = User.query.get(user_id)
    db.session.delete(user)  # Hard delete
    db.session.commit()
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-10', code, 'python')
    
    assert len(result.findings) == 1, f"Expected 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.MEDIUM, f"Expected MEDIUM, got {result.findings[0].severity}"
    assert "Hard Delete Without Soft Delete" in result.findings[0].title
    print("[PASS] Python hard delete detected (MEDIUM)")


def test_python_soft_delete():
    """Test Python with soft delete mechanism (passes)"""
    code = """
def soft_delete_user(user_id):
    user = User.query.get(user_id)
    user.deleted_at = datetime.now()
    user.is_deleted = True
    db.session.commit()
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-10', code, 'python')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] Python soft delete passes")


def test_python_no_delete():
    """Test Python without delete operations (passes)"""
    code = """
def update_user(user_id, name):
    user = User.query.get(user_id)
    user.name = name
    db.session.commit()
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-10', code, 'python')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] Python without delete passes")


def test_csharp_hard_delete():
    """Test C# EF Core Remove without soft delete (MEDIUM)"""
    code = """
public async Task DeleteCustomerAsync(int id)
{
    var customer = await _context.Customers.FindAsync(id);
    if (customer != null)
    {
        _context.Customers.Remove(customer);  // Hard delete
        await _context.SaveChangesAsync();
    }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-10', code, 'csharp')
    
    assert len(result.findings) == 1, f"Expected 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.MEDIUM, f"Expected MEDIUM, got {result.findings[0].severity}"
    assert "Hard Delete" in result.findings[0].title
    print("[PASS] C# hard delete detected (MEDIUM)")


def test_csharp_soft_delete():
    """Test C# with soft delete (passes)"""
    code = """
public async Task SoftDeleteCustomerAsync(int id)
{
    var customer = await _context.Customers.FindAsync(id);
    if (customer != null)
    {
        customer.DeletedAt = DateTime.UtcNow;
        customer.IsDeleted = true;
        await _context.SaveChangesAsync();
    }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-10', code, 'csharp')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] C# soft delete passes")


def test_csharp_no_delete():
    """Test C# without delete operations (passes)"""
    code = """
public async Task UpdateCustomerAsync(int id, string name)
{
    var customer = await _context.Customers.FindAsync(id);
    if (customer != null)
    {
        customer.Name = name;
        await _context.SaveChangesAsync();
    }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-10', code, 'csharp')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] C# without delete passes")


def test_java_hard_delete():
    """Test Java JPA delete without soft delete (MEDIUM)"""
    code = """
public void deleteCustomer(Long id) {
    Customer customer = customerRepository.findById(id)
        .orElseThrow(() -> new EntityNotFoundException());
    customerRepository.delete(customer);  // Hard delete
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-10', code, 'java')
    
    assert len(result.findings) >= 1, f"Expected at least 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.MEDIUM, f"Expected MEDIUM, got {result.findings[0].severity}"
    assert "Hard Delete" in result.findings[0].title
    print("[PASS] Java hard delete detected (MEDIUM)")


def test_java_soft_delete():
    """Test Java with @SQLDelete annotation (passes)"""
    code = """
@Entity
@SQLDelete(sql = "UPDATE customer SET deleted_at = NOW() WHERE id = ?")
public class Customer {
    private Long id;
    private String name;
    private LocalDateTime deletedAt;
}

public void deleteCustomer(Long id) {
    customerRepository.deleteById(id);  // Soft delete via @SQLDelete
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-10', code, 'java')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] Java with @SQLDelete passes")


def test_java_no_delete():
    """Test Java without delete operations (passes)"""
    code = """
public Customer updateCustomer(Long id, String name) {
    Customer customer = customerRepository.findById(id)
        .orElseThrow(() -> new EntityNotFoundException());
    customer.setName(name);
    return customerRepository.save(customer);
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-10', code, 'java')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] Java without delete passes")


def test_typescript_hard_delete():
    """Test TypeScript ORM delete without soft delete (MEDIUM)"""
    code = """
async function deleteCustomer(id: number): Promise<void> {
    const customer = await customerRepository.findOne({ where: { id } });
    if (customer) {
        await customerRepository.remove(customer);  // Hard delete
    }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-10', code, 'typescript')
    
    assert len(result.findings) >= 1, f"Expected at least 1 finding, got {len(result.findings)}"
    assert result.findings[0].severity == Severity.MEDIUM, f"Expected MEDIUM, got {result.findings[0].severity}"
    assert "Hard Delete" in result.findings[0].title
    print("[PASS] TypeScript hard delete detected (MEDIUM)")


def test_typescript_soft_delete():
    """Test TypeScript with deletedAt field (passes)"""
    code = """
async function softDeleteCustomer(id: number): Promise<void> {
    const customer = await customerRepository.findOne({ where: { id } });
    if (customer) {
        customer.deletedAt = new Date();
        customer.isDeleted = true;
        await customerRepository.save(customer);
    }
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-10', code, 'typescript')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] TypeScript soft delete passes")


def test_typescript_no_delete():
    """Test TypeScript without delete operations (passes)"""
    code = """
async function updateCustomer(id: number, name: string): Promise<Customer> {
    const customer = await customerRepository.findOne({ where: { id } });
    if (customer) {
        customer.name = name;
        return await customerRepository.save(customer);
    }
    throw new Error('Customer not found');
}
"""
    factory = get_factory()
    result = factory.analyze('KSI-SVC-10', code, 'typescript')
    
    assert len(result.findings) == 0, f"Expected 0 findings, got {len(result.findings)}"
    print("[PASS] TypeScript without delete passes")


if __name__ == '__main__':
    print("=" * 80)
    print("KSI-SVC-10 COMPREHENSIVE TEST SUITE")
    print("Testing: Data Destruction (Soft Delete)")
    print("=" * 80)
    print()
    
    tests = [
        ("Python hard delete", test_python_hard_delete),
        ("Python soft delete", test_python_soft_delete),
        ("Python no delete", test_python_no_delete),
        ("C# hard delete", test_csharp_hard_delete),
        ("C# soft delete", test_csharp_soft_delete),
        ("C# no delete", test_csharp_no_delete),
        ("Java hard delete", test_java_hard_delete),
        ("Java soft delete", test_java_soft_delete),
        ("Java no delete", test_java_no_delete),
        ("TypeScript hard delete", test_typescript_hard_delete),
        ("TypeScript soft delete", test_typescript_soft_delete),
        ("TypeScript no delete", test_typescript_no_delete),
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
    
    print()
    print("=" * 80)
    print(f"Total: {len(tests)} | Passed: {passed} | Failed: {failed}")
    if failed == 0:
        print("ALL KSI-SVC-10 TESTS PASSED [PASS]")
    else:
        print(f"TESTS FAILED: {failed}/{len(tests)} [FAIL]")
    print("=" * 80)
    
    sys.exit(0 if failed == 0 else 1)
