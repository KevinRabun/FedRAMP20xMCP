"""Tests for KSI-MLA-07 Enhanced: Event Types"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_mla_07 import KSI_MLA_07_Analyzer
from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_auth_without_logging():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
def login(username, password):
    user = authenticate(username, password)
    return user
"""
    result = analyzer.analyze(code, "python", "auth.py")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Python auth without logging")


def test_python_with_logging():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
import logging
logger = logging.getLogger(__name__)

def login(username, password):
    logger.info('Login attempt', extra={'event_type': 'authentication'})
    user = authenticate(username, password)
    logger.info('Login success')
    return user
"""
    result = analyzer.analyze(code, "python", "auth.py")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Python with logging")


def test_python_data_access():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
def get_users():
    users = User.query.filter(active=True)
    return users

def get_orders():
    orders = Order.query.all()
    return orders

def get_products():
    products = Product.query.filter(category='electronics')
    return products

def get_invoices():
    invoices = Invoice.query.filter(paid=False)
    return invoices

def get_customers():
    customers = Customer.query.filter(status='active')
    return customers

def get_transactions():
    transactions = Transaction.query.all()
    return transactions
"""
    result = analyzer.analyze(code, "python", "data.py")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] Python data access")


def test_csharp_auth_without_logging():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
public class AuthService
{
    public async Task LoginAsync(string username)
    {
        await SignInAsync(user);
    }
}
"""
    result = analyzer.analyze(code, "csharp", "AuthService.cs")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] C# auth without logging")


def test_csharp_with_logging():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
public class AuthService
{
    private readonly ILogger<AuthService> _logger;
    
    public async Task LoginAsync(string username)
    {
        _logger.LogInformation("Login attempt {username}", username);
        await SignInAsync(user);
        _logger.LogInformation("Login success");
    }
}
"""
    result = analyzer.analyze(code, "csharp", "AuthService.cs")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] C# with logging")


def test_csharp_data_operations():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
public class DataService
{
    public void SaveUser(User user) => _context.Users.Add(user);
    public void UpdateUser(User user) => _context.Users.Update(user);
    public void DeleteUser(User user) => _context.Users.Remove(user);
    public void SaveOrder(Order order) => _context.Orders.Add(order);
}
"""
    result = analyzer.analyze(code, "csharp", "DataService.cs")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] C# data operations")


def test_java_auth_without_logging():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
@Service
public class AuthService {
    @PreAuthorize("hasRole('ADMIN')")
    public void adminOperation() {
        performAction();
    }
}
"""
    result = analyzer.analyze(code, "java", "AuthService.java")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Java auth without logging")


def test_java_with_logging():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class AuthService {
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    
    @PreAuthorize("hasRole('ADMIN')")
    public void adminOperation() {
        log.info("Admin operation attempt");
        performAction();
    }
}
"""
    result = analyzer.analyze(code, "java", "AuthService.java")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Java with logging")


def test_java_repository():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    List<User> findByActive(boolean active);
}
"""
    result = analyzer.analyze(code, "java", "UserRepository.java")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] Java repository")


def test_typescript_guard_without_logging():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
@Injectable()
export class RolesGuard implements CanActivate {
    canActivate(context: ExecutionContext): boolean {
        return validateRoles(user);
    }
}
"""
    result = analyzer.analyze(code, "typescript", "roles.guard.ts")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] TypeScript guard without logging")


def test_typescript_with_logging():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
import { Logger } from '@nestjs/common';

@Injectable()
export class RolesGuard implements CanActivate {
    private readonly logger = new Logger(RolesGuard.name);
    
    canActivate(context: ExecutionContext): boolean {
        this.logger.log('Authorization check');
        return validateRoles(user);
    }
}
"""
    result = analyzer.analyze(code, "typescript", "roles.guard.ts")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] TypeScript with logging")


def test_typescript_data_operations():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
export class DataService {
    save(data: any) { return this.repo.save(data); }
    update(id: number, data: any) { return this.repo.update(id, data); }
    delete(id: number) { return this.repo.delete(id); }
    create(data: any) { return this.repo.create(data); }
    saveUser(user: User) { return this.repo.save(user); }
    updateOrder(order: Order) { return this.repo.update(order); }
}
"""
    result = analyzer.analyze(code, "typescript", "data.service.ts")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] TypeScript data operations")


def test_bicep_missing_diagnostics():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
    name: 'kv-test'
    location: location
}
"""
    result = analyzer.analyze(code, "bicep", "main.bicep")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Bicep missing diagnostics")


def test_bicep_with_diagnostics():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
    name: 'kv-test'
    location: location
}

resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
    scope: keyVault
    name: 'diag'
}
"""
    result = analyzer.analyze(code, "bicep", "main.bicep")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Bicep with diagnostics")


def test_terraform_missing_diagnostics():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
resource "azurerm_key_vault" "main" {
    name     = "kv-test"
    location = azurerm_resource_group.main.location
}
"""
    result = analyzer.analyze(code, "terraform", "main.tf")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Terraform missing diagnostics")


def test_terraform_with_diagnostics():
    analyzer = KSI_MLA_07_Analyzer()
    code = """
resource "azurerm_key_vault" "main" {
    name = "kv-test"
}

resource "azurerm_monitor_diagnostic_setting" "kv" {
    target_resource_id = azurerm_key_vault.main.id
}
"""
    result = analyzer.analyze(code, "terraform", "main.tf")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Terraform with diagnostics")


def test_factory():
    factory = get_factory()
    code = """
def login(user):
    authenticate(user)
"""
    result = factory.analyze("KSI-MLA-07", code, "python", "auth.py")
    assert result.ksi_id == "KSI-MLA-07"
    assert len(result.findings) >= 1
    print("[PASS] Factory integration")


def run_all():
    tests = [
        test_python_auth_without_logging,
        test_python_with_logging,
        test_python_data_access,
        test_csharp_auth_without_logging,
        test_csharp_with_logging,
        test_csharp_data_operations,
        test_java_auth_without_logging,
        test_java_with_logging,
        test_java_repository,
        test_typescript_guard_without_logging,
        test_typescript_with_logging,
        test_typescript_data_operations,
        test_bicep_missing_diagnostics,
        test_bicep_with_diagnostics,
        test_terraform_missing_diagnostics,
        test_terraform_with_diagnostics,
        test_factory,
    ]
    
    print("\nKSI-MLA-07 Enhanced Tests")
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

