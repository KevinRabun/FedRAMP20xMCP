"""Tests for KSI-MLA-02 Enhanced: Audit Logging"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_mla_02 import KSI_MLA_02_Analyzer
from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_auth_without_logging():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
def authenticate(username, password):
    user = User.objects.get(username=username)
    if user.check_password(password):
        return user
    return None
"""
    result = analyzer.analyze(code, "python", "auth.py")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Python auth without logging")


def test_python_with_logging():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
import logging
logger = logging.getLogger(__name__)

def authenticate(username, password):
    logger.info(f"Auth attempt: {username}")
    user = User.objects.get(username=username)
    if user.check_password(password):
        logger.info(f"Auth success: {username}")
        return user
    logger.warning(f"Auth failed: {username}")
    return None
"""
    result = analyzer.analyze(code, "python", "auth.py")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Python with logging")


def test_python_missing_config():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
from flask import Flask
app = Flask(__name__)

@app.route('/users')
def get_users():
    return User.query.all()

# Many more lines...
""" + "\n".join([f"# Line {i}" for i in range(50)])
    result = analyzer.analyze(code, "python", "app.py")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] Python missing config")


def test_csharp_controller_no_logger():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
[ApiController]
[Route("api/[controller]")]
public class UsersController : ControllerBase
{
    private readonly IUserService _userService;
    
    public UsersController(IUserService userService)
    {
        _userService = userService;
    }
}
"""
    result = analyzer.analyze(code, "csharp", "UsersController.cs")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] C# controller no logger")


def test_csharp_with_logger():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
[ApiController]
public class AuthController : ControllerBase
{
    private readonly ILogger<AuthController> _logger;
    
    public AuthController(ILogger<AuthController> logger)
    {
        _logger = logger;
    }
    
    [HttpPost("login")]
    public async Task<IActionResult> Login()
    {
        _logger.LogInformation("Login attempt");
        await SignInAsync(user);
        _logger.LogInformation("Login success");
        return Ok();
    }
}
"""
    result = analyzer.analyze(code, "csharp", "AuthController.cs")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] C# with logger")


def test_csharp_signin_without_logging():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
public class AuthService
{
    public async Task LoginUser(string username)
    {
        var user = await _userManager.FindByNameAsync(username);
        await SignInAsync(user, isPersistent: false);
    }
}
"""
    result = analyzer.analyze(code, "csharp", "AuthService.cs")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] C# SignIn without logging")


def test_java_auth_without_logging():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
@Service
public class AuthService {
    @Autowired
    private AuthenticationManager authenticationManager;
    
    public void authenticate(String username, String password) {
        Authentication auth = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(username, password)
        );
    }
}
"""
    result = analyzer.analyze(code, "java", "AuthService.java")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Java auth without logging")


def test_java_with_logger():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class AuthService {
    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    
    public void authenticate(String username) {
        log.info("Auth attempt: {}", username);
        authenticationManager.authenticate(creds);
        log.info("Auth success: {}", username);
    }
}
"""
    result = analyzer.analyze(code, "java", "AuthService.java")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Java with logger")


def test_java_missing_logger():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;
    
    @GetMapping
    public List<User> getUsers() {
        return userService.findAll();
    }
    
""" + "\n".join([f"    // Line {i}" for i in range(50)])
    result = analyzer.analyze(code, "java", "UserController.java")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] Java missing logger")


def test_typescript_auth_without_logging():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
export class AuthService {
    async login(username: string, password: string) {
        const token = jwt.sign({ username }, SECRET);
        return token;
    }
}
"""
    result = analyzer.analyze(code, "typescript", "auth.service.ts")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] TypeScript auth without logging")


def test_typescript_with_logging():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
import winston from 'winston';
const logger = winston.createLogger();

export class AuthService {
    async login(username: string) {
        logger.info('Login attempt', { username });
        const token = jwt.sign({ username }, SECRET);
        logger.info('Login success', { username });
        return token;
    }
}
"""
    result = analyzer.analyze(code, "typescript", "auth.service.ts")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] TypeScript with logging")


def test_typescript_guard_without_logging():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
@Injectable()
export class RolesGuard implements CanActivate {
    canActivate(context: ExecutionContext): boolean {
        const roles = this.reflector.get('roles', context.getHandler());
        return validateRoles(user, roles);
    }
}
"""
    result = analyzer.analyze(code, "typescript", "roles.guard.ts")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] TypeScript guard without logging")


def test_bicep_missing_diagnostics():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
    name: 'kv-${uniqueString(resourceGroup().id)}'
    location: location
    properties: {
        sku: { family: 'A', name: 'standard' }
        tenantId: tenant().tenantId
    }
}
"""
    result = analyzer.analyze(code, "bicep", "main.bicep")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Bicep missing diagnostics")


def test_bicep_with_diagnostics():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
    name: 'kv-test'
    location: location
}

resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
    name: 'diag-kv'
    scope: keyVault
    properties: {
        logs: [{ category: 'AuditEvent', enabled: true }]
    }
}
"""
    result = analyzer.analyze(code, "bicep", "main.bicep")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Bicep with diagnostics")


def test_terraform_missing_diagnostics():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
resource "azurerm_key_vault" "main" {
    name                = "kv-test"
    location            = azurerm_resource_group.main.location
    resource_group_name = azurerm_resource_group.main.name
    tenant_id           = data.azurerm_client_config.current.tenant_id
    sku_name            = "standard"
}
"""
    result = analyzer.analyze(code, "terraform", "main.tf")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Terraform missing diagnostics")


def test_terraform_with_diagnostics():
    analyzer = KSI_MLA_02_Analyzer()
    code = """
resource "azurerm_key_vault" "main" {
    name = "kv-test"
}

resource "azurerm_monitor_diagnostic_setting" "kv" {
    name               = "diag-kv"
    target_resource_id = azurerm_key_vault.main.id
    log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id
}
"""
    result = analyzer.analyze(code, "terraform", "main.tf")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Terraform with diagnostics")


def test_factory():
    factory = get_factory()
    code = """
def login(user, password):
    if check_password(user, password):
        return create_session(user)
"""
    result = factory.analyze("KSI-MLA-02", code, "python", "auth.py")
    assert result.ksi_id == "KSI-MLA-02"
    assert len(result.findings) >= 1
    print("[PASS] Factory integration")


def run_all():
    tests = [
        test_python_auth_without_logging,
        test_python_with_logging,
        test_python_missing_config,
        test_csharp_controller_no_logger,
        test_csharp_with_logger,
        test_csharp_signin_without_logging,
        test_java_auth_without_logging,
        test_java_with_logger,
        test_java_missing_logger,
        test_typescript_auth_without_logging,
        test_typescript_with_logging,
        test_typescript_guard_without_logging,
        test_bicep_missing_diagnostics,
        test_bicep_with_diagnostics,
        test_terraform_missing_diagnostics,
        test_terraform_with_diagnostics,
        test_factory,
    ]
    
    print("\nKSI-MLA-02 Enhanced Tests")
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

