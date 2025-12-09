"""
Comprehensive tests for KSI-MLA-02: Audit Logging (AST-based)

Tests all language analyzers with positive and negative cases.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from fedramp_20x_mcp.analyzers.ksi.ksi_mla_02 import KSI_MLA_02_Analyzer


def test_python_auth_without_logging():
    """Test Python authentication function without logging."""
    code = '''
def authenticate_user(username, password):
    user = User.query.filter_by(username=username).first()
    if user and check_password(password, user.password_hash):
        return user
    return None
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_python(code)
    
    auth_findings = [f for f in findings if "authenticate" in f.title.lower() or "password" in f.title.lower()]
    assert len(auth_findings) > 0, "Should detect auth function without logging"
    print("[PASS] Python auth function without logging detected")


def test_python_auth_with_logging():
    """Test Python authentication with proper logging."""
    code = '''
import logging

def authenticate_user(username, password):
    logger.info("Authentication attempt", extra={"username": username})
    user = User.query.filter_by(username=username).first()
    if user and check_password(password, user.password_hash):
        logger.info("Authentication successful", extra={"user_id": user.id})
        return user
    logger.warning("Authentication failed", extra={"username": username})
    return None
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_python(code)
    
    # Should not flag the auth function since it has logging
    auth_findings = [f for f in findings if "authenticate" in f.title.lower() and "function" in f.title.lower()]
    assert len(auth_findings) == 0, "Should not flag auth function with logging"
    print("[PASS] Python auth with logging passes")


def test_python_decorator_without_logging():
    """Test Python protected endpoint without logging."""
    code = '''
@login_required
def protected_view(request):
    return render(request, 'protected.html')
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_python(code)
    
    decorator_findings = [f for f in findings if "protected endpoint" in f.title.lower() or "login_required" in f.description.lower()]
    assert len(decorator_findings) > 0, "Should detect protected endpoint without logging"
    print("[PASS] Python decorator without logging detected")


def test_python_decorator_with_logging():
    """Test Python protected endpoint with logging."""
    code = '''
import logging

@login_required
def protected_view(request):
    logger.info("Access to protected resource", extra={"user_id": request.user.id})
    return render(request, 'protected.html')
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_python(code)
    
    decorator_findings = [f for f in findings if "protected endpoint" in f.title.lower()]
    assert len(decorator_findings) == 0, "Should not flag protected endpoint with logging"
    print("[PASS] Python decorator with logging passes")


def test_csharp_controller_without_logger():
    """Test C# controller without ILogger."""
    code = '''
public class UserController : Controller
{
    private readonly UserService _userService;
    
    public UserController(UserService userService)
    {
        _userService = userService;
    }
    
    public async Task<IActionResult> SignIn([FromBody] LoginRequest request)
    {
        var result = await _userService.SignInAsync(request);
        return Ok(result);
    }
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_csharp(code)
    
    controller_findings = [f for f in findings if "controller" in f.title.lower() and "ilogger" in f.title.lower()]
    assert len(controller_findings) > 0, "Should detect controller without ILogger"
    print("[PASS] C# controller without ILogger detected")


def test_csharp_controller_with_logger():
    """Test C# controller with ILogger."""
    code = '''
public class UserController : Controller
{
    private readonly ILogger<UserController> _logger;
    private readonly UserService _userService;
    
    public UserController(ILogger<UserController> logger, UserService userService)
    {
        _logger = logger;
        _userService = userService;
    }
    
    public async Task<IActionResult> SignIn([FromBody] LoginRequest request)
    {
        _logger.LogInformation("Sign in attempt for user {Username}", request.Username);
        var result = await _userService.SignInAsync(request);
        return Ok(result);
    }
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_csharp(code)
    
    controller_findings = [f for f in findings if "controller" in f.title.lower() and "ilogger" in f.title.lower()]
    assert len(controller_findings) == 0, "Should not flag controller with ILogger"
    print("[PASS] C# controller with ILogger passes")


def test_csharp_signin_without_logging():
    """Test C# sign-in operation without logging."""
    code = '''
public class AuthService
{
    public async Task<User> SignInAsync(string username, string password)
    {
        var user = await _userManager.FindByNameAsync(username);
        if (user != null)
        {
            await _signInManager.SignInAsync(user, isPersistent: false);
            return user;
        }
        return null;
    }
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_csharp(code)
    
    signin_findings = [f for f in findings if "sign in" in f.title.lower()]
    assert len(signin_findings) > 0, "Should detect SignInAsync without logging"
    print("[PASS] C# sign-in without logging detected")


def test_csharp_signin_with_logging():
    """Test C# sign-in operation with logging."""
    code = '''
public class AuthService
{
    private readonly ILogger<AuthService> _logger;
    
    public async Task<User> SignInAsync(string username, string password)
    {
        _logger.LogInformation("Sign in attempt for {Username}", username);
        var user = await _userManager.FindByNameAsync(username);
        if (user != null)
        {
            await _signInManager.SignInAsync(user, isPersistent: false);
            _logger.LogInformation("User {UserId} signed in successfully", user.Id);
            return user;
        }
        _logger.LogWarning("Sign in failed for {Username}", username);
        return null;
    }
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_csharp(code)
    
    signin_findings = [f for f in findings if "sign in" in f.title.lower() and "without" in f.title.lower()]
    assert len(signin_findings) == 0, "Should not flag SignInAsync with logging"
    print("[PASS] C# sign-in with logging passes")


def test_java_spring_auth_without_logging():
    """Test Java Spring Security annotation without logging."""
    code = '''
@RestController
public class AdminController {
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/users")
    public List<User> getUsers() {
        return userService.getAllUsers();
    }
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_java(code)
    
    auth_findings = [f for f in findings if "authorization" in f.title.lower()]
    assert len(auth_findings) > 0, "Should detect @PreAuthorize without logging"
    print("[PASS] Java Spring Security annotation without logging detected")


def test_java_spring_auth_with_logging():
    """Test Java Spring Security with logging."""
    code = '''
@RestController
public class AdminController {
    private static final Logger log = LoggerFactory.getLogger(AdminController.class);
    
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/users")
    public List<User> getUsers() {
        log.info("Admin access to user list");
        return userService.getAllUsers();
    }
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_java(code)
    
    auth_findings = [f for f in findings if "authorization" in f.title.lower() and "without" in f.title.lower()]
    assert len(auth_findings) == 0, "Should not flag @PreAuthorize with logging"
    print("[PASS] Java Spring Security with logging passes")


def test_java_missing_logger():
    """Test Java class without logger declaration."""
    code = '''
@Service
public class UserService {
    private final UserRepository userRepository;
    
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
    
    public User findById(Long id) {
        return userRepository.findById(id).orElse(null);
    }
    
    public List<User> findAll() {
        return userRepository.findAll();
    }
    
    public User create(User user) {
        return userRepository.save(user);
    }
    
    public User update(User user) {
        return userRepository.save(user);
    }
    
    public void delete(Long id) {
        userRepository.deleteById(id);
    }
    
    public boolean exists(Long id) {
        return userRepository.existsById(id);
    }
    
    public long count() {
        return userRepository.count();
    }
    
    public List<User> findByRole(String role) {
        return userRepository.findByRole(role);
    }
    
    public List<User> findActiveUsers() {
        return userRepository.findByActive(true);
    }
    
    // Additional methods to make file longer
    public void performAction1() { }
    public void performAction2() { }
    public void performAction3() { }
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_java(code, "UserService.java")
    
    logger_findings = [f for f in findings if "missing logger" in f.title.lower()]
    assert len(logger_findings) > 0, "Should detect missing logger declaration"
    print("[PASS] Java missing logger detected")


def test_java_with_slf4j():
    """Test Java class with @Slf4j annotation."""
    code = '''
@Slf4j
@Service
public class UserService {
    private final UserRepository userRepository;
    
    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    public User findByUsername(String username) {
        log.debug("Finding user by username: {}", username);
        return userRepository.findByUsername(username);
    }
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_java(code, "UserService.java")
    
    logger_findings = [f for f in findings if "missing logger" in f.title.lower()]
    assert len(logger_findings) == 0, "Should not flag class with @Slf4j"
    print("[PASS] Java with @Slf4j passes")


def test_typescript_passport_without_logging():
    """Test TypeScript Passport authentication without logging."""
    code = '''
app.post('/login', 
    passport.authenticate('local', { failureRedirect: '/login' }),
    (req, res) => {
        res.redirect('/dashboard');
    }
);
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_typescript(code)
    
    auth_findings = [f for f in findings if "authentication" in f.title.lower()]
    assert len(auth_findings) > 0, "Should detect passport.authenticate without logging"
    print("[PASS] TypeScript Passport without logging detected")


def test_typescript_passport_with_logging():
    """Test TypeScript Passport with logging."""
    code = '''
app.post('/login', 
    passport.authenticate('local', { failureRedirect: '/login' }),
    (req, res) => {
        logger.info('User logged in', { userId: req.user.id, ip: req.ip });
        res.redirect('/dashboard');
    }
);
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_typescript(code)
    
    auth_findings = [f for f in findings if "authentication" in f.title.lower() and "without" in f.title.lower()]
    assert len(auth_findings) == 0, "Should not flag passport.authenticate with logging"
    print("[PASS] TypeScript Passport with logging passes")


def test_typescript_nestjs_guard_without_logging():
    """Test NestJS guard without logging."""
    code = '''
@Controller('admin')
export class AdminController {
    @UseGuards(AuthGuard)
    @Get('users')
    getUsers() {
        return this.userService.findAll();
    }
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_typescript(code)
    
    guard_findings = [f for f in findings if "guard" in f.title.lower()]
    assert len(guard_findings) > 0, "Should detect @UseGuards without logging"
    print("[PASS] TypeScript NestJS guard without logging detected")


def test_typescript_nestjs_guard_with_logging():
    """Test NestJS guard with logging."""
    code = '''
@Controller('admin')
export class AdminController {
    private readonly logger = new Logger(AdminController.name);
    
    @UseGuards(AuthGuard)
    @Get('users')
    getUsers(@Request() req) {
        this.logger.log(`Admin access by user ${req.user.id}`);
        return this.userService.findAll();
    }
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_typescript(code)
    
    guard_findings = [f for f in findings if "guard" in f.title.lower() and "without" in f.title.lower()]
    assert len(guard_findings) == 0, "Should not flag @UseGuards with logging"
    print("[PASS] TypeScript NestJS guard with logging passes")


def test_bicep_keyvault_without_diagnostics():
    """Test Bicep Key Vault without diagnostic settings."""
    code = '''
resource keyVault 'Microsoft.KeyVault/vaults@2021-10-01' = {
  name: 'myKeyVault'
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
  }
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_bicep(code)
    
    assert len(findings) > 0, "Should detect Key Vault without diagnostic settings"
    assert any("diagnostic" in f.title.lower() for f in findings)
    print("[PASS] Bicep Key Vault without diagnostics detected")


def test_bicep_keyvault_with_diagnostics():
    """Test Bicep Key Vault with diagnostic settings."""
    code = '''
resource keyVault 'Microsoft.KeyVault/vaults@2021-10-01' = {
  name: 'myKeyVault'
  location: location
  properties: {
    tenantId: subscription().tenantId
    sku: {
      family: 'A'
      name: 'standard'
    }
  }
}

resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'kvDiagnostics'
  scope: keyVault
  properties: {
    logs: [
      {
        category: 'AuditEvent'
        enabled: true
      }
    ]
  }
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_bicep(code)
    
    assert len(findings) == 0, "Should not flag Key Vault with diagnostic settings"
    print("[PASS] Bicep Key Vault with diagnostics passes")


def test_terraform_storage_without_diagnostics():
    """Test Terraform storage account without monitoring."""
    code = '''
resource "azurerm_storage_account" "example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_terraform(code)
    
    assert len(findings) > 0, "Should detect storage account without diagnostic settings"
    assert any("diagnostic" in f.title.lower() for f in findings)
    print("[PASS] Terraform storage without diagnostics detected")


def test_terraform_storage_with_diagnostics():
    """Test Terraform storage account with monitoring."""
    code = '''
resource "azurerm_storage_account" "example" {
  name                     = "storageaccountname"
  resource_group_name      = azurerm_resource_group.example.name
  location                 = azurerm_resource_group.example.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_monitor_diagnostic_setting" "example" {
  name               = "storage-diag"
  target_resource_id = azurerm_storage_account.example.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id

  log {
    category = "StorageRead"
    enabled  = true
  }
}
'''
    
    analyzer = KSI_MLA_02_Analyzer()
    findings = analyzer.analyze_terraform(code)
    
    assert len(findings) == 0, "Should not flag storage account with diagnostic settings"
    print("[PASS] Terraform storage with diagnostics passes")


if __name__ == "__main__":
    print("\nTesting KSI-MLA-02: Audit Logging (AST-based)\n")
    
    # Python tests
    test_python_auth_without_logging()
    test_python_auth_with_logging()
    test_python_decorator_without_logging()
    test_python_decorator_with_logging()
    
    # C# tests
    test_csharp_controller_without_logger()
    test_csharp_controller_with_logger()
    test_csharp_signin_without_logging()
    test_csharp_signin_with_logging()
    
    # Java tests
    test_java_spring_auth_without_logging()
    test_java_spring_auth_with_logging()
    test_java_missing_logger()
    test_java_with_slf4j()
    
    # TypeScript tests
    test_typescript_passport_without_logging()
    test_typescript_passport_with_logging()
    test_typescript_nestjs_guard_without_logging()
    test_typescript_nestjs_guard_with_logging()
    
    # Bicep tests
    test_bicep_keyvault_without_diagnostics()
    test_bicep_keyvault_with_diagnostics()
    
    # Terraform tests
    test_terraform_storage_without_diagnostics()
    test_terraform_storage_with_diagnostics()
    
    print("\n" + "="*50)
    print("ALL KSI-MLA-02 TESTS PASSED [PASS]")
    print("="*50)
