"""
KSI-MLA-07: Event Types

Maintain a list of information resources and event types that will be monitored, logged, and audited, then do so.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_MLA_07_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-MLA-07: Event Types
    
    **Official Statement:**
    Maintain a list of information resources and event types that will be monitored, logged, and audited, then do so.
    
    **Family:** MLA - Monitoring, Logging, and Auditing
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-2.4
    - ac-6.9
    - ac-17.1
    - ac-20.1
    - au-2
    - au-7.1
    - au-12
    - si-4.4
    - si-4.5
    - si-7.7
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Maintain a list of information resources and event types that will be monitored, logged, and audited...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-MLA-07"
    KSI_NAME = "Event Types"
    KSI_STATEMENT = """Maintain a list of information resources and event types that will be monitored, logged, and audited, then do so."""
    FAMILY = "MLA"
    FAMILY_NAME = "Monitoring, Logging, and Auditing"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["ac-2.4", "ac-6.9", "ac-17.1", "ac-20.1", "au-2", "au-7.1", "au-12", "si-4.4", "si-4.5", "si-7.7"]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
    def __init__(self):
        super().__init__(
            ksi_id=self.KSI_ID,
            ksi_name=self.KSI_NAME,
            ksi_statement=self.KSI_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-MLA-07 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Missing audit logging for authentication events
        - Missing audit logging for authorization checks
        - Missing audit logging for data access operations
        - Missing audit logging for configuration changes
        """
        findings = []
        lines = code.split('\n')
        
        # Check for authentication without logging
        has_auth = bool(re.search(r'(def\s+login|def\s+authenticate|@login_required|authenticate\()', code, re.IGNORECASE))
        has_logging = bool(re.search(r'(import logging|logger\.|log\.)', code, re.IGNORECASE))
        
        if has_auth and not has_logging:
            auth_line = self._find_line(lines, 'def login') or self._find_line(lines, 'authenticate')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Audit Logging for Authentication",
                description=f"File '{file_path}' contains authentication logic but does not import logging. KSI-MLA-07 requires audit logging for all security events.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=auth_line,
                code_snippet=self._get_snippet(lines, auth_line),
                remediation="""Add comprehensive audit logging for authentication events:

```python
import logging
from azure.monitor.opentelemetry import configure_azure_monitor

logger = logging.getLogger(__name__)

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

def login(username, password):
    logger.info(f"Authentication attempt for user: {username}")
    
    if authenticate(username, password):
        logger.info(f"Authentication successful for user: {username}", extra={
            'event_type': 'authentication',
            'action': 'login_success',
            'user': username,
            'ip_address': request.remote_addr
        })
        return True
    else:
        logger.warning(f"Authentication failed for user: {username}", extra={
            'event_type': 'authentication',
            'action': 'login_failure',
            'user': username,
            'ip_address': request.remote_addr
        })
        return False
```

Reference: FRR-MLA-07 - Event Types for Monitoring and Auditing"""
            ))
        
        # Check for authorization checks without logging
        has_authz = bool(re.search(r'(@require_role|@require_permission|check_permission|has_permission)', code, re.IGNORECASE))
        if has_authz and not has_logging:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Audit Logging for Authorization",
                description=f"File '{file_path}' contains authorization checks but no audit logging. All access control decisions must be logged per KSI-MLA-07.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add audit logging for authorization decisions:

```python
def check_permission(user, resource, action):
    allowed = user.has_permission(resource, action)
    
    logger.info(f"Authorization check: {action} on {resource}", extra={
        'event_type': 'authorization',
        'user': user.id,
        'resource': resource,
        'action': action,
        'result': 'allowed' if allowed else 'denied'
    })
    
    return allowed
```"""
            ))
        
        # Check for database operations without logging
        has_db_ops = bool(re.search(r'(execute\(|executemany\(|\.save\(|\.delete\(|\.update\()', code, re.IGNORECASE))
        if has_db_ops and not has_logging:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Audit Logging for Data Operations",
                description=f"File '{file_path}' performs database operations without audit logging. KSI-MLA-07 requires logging data access and modifications.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add audit logging for data operations:

```python
def update_user_data(user_id, data):
    logger.info(f"Data modification initiated", extra={
        'event_type': 'data_access',
        'action': 'update',
        'resource': 'user_data',
        'user_id': user_id,
        'fields_modified': list(data.keys())
    })
    
    result = db.users.update_one({'_id': user_id}, {'$set': data})
    
    logger.info(f"Data modification completed", extra={
        'event_type': 'data_access',
        'action': 'update_complete',
        'records_affected': result.modified_count
    })
```"""
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-MLA-07 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Missing ILogger injection and usage
        - Missing audit logging for authentication/authorization
        - Missing logging for data operations
        """
        findings = []
        lines = code.split('\n')
        
        # Check for authentication/authorization attributes without logging
        has_auth = bool(re.search(r'(\[Authorize\]|\[AllowAnonymous\]|SignInAsync|AuthenticateAsync)', code))
        has_logging = bool(re.search(r'(ILogger|_logger\.|Log\.)', code))
        
        if has_auth and not has_logging:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Audit Logging for Authentication",
                description=f"File '{file_path}' uses authentication/authorization but does not inject ILogger. KSI-MLA-07 requires audit logging.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add ILogger and audit logging:

```csharp
using Microsoft.Extensions.Logging;

public class AccountController : Controller
{
    private readonly ILogger<AccountController> _logger;
    
    public AccountController(ILogger<AccountController> logger)
    {
        _logger = logger;
    }
    
    [HttpPost]
    public async Task<IActionResult> Login(LoginModel model)
    {
        _logger.LogInformation("Authentication attempt for user: {Username}", model.Username);
        
        var result = await _signInManager.PasswordSignInAsync(
            model.Username, model.Password, model.RememberMe, lockoutOnFailure: true);
        
        if (result.Succeeded)
        {
            _logger.LogInformation(
                "Authentication successful for user: {Username} from IP: {IpAddress}",
                model.Username, HttpContext.Connection.RemoteIpAddress);
        }
        else
        {
            _logger.LogWarning(
                "Authentication failed for user: {Username} from IP: {IpAddress}",
                model.Username, HttpContext.Connection.RemoteIpAddress);
        }
        
        return result.Succeeded ? RedirectToAction("Index") : View(model);
    }
}
```

Reference: FRR-MLA-07 - Event Types"""
            ))
        
        # Check for controller actions without logging
        has_controller = bool(re.search(r': Controller|: ControllerBase', code))
        if has_controller and not has_logging:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing ILogger in Controller",
                description=f"Controller in '{file_path}' does not use ILogger. All API endpoints should log access per KSI-MLA-07.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Inject ILogger in controller:

```csharp
public class ApiController : ControllerBase
{
    private readonly ILogger<ApiController> _logger;
    
    public ApiController(ILogger<ApiController> logger)
    {
        _logger = logger;
    }
    
    [HttpGet("{id}")]
    public async Task<IActionResult> GetData(int id)
    {
        _logger.LogInformation("Data access request: {Resource} ID: {Id} User: {User}",
            "data", id, User.Identity.Name);
        
        var data = await _repository.GetByIdAsync(id);
        
        _logger.LogInformation("Data access completed: {Resource} ID: {Id}",
            "data", id);
        
        return Ok(data);
    }
}
```"""
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-MLA-07 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Missing Logger/Slf4j logging
        - Missing audit logging for security events
        - Missing logging for REST endpoints
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Spring Security without logging
        has_security = bool(re.search(r'(@PreAuthorize|@Secured|@RolesAllowed|SecurityContextHolder)', code))
        has_logging = bool(re.search(r'(import.*Logger|@Slf4j|log\.|logger\.)', code))
        
        if has_security and not has_logging:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Audit Logging for Security Events",
                description=f"File '{file_path}' uses Spring Security but lacks logging. KSI-MLA-07 requires audit logging for all authorization checks.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add Slf4j logging for security events:

```java
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;

@Slf4j
@RestController
@RequestMapping("/api")
public class SecureController {
    
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/admin/data")
    public ResponseEntity<?> getAdminData() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        
        log.info("Authorization check: action=access_admin_data user={} roles={}",
            auth.getName(), auth.getAuthorities());
        
        var data = adminService.getData();
        
        log.info("Admin data access: user={} records={}",
            auth.getName(), data.size());
        
        return ResponseEntity.ok(data);
    }
}
```

Reference: FRR-MLA-07 - Event Types"""
            ))
        
        # Check for REST controllers without logging
        has_rest_controller = bool(re.search(r'@RestController|@Controller', code))
        if has_rest_controller and not has_logging:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Logger in REST Controller",
                description=f"REST controller in '{file_path}' does not use logging. All API endpoints should log access per KSI-MLA-07.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add Slf4j logging:

```java
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RestController
public class DataController {
    
    @GetMapping("/data/{id}")
    public ResponseEntity<?> getData(@PathVariable Long id, Principal principal) {
        log.info("Data access request: resource=data id={} user={}",
            id, principal.getName());
        
        var data = dataService.findById(id);
        
        if (data.isEmpty()) {
            log.warn("Data not found: resource=data id={} user={}",
                id, principal.getName());
            return ResponseEntity.notFound().build();
        }
        
        log.info("Data access successful: resource=data id={}", id);
        return ResponseEntity.ok(data.get());
    }
}
```"""
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-MLA-07 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Missing Winston/Pino logging imports
        - Missing audit logging for authentication
        - Missing logging for API routes
        """
        findings = []
        lines = code.split('\n')
        
        # Check for authentication without logging
        has_auth = bool(re.search(r'(passport\.|jwt\.sign|jwt\.verify|authenticate\(|login\()', code, re.IGNORECASE))
        has_logging = bool(re.search(r'(import.*winston|import.*pino|console\.log|logger\.)', code, re.IGNORECASE))
        
        if has_auth and not has_logging:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Audit Logging for Authentication",
                description=f"File '{file_path}' handles authentication but lacks structured logging. KSI-MLA-07 requires audit logging for security events.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add Winston or Pino for structured logging:

```typescript
import winston from 'winston';
import { Request, Response } from 'express';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console(),
    new winston.transports.File({ filename: 'audit.log' })
  ]
});

export async function login(req: Request, res: Response) {
  const { username, password } = req.body;
  
  logger.info('Authentication attempt', {
    event_type: 'authentication',
    action: 'login_attempt',
    username,
    ip_address: req.ip
  });
  
  const user = await authenticateUser(username, password);
  
  if (user) {
    logger.info('Authentication successful', {
      event_type: 'authentication',
      action: 'login_success',
      username,
      user_id: user.id,
      ip_address: req.ip
    });
    
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET);
    return res.json({ token });
  } else {
    logger.warn('Authentication failed', {
      event_type: 'authentication',
      action: 'login_failure',
      username,
      ip_address: req.ip
    });
    
    return res.status(401).json({ error: 'Invalid credentials' });
  }
}
```

Reference: FRR-MLA-07 - Event Types"""
            ))
        
        # Check for Express routes without logging
        has_routes = bool(re.search(r'(app\.(get|post|put|delete)|router\.(get|post|put|delete)|@(Get|Post|Put|Delete))', code, re.IGNORECASE))
        if has_routes and not has_logging:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Logging in API Routes",
                description=f"File '{file_path}' defines API routes without logging. All endpoints should log access per KSI-MLA-07.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add logging to API routes:

```typescript
import { Logger } from '@nestjs/common';

export class DataController {
  private readonly logger = new Logger(DataController.name);
  
  @Get(':id')
  async getData(@Param('id') id: string, @Req() req: Request) {
    this.logger.log(`Data access request: resource=data id=${id} user=${req.user?.id}`);
    
    const data = await this.dataService.findById(id);
    
    this.logger.log(`Data access completed: resource=data id=${id}`);
    
    return data;
  }
}
```"""
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-MLA-07 compliance.
        
        Detects:
        - Missing Log Analytics workspace
        - Missing diagnostic settings on resources
        - Missing Application Insights
        """
        findings = []
        lines = code.split('\n')
        
        # Check for resources without diagnostic settings
        has_resources = bool(re.search(r"resource\s+\w+\s+'Microsoft\.(Web|Storage|KeyVault|Sql|ContainerRegistry)", code))
        has_diagnostics = bool(re.search(r"Microsoft\.Insights/diagnosticSettings", code))
        
        if has_resources and not has_diagnostics:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Diagnostic Settings for Audit Logging",
                description=f"Bicep template '{file_path}' deploys Azure resources without diagnostic settings. KSI-MLA-07 requires audit logging for all resources.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add diagnostic settings to enable audit logging:

```bicep
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'law-${uniqueString(resourceGroup().id)}'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90
  }
}

resource webApp 'Microsoft.Web/sites@2023-01-01' = {
  name: 'webapp-example'
  location: location
  properties: {
    // ... web app properties
  }
}

resource webAppDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: 'diagnostics'
  scope: webApp
  properties: {
    workspaceId: logAnalytics.id
    logs: [
      {
        category: 'AppServiceHTTPLogs'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
      {
        category: 'AppServiceConsoleLogs'
        enabled: true
      }
      {
        category: 'AppServiceAppLogs'
        enabled: true
      }
      {
        category: 'AppServiceAuditLogs'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}
```

Reference: FRR-MLA-07 - Event Types for Monitoring"""
            ))
        
        # Check for Log Analytics workspace
        has_log_analytics = bool(re.search(r"Microsoft\.OperationalInsights/workspaces", code))
        if has_resources and not has_log_analytics:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Log Analytics Workspace",
                description=f"Bicep template '{file_path}' does not deploy a Log Analytics workspace. KSI-MLA-07 requires centralized logging.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Deploy Log Analytics workspace for centralized audit logging:

```bicep
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'law-${uniqueString(resourceGroup().id)}'
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 90  // FedRAMP requires 90+ days retention
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
  tags: {
    purpose: 'audit-logging'
    compliance: 'fedramp'
  }
}
```"""
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-MLA-07 compliance.
        
        Detects:
        - Missing azurerm_log_analytics_workspace
        - Missing azurerm_monitor_diagnostic_setting
        - Resources without audit logging
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Azure resources without diagnostic settings
        has_resources = bool(re.search(r'resource "azurerm_(app_service|storage_account|key_vault|sql_server|container_registry)', code))
        has_diagnostics = bool(re.search(r'azurerm_monitor_diagnostic_setting', code))
        
        if has_resources and not has_diagnostics:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Diagnostic Settings for Audit Logging",
                description=f"Terraform configuration '{file_path}' deploys Azure resources without diagnostic settings. KSI-MLA-07 requires audit logging.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add diagnostic settings for audit logging:

```hcl
resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 90  # FedRAMP requires 90+ days
  
  tags = {
    purpose    = "audit-logging"
    compliance = "fedramp"
  }
}

resource "azurerm_app_service" "main" {
  name                = "app-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  app_service_plan_id = azurerm_app_service_plan.main.id
}

resource "azurerm_monitor_diagnostic_setting" "app_service" {
  name                       = "diagnostics"
  target_resource_id         = azurerm_app_service.main.id
  log_analytics_workspace_id = azurerm_log_analytics_workspace.main.id

  enabled_log {
    category = "AppServiceHTTPLogs"
  }
  
  enabled_log {
    category = "AppServiceConsoleLogs"
  }
  
  enabled_log {
    category = "AppServiceAuditLogs"
  }

  metric {
    category = "AllMetrics"
    enabled  = true
  }
}
```

Reference: FRR-MLA-07 - Event Types"""
            ))
        
        # Check for Log Analytics workspace
        has_log_analytics = bool(re.search(r'azurerm_log_analytics_workspace', code))
        if has_resources and not has_log_analytics:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Log Analytics Workspace",
                description=f"Terraform configuration '{file_path}' does not provision Log Analytics workspace. KSI-MLA-07 requires centralized logging.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add Log Analytics workspace:

```hcl
resource "azurerm_log_analytics_workspace" "main" {
  name                = "law-${var.environment}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
}
```"""
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-MLA-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-MLA-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-MLA-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], search_term: str) -> int:
        """Find line number containing search term."""
        for i, line in enumerate(lines, 1):
            if search_term.lower() in line.lower():
                return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
