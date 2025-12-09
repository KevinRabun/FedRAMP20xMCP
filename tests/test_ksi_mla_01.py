"""
Tests for KSI-MLA-01 Enhanced Analyzer: Security Information and Event Management (SIEM)

Test Coverage:
- Python: Local file logging, missing Azure Monitor, proper integration
- C#: File logging, Serilog file sink, missing Application Insights
- Java: FileAppender, missing Azure Monitor
- TypeScript: File transport, console logging, proper integration
- Bicep: Missing Log Analytics, resources without diagnostic settings
- Terraform: Missing Log Analytics workspace, resources without diagnostic settings
- Factory integration
"""

import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_mla_01 import KSI_MLA_01_Analyzer
from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_local_file_logging():
    """Test detection of local file logging without centralized SIEM."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
import logging

# Configure local file logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)
logger.info('Application started')
"""
    
    result = analyzer.analyze(code, "python", "app.py")
    findings = result.findings
    
    print(f"\n=== Python Local File Logging Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect basicConfig with filename parameter (HIGH) and missing Azure Monitor (MEDIUM)
    assert len(findings) >= 1, "Should detect local file logging issues"
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1, "Should have HIGH severity for file logging"
    assert any("basicConfig" in f.title or "File Logging" in f.title for f in high_findings), \
        "Should detect basicConfig file logging"
    print("[PASS] PASS: Detected local file logging without SIEM")


def test_python_file_handler():
    """Test detection of FileHandler without centralized logging."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
import logging

logger = logging.getLogger(__name__)

# Add file handler for local logging
file_handler = logging.FileHandler('application.log')
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

logger.info('Logging to file')
"""
    
    result = analyzer.analyze(code, "python", "logger_config.py")
    findings = result.findings
    
    print(f"\n=== Python FileHandler Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect FileHandler without centralized logging
    assert len(findings) >= 1, "Should detect FileHandler issues"
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1, "Should have HIGH severity for FileHandler"
    assert any("File Logging" in f.title or "FileHandler" in f.title for f in high_findings), \
        "Should detect FileHandler usage"
    print("[PASS] PASS: Detected FileHandler without centralized SIEM")


def test_python_proper_azure_monitor():
    """Test proper Azure Monitor integration (should not flag)."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
import logging
import os
from opencensus.ext.azure.log_exporter import AzureLogHandler

logger = logging.getLogger(__name__)

# Configure Azure Monitor for centralized logging
connection_string = os.getenv('APPLICATIONINSIGHTS_CONNECTION_STRING')
logger.addHandler(AzureLogHandler(connection_string=connection_string))

logger.info('Logging to Azure Monitor')
"""
    
    result = analyzer.analyze(code, "python", "azure_logger.py")
    findings = result.findings
    
    print(f"\n=== Python Proper Azure Monitor Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should not detect issues with proper Azure Monitor integration
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0, "Should not flag proper Azure Monitor integration"
    print("[PASS] PASS: No issues detected with proper Azure Monitor")


def test_python_direct_file_write():
    """Test detection of direct file writes to log files."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
def log_event(message):
    with open('audit.log', 'w') as log_file:
        log_file.write(f"{message}\\n")

log_event("User login attempt")
"""
    
    result = analyzer.analyze(code, "python", "manual_logging.py")
    findings = result.findings
    
    print(f"\n=== Python Direct File Write Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect direct file write to .log file
    assert len(findings) >= 1, "Should detect direct file write issues"
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1, "Should have HIGH severity for direct file write"
    assert any("File Write" in f.title or "Direct" in f.title for f in high_findings), \
        "Should detect direct file write"
    print("[PASS] PASS: Detected direct file write without SIEM")


def test_csharp_file_logging():
    """Test detection of C# file logging without Application Insights."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
using Microsoft.Extensions.Logging;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddLogging(builder =>
        {
            builder.AddFile("logs/app.log");
        });
    }
}
"""
    
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    findings = result.findings
    
    print(f"\n=== C# File Logging Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect AddFile without Application Insights
    assert len(findings) >= 1, "Should detect file logging issues"
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1, "Should have HIGH severity for file logging"
    assert any("File Logging" in f.title for f in high_findings), \
        "Should detect file logging"
    print("[PASS] PASS: Detected C# file logging without Application Insights")


def test_csharp_serilog_file_sink():
    """Test detection of Serilog WriteTo.File without centralized logging."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
using Serilog;

public class LoggerConfiguration
{
    public static void ConfigureLogger()
    {
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console()
            .WriteTo.File("logs/app.log", rollingInterval: RollingInterval.Day)
            .CreateLogger();
    }
}
"""
    
    result = analyzer.analyze(code, "csharp", "LoggerConfig.cs")
    findings = result.findings
    
    print(f"\n=== C# Serilog File Sink Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect WriteTo.File without Application Insights
    assert len(findings) >= 1, "Should detect Serilog file sink issues"
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1, "Should have HIGH severity for Serilog file sink"
    assert any("Serilog" in f.title or "File" in f.title for f in high_findings), \
        "Should detect Serilog file sink"
    print("[PASS] PASS: Detected Serilog file sink without centralized SIEM")


def test_csharp_missing_application_insights():
    """Test detection of logging without Application Insights integration."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
using Microsoft.Extensions.Logging;

public class UserService
{
    private readonly ILogger<UserService> _logger;
    
    public UserService(ILogger<UserService> logger)
    {
        _logger = logger;
    }
    
    public void ProcessUser()
    {
        _logger.LogInformation("Processing user");
    }
}
"""
    
    result = analyzer.analyze(code, "csharp", "UserService.cs")
    findings = result.findings
    
    print(f"\n=== C# Missing Application Insights Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect ILogger without Application Insights
    assert len(findings) >= 1, "Should detect missing Application Insights"
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    assert len(medium_findings) >= 1, "Should have MEDIUM severity for missing Application Insights"
    assert any("Application Insights" in f.title for f in medium_findings), \
        "Should detect missing Application Insights"
    print("[PASS] PASS: Detected missing Application Insights integration")


def test_csharp_proper_application_insights():
    """Test proper Application Insights integration (should not flag file logging)."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
using Microsoft.ApplicationInsights;
using Microsoft.Extensions.Logging;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddApplicationInsightsTelemetry();
        services.AddLogging();
    }
    
    public void ConfigureLogging(ILoggingBuilder builder)
    {
        builder.AddFile("logs/app.log");  // Still logs locally but also to App Insights
    }
}
"""
    
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    findings = result.findings
    
    print(f"\n=== C# Proper Application Insights Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should not flag HIGH severity issues when Application Insights is present
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0, "Should not flag HIGH severity with Application Insights"
    print("[PASS] PASS: No HIGH severity issues with Application Insights")


def test_java_file_appender():
    """Test detection of Log4j/Logback FileAppender without Azure Monitor."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
import org.apache.log4j.FileAppender;
import org.apache.log4j.Logger;

public class LoggerConfig {
    public static void configureLogger() {
        Logger logger = Logger.getRootLogger();
        FileAppender fileAppender = new FileAppender();
        fileAppender.setFile("logs/application.log");
        logger.addAppender(fileAppender);
    }
}
"""
    
    result = analyzer.analyze(code, "java", "LoggerConfig.java")
    findings = result.findings
    
    print(f"\n=== Java FileAppender Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect FileAppender without Azure Monitor
    assert len(findings) >= 1, "Should detect FileAppender issues"
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1, "Should have HIGH severity for FileAppender"
    assert any("FileAppender" in f.title or "File Appender" in f.title for f in high_findings), \
        "Should detect FileAppender"
    print("[PASS] PASS: Detected FileAppender without centralized SIEM")


def test_java_missing_telemetry():
    """Test detection of logging without centralized telemetry."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    
    public void processUser() {
        logger.info("Processing user");
    }
}
"""
    
    result = analyzer.analyze(code, "java", "UserService.java")
    findings = result.findings
    
    print(f"\n=== Java Missing Telemetry Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect SLF4J without Azure Monitor
    assert len(findings) >= 1, "Should detect missing telemetry"
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    assert len(medium_findings) >= 1, "Should have MEDIUM severity for missing telemetry"
    assert any("Telemetry" in f.title or "Azure Monitor" in f.title for f in medium_findings), \
        "Should detect missing telemetry"
    print("[PASS] PASS: Detected missing centralized telemetry")


def test_typescript_file_transport():
    """Test detection of Winston file transport without Application Insights."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
import winston from 'winston';

const logger = winston.createLogger({
  level: 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

logger.info('Application started');
"""
    
    result = analyzer.analyze(code, "typescript", "logger.ts")
    findings = result.findings
    
    print(f"\n=== TypeScript File Transport Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect File transport without Application Insights
    assert len(findings) >= 1, "Should detect file transport issues"
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1, "Should have HIGH severity for file transport"
    assert any("File Transport" in f.title or "File" in f.title for f in high_findings), \
        "Should detect file transport"
    print("[PASS] PASS: Detected file transport without Application Insights")


def test_typescript_console_logging():
    """Test detection of console.log without centralized monitoring."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
function processUser(userId: string) {
    console.log('Processing user:', userId);
    
    // Business logic
    console.info('User processed successfully');
}

processUser('12345');
"""
    
    result = analyzer.analyze(code, "typescript", "userService.ts")
    findings = result.findings
    
    print(f"\n=== TypeScript Console Logging Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect console logging without Application Insights
    assert len(findings) >= 1, "Should detect console logging issues"
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    assert len(medium_findings) >= 1, "Should have MEDIUM severity for console logging"
    assert any("Console" in f.title for f in medium_findings), \
        "Should detect console logging"
    print("[PASS] PASS: Detected console logging without centralized monitoring")


def test_typescript_proper_app_insights():
    """Test proper Application Insights integration (should not flag)."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
import * as appInsights from 'applicationinsights';

// Configure Application Insights
appInsights.setup(process.env.APPLICATIONINSIGHTS_CONNECTION_STRING)
    .setAutoCollectRequests(true)
    .setAutoCollectPerformance(true)
    .start();

const client = appInsights.defaultClient;

function processUser(userId: string) {
    client.trackTrace({ message: 'Processing user', properties: { userId } });
}
"""
    
    result = analyzer.analyze(code, "typescript", "appInsights.ts")
    findings = result.findings
    
    print(f"\n=== TypeScript Proper Application Insights Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should not flag issues with proper Application Insights
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    assert len(high_findings) == 0, "Should not flag HIGH severity with Application Insights"
    assert len(medium_findings) == 0, "Should not flag MEDIUM severity with Application Insights"
    print("[PASS] PASS: No issues detected with proper Application Insights")


def test_bicep_missing_log_analytics():
    """Test detection of missing Log Analytics workspace in Bicep."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'mystorageaccount'
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
}

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'mykeyvault'
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: tenant().tenantId
  }
}
"""
    
    result = analyzer.analyze(code, "bicep", "main.bicep")
    findings = result.findings
    
    print(f"\n=== Bicep Missing Log Analytics Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect missing Log Analytics workspace
    assert len(findings) >= 1, "Should detect missing Log Analytics"
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 1, "Should have CRITICAL severity for missing Log Analytics"
    assert any("Log Analytics" in f.title for f in critical_findings), \
        "Should detect missing Log Analytics workspace"
    print("[PASS] PASS: Detected missing Log Analytics workspace")


def test_bicep_missing_diagnostic_settings():
    """Test detection of resources without diagnostic settings in Bicep."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'law-${uniqueString(resourceGroup().id)}'
  location: location
  properties: {
    retentionInDays: 90
    sku: {
      name: 'PerGB2018'
    }
  }
}

resource webApp 'Microsoft.Web/sites@2023-01-01' = {
  name: 'mywebapp'
  location: location
  properties: {
    serverFarmId: appServicePlan.id
  }
}
"""
    
    result = analyzer.analyze(code, "bicep", "resources.bicep")
    findings = result.findings
    
    print(f"\n=== Bicep Missing Diagnostic Settings Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect resource without diagnostic settings
    assert len(findings) >= 1, "Should detect missing diagnostic settings"
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1, "Should have HIGH severity for missing diagnostic settings"
    assert any("Diagnostic Settings" in f.title for f in high_findings), \
        "Should detect missing diagnostic settings"
    print("[PASS] PASS: Detected resource without diagnostic settings")


def test_terraform_missing_log_analytics():
    """Test detection of missing Log Analytics workspace in Terraform."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
resource "azurerm_resource_group" "main" {
  name     = "rg-${var.project}"
  location = var.location
}

resource "azurerm_storage_account" "main" {
  name                     = "st${var.project}"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}
"""
    
    result = analyzer.analyze(code, "terraform", "main.tf")
    findings = result.findings
    
    print(f"\n=== Terraform Missing Log Analytics Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect missing Log Analytics workspace
    assert len(findings) >= 1, "Should detect missing Log Analytics"
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 1, "Should have CRITICAL severity for missing Log Analytics"
    assert any("Log Analytics" in f.title for f in critical_findings), \
        "Should detect missing Log Analytics workspace"
    print("[PASS] PASS: Detected missing Log Analytics workspace")


def test_terraform_missing_diagnostic_settings():
    """Test detection of resources without diagnostic settings in Terraform."""
    analyzer = KSI_MLA_01_Analyzer()
    
    code = """
resource "azurerm_log_analytics_workspace" "siem" {
  name                = "law-${var.project}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  sku                 = "PerGB2018"
  retention_in_days   = 90
}

resource "azurerm_key_vault" "main" {
  name                = "kv-${var.project}"
  location            = azurerm_resource_group.main.location
  resource_group_name = azurerm_resource_group.main.name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"
}
"""
    
    result = analyzer.analyze(code, "terraform", "keyvault.tf")
    findings = result.findings
    
    print(f"\n=== Terraform Missing Diagnostic Settings Test ===")
    print(f"Findings: {len(findings)}")
    for f in findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    # Should detect resource without diagnostic settings
    assert len(findings) >= 1, "Should detect missing diagnostic settings"
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) >= 1, "Should have HIGH severity for missing diagnostic settings"
    assert any("Diagnostic Settings" in f.title for f in high_findings), \
        "Should detect missing diagnostic settings"
    print("[PASS] PASS: Detected resource without diagnostic settings")


def test_factory_integration():
    """Test factory integration for KSI-MLA-01."""
    factory = get_factory()
    
    code = """
import logging

logging.basicConfig(filename='app.log', level=logging.INFO)
logger = logging.getLogger(__name__)
logger.info('Test message')
"""
    
    result = factory.analyze("KSI-MLA-01", code, "python", "test.py")
    
    print(f"\n=== Factory Integration Test ===")
    print(f"KSI ID: {result.ksi_id}")
    print(f"Findings: {len(result.findings)}")
    for f in result.findings:
        print(f"  - {f.title} (Line {f.line_number}, {f.severity.name})")
    
    assert result.ksi_id == "KSI-MLA-01", "Should have correct KSI ID"
    assert len(result.findings) >= 1, "Should detect issues via factory"
    print("[PASS] PASS: Factory integration successful")


def run_all_tests():
    """Run all test cases."""
    tests = [
        ("Python Local File Logging", test_python_local_file_logging),
        ("Python FileHandler", test_python_file_handler),
        ("Python Proper Azure Monitor", test_python_proper_azure_monitor),
        ("Python Direct File Write", test_python_direct_file_write),
        ("C# File Logging", test_csharp_file_logging),
        ("C# Serilog File Sink", test_csharp_serilog_file_sink),
        ("C# Missing Application Insights", test_csharp_missing_application_insights),
        ("C# Proper Application Insights", test_csharp_proper_application_insights),
        ("Java FileAppender", test_java_file_appender),
        ("Java Missing Telemetry", test_java_missing_telemetry),
        ("TypeScript File Transport", test_typescript_file_transport),
        ("TypeScript Console Logging", test_typescript_console_logging),
        ("TypeScript Proper App Insights", test_typescript_proper_app_insights),
        ("Bicep Missing Log Analytics", test_bicep_missing_log_analytics),
        ("Bicep Missing Diagnostic Settings", test_bicep_missing_diagnostic_settings),
        ("Terraform Missing Log Analytics", test_terraform_missing_log_analytics),
        ("Terraform Missing Diagnostic Settings", test_terraform_missing_diagnostic_settings),
        ("Factory Integration", test_factory_integration),
    ]
    
    passed = 0
    failed = 0
    
    print("\n" + "="*80)
    print("KSI-MLA-01 Enhanced Analyzer Test Suite")
    print("="*80)
    
    for name, test_func in tests:
        try:
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"\n[FAIL] FAIL: {name}")
            print(f"  Error: {e}")
            failed += 1
        except Exception as e:
            print(f"\n[FAIL] ERROR: {name}")
            print(f"  Exception: {e}")
            failed += 1
    
    print("\n" + "="*80)
    print(f"Test Results: {passed} passed, {failed} failed out of {len(tests)} total")
    print("="*80)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

