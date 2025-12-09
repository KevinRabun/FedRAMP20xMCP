"""Tests for KSI-MLA-08 Enhanced: Log Data Access"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_mla_08 import KSI_MLA_08_Analyzer
from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_azure_monitor_without_scope():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
from azure.monitor.query import LogsQueryClient
from azure.identity import DefaultAzureCredential

client = LogsQueryClient(DefaultAzureCredential())
"""
    result = analyzer.analyze(code, "python", "query.py")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] Python Azure Monitor without scope")


def test_python_log_access_without_authz():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
def read_logs():
    with open('/var/log/app.log', 'r') as f:
        return f.read()
"""
    result = analyzer.analyze(code, "python", "logs.py")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Python log access without authz")


def test_python_with_authorization():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
@require_role('admin')
def read_logs():
    with open('/var/log/app.log', 'r') as f:
        return f.read()
"""
    result = analyzer.analyze(code, "python", "logs.py")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Python with authorization")


def test_csharp_log_query_without_credential():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
using Azure.Monitor.Query;

var client = new LogsQueryClient();
var result = await client.QueryWorkspaceAsync(workspaceId, query);
"""
    result = analyzer.analyze(code, "csharp", "Query.cs")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.MEDIUM for f in result.findings)
    print("[PASS] C# log query without credential")


def test_csharp_log_file_without_authz():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
public class LogService
{
    public string ReadLogs()
    {
        return File.ReadAllText("/var/log/app.log");
    }
}
"""
    result = analyzer.analyze(code, "csharp", "LogService.cs")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] C# log file without authz")


def test_csharp_with_authorization():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
[Authorize(Roles = "Admin")]
public class LogController : ControllerBase
{
    public string GetLogs()
    {
        return File.ReadAllText("/var/log/app.log");
    }
}
"""
    result = analyzer.analyze(code, "csharp", "LogController.cs")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] C# with authorization")


def test_java_log_file_without_authz():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
public class LogService {
    public String readLogs() throws IOException {
        return Files.readAllLines(Paths.get("/var/log/app.log"));
    }
}
"""
    result = analyzer.analyze(code, "java", "LogService.java")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Java log file without authz")


def test_java_with_authorization():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
@Service
public class LogService {
    @PreAuthorize("hasRole('ADMIN')")
    public String readLogs() throws IOException {
        return Files.readAllLines(Paths.get("/var/log/app.log"));
    }
}
"""
    result = analyzer.analyze(code, "java", "LogService.java")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Java with authorization")


def test_typescript_log_file_without_authz():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
export class LogService {
    readLogs(): string {
        return fs.readFileSync('/var/log/app.log', 'utf8');
    }
}
"""
    result = analyzer.analyze(code, "typescript", "log.service.ts")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] TypeScript log file without authz")


def test_typescript_with_authorization():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
@UseGuards(RolesGuard)
@Roles('admin')
export class LogController {
    readLogs(): string {
        return fs.readFileSync('/var/log/app.log', 'utf8');
    }
}
"""
    result = analyzer.analyze(code, "typescript", "log.controller.ts")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] TypeScript with authorization")


def test_bicep_log_analytics_without_rbac():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
    name: 'law-prod'
    location: location
    properties: {
        sku: { name: 'PerGB2018' }
        retentionInDays: 90
    }
}
"""
    result = analyzer.analyze(code, "bicep", "main.bicep")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Bicep Log Analytics without RBAC")


def test_bicep_with_rbac():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
    name: 'law-prod'
    location: location
}

resource rbac 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
    scope: logAnalytics
    name: guid(logAnalytics.id, 'MonitoringReader')
    properties: {
        roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '43d0d8ad-25c7-4714-9337-8ba259a9fe05')
        principalId: principalId
    }
}
"""
    result = analyzer.analyze(code, "bicep", "main.bicep")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Bicep with RBAC")


def test_bicep_storage_logs_without_rbac():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
    name: 'stlogs'
    location: location
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
    parent: storage
    name: 'default'
}

resource logsContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
    parent: blobService
    name: 'logs'
}
"""
    result = analyzer.analyze(code, "bicep", "storage.bicep")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Bicep storage logs without RBAC")


def test_terraform_log_analytics_without_rbac():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
resource "azurerm_log_analytics_workspace" "main" {
    name                = "law-prod"
    location            = azurerm_resource_group.main.location
    resource_group_name = azurerm_resource_group.main.name
    sku                 = "PerGB2018"
    retention_in_days   = 90
}
"""
    result = analyzer.analyze(code, "terraform", "main.tf")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Terraform Log Analytics without RBAC")


def test_terraform_with_rbac():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
resource "azurerm_log_analytics_workspace" "main" {
    name = "law-prod"
}

resource "azurerm_role_assignment" "logs" {
    scope                = azurerm_log_analytics_workspace.main.id
    role_definition_name = "Monitoring Reader"
    principal_id         = var.principal_id
}
"""
    result = analyzer.analyze(code, "terraform", "main.tf")
    high_findings = [f for f in result.findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0
    print("[PASS] Terraform with RBAC")


def test_terraform_storage_logs_without_rbac():
    analyzer = KSI_MLA_08_Analyzer()
    code = """
resource "azurerm_storage_account" "main" {
    name = "stlogs"
}

resource "azurerm_storage_container" "logs" {
    name                  = "logs"
    storage_account_name  = azurerm_storage_account.main.name
}
"""
    result = analyzer.analyze(code, "terraform", "storage.tf")
    assert len(result.findings) >= 1
    assert any(f.severity == Severity.HIGH for f in result.findings)
    print("[PASS] Terraform storage logs without RBAC")


def test_factory():
    # Manual registration for enhanced analyzer
    from fedramp_20x_mcp.analyzers.ksi.factory import get_factory
    factory = get_factory()
    analyzer = KSI_MLA_08_Analyzer()
    factory.register(analyzer)
    
    code = """
def read_logs():
    with open('/var/log/app.log') as f:
        return f.read()
"""
    result = factory.analyze("KSI-MLA-08", code, "python", "logs.py")
    assert result.ksi_id == "KSI-MLA-08"
    assert len(result.findings) >= 1
    print("[PASS] Factory integration")


def run_all():
    tests = [
        test_python_azure_monitor_without_scope,
        test_python_log_access_without_authz,
        test_python_with_authorization,
        test_csharp_log_query_without_credential,
        test_csharp_log_file_without_authz,
        test_csharp_with_authorization,
        test_java_log_file_without_authz,
        test_java_with_authorization,
        test_typescript_log_file_without_authz,
        test_typescript_with_authorization,
        test_bicep_log_analytics_without_rbac,
        test_bicep_with_rbac,
        test_bicep_storage_logs_without_rbac,
        test_terraform_log_analytics_without_rbac,
        test_terraform_with_rbac,
        test_terraform_storage_logs_without_rbac,
        test_factory,
    ]
    
    print("\nKSI-MLA-08 Enhanced Tests")
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

