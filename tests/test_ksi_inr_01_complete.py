"""
Comprehensive tests for KSI-INR-01: Incident Response Procedure

Tests automated incident handling and reporting detection across:
- Python application code
- C# application code
- Bicep IaC
- Terraform IaC
"""

import sys
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(src_path))

from fedramp_20x_mcp.analyzers.ksi.ksi_inr_01 import KSI_INR_01_Analyzer


def test_python_with_critical_logging_and_alerting():
    """Test detection of critical logging with alerting service"""
    analyzer = KSI_INR_01_Analyzer()
    
    code = """
import logging
from azure.monitor.opentelemetry import configure_azure_monitor

configure_azure_monitor(connection_string="InstrumentationKey=...")
logger = logging.getLogger(__name__)

def handle_payment(amount):
    try:
        process_payment(amount)
    except PaymentException as e:
        logger.critical(f"Payment processing failed: {e}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise
"""
    
    result = analyzer.analyze(code, 'python', 'payment.py')
    
    # Should pass - has critical/error logging and Azure Monitor
    print(f"Python critical logging + alerting test: {result.total_issues} findings")
    assert result.total_issues == 0, f"Should pass with logging and alerting, got: {result.findings}"
    print("  PASS - Critical logging with Application Insights detected")


def test_python_missing_critical_logging():
    """Test detection of missing critical/error logging"""
    analyzer = KSI_INR_01_Analyzer()
    
    code = """
import logging

logger = logging.getLogger(__name__)

def process_data(data):
    logger.info("Processing data")
    result = transform(data)
    logger.debug(f"Result: {result}")
    return result
"""
    
    result = analyzer.analyze(code, 'python', 'processor.py')
    
    # Should detect missing critical logging
    print(f"Missing critical logging test: {result.total_issues} findings")
    assert result.total_issues >= 1
    assert any('critical' in f.title.lower() or 'error' in f.title.lower() for f in result.findings)
    # NIST control validation removed - not stored in Finding
    print("  PASS - Missing critical logging detected")


def test_python_logging_no_alerting():
    """Test detection of logging without alerting service"""
    analyzer = KSI_INR_01_Analyzer()
    
    code = """
import logging

logger = logging.getLogger(__name__)

def dangerous_operation():
    try:
        risky_function()
    except Exception as e:
        logger.critical(f"Critical failure: {e}")
        raise
"""
    
    result = analyzer.analyze(code, 'python', 'operations.py')
    
    # Should detect missing alerting integration
    print(f"Logging without alerting test: {result.total_issues} findings")
    assert result.total_issues >= 1
    assert any('alerting' in f.title.lower() for f in result.findings)
    # NIST control validation removed - not stored in Finding
    print("  PASS - Missing alerting service detected")


def test_csharp_with_ilogger_and_appinsights():
    """Test detection of ILogger with Application Insights"""
    analyzer = KSI_INR_01_Analyzer()
    
    code = """
using Microsoft.Extensions.Logging;
using Microsoft.ApplicationInsights;

public class PaymentService
{
    private readonly ILogger<PaymentService> _logger;
    private readonly TelemetryClient _telemetry;

    public PaymentService(ILogger<PaymentService> logger, TelemetryClient telemetry)
    {
        _logger = logger;
        _telemetry = telemetry;
    }

    public void ProcessPayment(decimal amount)
    {
        try
        {
            ChargeCard(amount);
        }
        catch (PaymentException ex)
        {
            _logger.LogCritical(ex, "Payment processing failed");
            _telemetry.TrackException(ex);
            throw;
        }
    }
}
"""
    
    result = analyzer.analyze(code, 'csharp', 'PaymentService.cs')
    
    # Should pass - has ILogger and Application Insights
    print(f"C# ILogger + App Insights test: {result.total_issues} findings")
    assert result.total_issues == 0, f"Should pass with ILogger and monitoring, got: {result.findings}"
    print("  PASS - ILogger with Application Insights detected")


def test_csharp_missing_critical_logging():
    """Test detection of missing critical logging in C#"""
    analyzer = KSI_INR_01_Analyzer()
    
    code = """
using Microsoft.Extensions.Logging;

public class DataService
{
    private readonly ILogger<DataService> _logger;

    public void ProcessData(string data)
    {
        _logger.LogInformation("Processing data: {Data}", data);
        var result = Transform(data);
        _logger.LogDebug("Result: {Result}", result);
    }
}
"""
    
    result = analyzer.analyze(code, 'csharp', 'DataService.cs')
    
    # Should detect missing critical/error logging
    print(f"C# missing critical logging test: {result.total_issues} findings")
    assert result.total_issues >= 1
    assert any('critical' in f.title.lower() or 'error' in f.title.lower() for f in result.findings)
    print("  PASS - Missing critical logging detected")


def test_bicep_complete_incident_response():
    """Test detection of complete incident response infrastructure"""
    analyzer = KSI_INR_01_Analyzer()
    
    code = """
resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: 'incident-response-team'
  location: 'global'
  properties: {
    enabled: true
    emailReceivers: [
      {
        name: 'SecurityTeam'
        emailAddress: 'security@example.com'
      }
    ]
    smsReceivers: [
      {
        name: 'OnCallEngineer'
        countryCode: '1'
        phoneNumber: '5551234567'
      }
    ]
    webhookReceivers: [
      {
        name: 'PagerDuty'
        serviceUri: 'https://events.pagerduty.com/integration/...'
      }
    ]
  }
}

resource metricAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: 'critical-errors-alert'
  location: 'global'
  properties: {
    enabled: true
    severity: 0
    evaluationFrequency: 'PT1M'
    windowSize: 'PT5M'
    actions: [
      {
        actionGroupId: actionGroup.id
      }
    ]
    criteria: {
      allOf: [
        {
          name: 'CriticalErrors'
          metricName: 'Exceptions'
          operator: 'GreaterThan'
          threshold: 0
          timeAggregation: 'Total'
        }
      ]
    }
  }
}

resource logAlert 'Microsoft.Insights/scheduledQueryRules@2021-08-01' = {
  name: 'security-incident-alert'
  location: 'eastus'
  properties: {
    enabled: true
    actions: {
      actionGroups: [
        actionGroup.id
      ]
    }
    criteria: {
      allOf: [
        {
          query: 'SecurityEvent | where Level == "Critical"'
          threshold: 0
          operator: 'GreaterThan'
        }
      ]
    }
  }
}
"""
    
    result = analyzer.analyze(code, 'bicep', 'incident-response.bicep')
    
    # Should pass - complete incident response setup
    print(f"Bicep complete incident response test: {result.total_issues} findings")
    assert result.total_issues == 0, f"Should pass with complete setup, got: {result.findings}"
    print("  PASS - Complete incident response infrastructure detected")


def test_bicep_missing_action_groups():
    """Test detection of missing action groups"""
    analyzer = KSI_INR_01_Analyzer()
    
    code = """
resource appServicePlan 'Microsoft.Web/serverfarms@2021-03-01' = {
  name: 'my-app-service-plan'
  location: 'eastus'
  sku: {
    name: 'P1v2'
  }
}
"""
    
    result = analyzer.analyze(code, 'bicep', 'app-service.bicep')
    
    # Should detect missing action groups
    print(f"Missing action groups test: {result.total_issues} findings")
    assert result.total_issues >= 1
    assert any('action group' in f.title.lower() for f in result.findings)
    # NIST control validation removed - not stored in Finding
    print("  PASS - Missing action groups detected")


def test_bicep_missing_alert_rules():
    """Test detection of missing alert rules"""
    analyzer = KSI_INR_01_Analyzer()
    
    code = """
resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: 'my-action-group'
  location: 'global'
  properties: {
    enabled: true
    emailReceivers: [
      {
        name: 'Admin'
        emailAddress: 'admin@example.com'
      }
    ]
  }
}
"""
    
    result = analyzer.analyze(code, 'bicep', 'action-group-only.bicep')
    
    # Should detect missing alert rules
    print(f"Missing alert rules test: {result.total_issues} findings")
    assert result.total_issues >= 1
    assert any('alert' in f.title.lower() for f in result.findings)
    # NIST control validation removed - not stored in Finding
    print("  PASS - Missing alert rules detected")


def test_terraform_aws_complete():
    """Test detection of complete AWS incident response setup"""
    analyzer = KSI_INR_01_Analyzer()
    
    code = """
resource "aws_sns_topic" "incident_alerts" {
  name = "incident-response-alerts"
}

resource "aws_sns_topic_subscription" "security_team_email" {
  topic_arn = aws_sns_topic.incident_alerts.arn
  protocol  = "email"
  endpoint  = "security@example.com"
}

resource "aws_cloudwatch_metric_alarm" "high_error_rate" {
  alarm_name          = "critical-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = "60"
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "Critical error rate exceeded"
  alarm_actions       = [aws_sns_topic.incident_alerts.arn]
}

resource "aws_cloudwatch_log_metric_filter" "security_incidents" {
  name           = "security-incident-filter"
  log_group_name = "/aws/lambda/app"
  pattern        = "[level=CRITICAL, ...]"

  metric_transformation {
    name      = "SecurityIncidents"
    namespace = "CustomMetrics"
    value     = "1"
  }
}
"""
    
    result = analyzer.analyze(code, 'terraform', 'incident-monitoring.tf')
    
    # Should pass - complete AWS setup
    print(f"Terraform AWS complete test: {result.total_issues} findings")
    assert result.total_issues == 0, f"Should pass with complete AWS setup, got: {result.findings}"
    print("  PASS - Complete AWS incident response detected")


def test_terraform_missing_monitoring():
    """Test detection of missing monitoring resources"""
    analyzer = KSI_INR_01_Analyzer()
    
    code = """
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}

resource "aws_s3_bucket_versioning" "data_versioning" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}
"""
    
    result = analyzer.analyze(code, 'terraform', 's3-bucket.tf')
    
    # Should detect missing monitoring
    print(f"Terraform missing monitoring test: {result.total_issues} findings")
    assert result.total_issues >= 1
    assert any('monitoring' in f.title.lower() or 'alerting' in f.title.lower() for f in result.findings)
    print("  PASS - Missing monitoring detected")


def run_all_tests():
    """Run all KSI-INR-01 tests"""
    print("=" * 70)
    print("KSI-INR-01: Incident Response Procedure - Complete Test Suite")
    print("=" * 70)
    
    tests = [
        ("Python - Critical Logging + Alerting", test_python_with_critical_logging_and_alerting),
        ("Python - Missing Critical Logging", test_python_missing_critical_logging),
        ("Python - Logging No Alerting", test_python_logging_no_alerting),
        ("C# - ILogger + App Insights", test_csharp_with_ilogger_and_appinsights),
        ("C# - Missing Critical Logging", test_csharp_missing_critical_logging),
        ("Bicep - Complete Incident Response", test_bicep_complete_incident_response),
        ("Bicep - Missing Action Groups", test_bicep_missing_action_groups),
        ("Bicep - Missing Alert Rules", test_bicep_missing_alert_rules),
        ("Terraform - AWS Complete", test_terraform_aws_complete),
        ("Terraform - Missing Monitoring", test_terraform_missing_monitoring),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        try:
            print(f"\nTest: {test_name}")
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"  FAIL - {e}")
            failed += 1
        except Exception as e:
            print(f"  ERROR - {e}")
            failed += 1
    
    print("\n" + "=" * 70)
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    print("=" * 70)
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)




