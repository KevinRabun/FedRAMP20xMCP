"""
Tests for KSI-RPL-03 Enhanced Analyzer: System Backups

Test Coverage:
1. Bicep: Missing backup vault, short retention, missing geo-redundancy, missing encryption, complete config
2. Terraform: Missing Azure backup, missing AWS backup, short retention, missing encryption, complete config
3. Application: Azure SDK (Python/C#/TS), AWS SDK (Python/C#/TS), GCP SDK (Python)
4. CI/CD: Backup verification in GitHub Actions, Azure Pipelines, GitLab CI
5. Factory: Integration verification
"""

import sys
from pathlib import Path

# Add src directory to path
src_path = Path(__file__).parent.parent / 'src'
sys.path.insert(0, str(src_path))

from fedramp_20x_mcp.analyzers.ksi.ksi_rpl_03 import KSI_RPL_03_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity
from fedramp_20x_mcp.analyzers.ksi.factory import get_factory


def test_bicep_missing_backup_vault():
    """Test detection of missing Azure Backup configuration in Bicep."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
      name: 'production-vm'
      location: location
      properties: {
        hardwareProfile: {
          vmSize: 'Standard_D4s_v3'
        }
      }
    }
    
    resource db 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
      name: 'production-db'
      location: location
    }
    """
    
    result = analyzer.analyze(code, 'bicep', 'main.bicep')
    findings = result.findings
    
    assert len(findings) > 0, "Should detect missing backup configuration"
    
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) > 0, "Should have HIGH severity for missing backup vault"
    
    missing_backup = next((f for f in high_findings if 'Missing Azure Backup Configuration' in f.title), None)
    assert missing_backup is not None, "Should detect missing Azure Backup"
    assert 'Recovery Services Vault' in missing_backup.recommendation
    assert 'KSI-RPL-03' in missing_backup.description
    assert 'NIST CP-9' in missing_backup.description
    
    print("[PASS] Bicep missing backup vault test passed")


def test_bicep_short_retention():
    """Test detection of insufficient backup retention period in Bicep."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    resource vault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {
      name: 'backup-vault'
      location: location
    }
    
    resource backupPolicy 'Microsoft.RecoveryServices/vaults/backupPolicies@2023-01-01' = {
      parent: vault
      name: 'short-retention-policy'
      properties: {
        retentionPolicy: {
          dailySchedule: {
            retentionDuration: {
              count: 7  // Days (too short)
              durationType: 'Days'
            }
          }
        }
      }
    }
    """
    
    result = analyzer.analyze(code, 'bicep', 'backup.bicep')
    findings = result.findings
    
    retention_findings = [f for f in findings if 'Insufficient Backup Retention' in f.title]
    assert len(retention_findings) > 0, "Should detect short retention period"
    assert retention_findings[0].severity == Severity.MEDIUM
    assert '7 days' in retention_findings[0].description
    assert '30 days' in retention_findings[0].description
    
    print("[PASS] Bicep short retention test passed")


def test_bicep_missing_geo_redundancy():
    """Test detection of missing geo-redundancy in Bicep."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    resource vault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {
      name: 'backup-vault'
      location: location
      properties: {
        storageModelType: 'LocallyRedundant'  // Not geo-redundant
      }
    }
    """
    
    result = analyzer.analyze(code, 'bicep', 'vault.bicep')
    findings = result.findings
    
    geo_findings = [f for f in findings if 'Geo-Redundancy' in f.title]
    assert len(geo_findings) > 0, "Should detect missing geo-redundancy"
    assert geo_findings[0].severity == Severity.MEDIUM
    assert 'LocallyRedundant' in geo_findings[0].description
    assert 'GeoRedundant' in geo_findings[0].recommendation
    
    print("[PASS] Bicep missing geo-redundancy test passed")


def test_bicep_missing_encryption():
    """Test detection of missing backup encryption in Bicep."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    resource vault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {
      name: 'backup-vault'
      location: location
      sku: {
        name: 'RS0'
        tier: 'Standard'
      }
      properties: {
        publicNetworkAccess: 'Disabled'
      }
      // Missing encryption configuration
    }
    """
    
    result = analyzer.analyze(code, 'bicep', 'vault.bicep')
    findings = result.findings
    
    encryption_findings = [f for f in findings if 'Encryption' in f.title]
    assert len(encryption_findings) > 0, "Should detect missing encryption"
    assert encryption_findings[0].severity == Severity.HIGH
    assert 'encryption' in encryption_findings[0].recommendation.lower()
    assert 'KSI-SVC-06' in encryption_findings[0].description
    
    print("[PASS] Bicep missing encryption test passed")


def test_bicep_complete_configuration():
    """Test that complete backup configuration produces minimal findings."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    resource vault 'Microsoft.RecoveryServices/vaults@2023-01-01' = {
      name: 'backup-vault'
      location: location
      sku: {
        name: 'RS0'
        tier: 'Standard'
      }
      properties: {
        redundancySettings: {
          standardTierStorageRedundancy: 'GeoRedundant'
          crossRegionRestore: 'Enabled'
        }
        encryption: {
          infrastructureEncryption: 'Enabled'
          kekIdentity: {
            userAssignedIdentity: managedIdentityId
          }
          keyVaultProperties: {
            keyUri: keyVaultKeyUri
          }
        }
      }
    }
    
    resource backupPolicy 'Microsoft.RecoveryServices/vaults/backupPolicies@2023-01-01' = {
      parent: vault
      name: 'daily-backup-policy'
      properties: {
        retentionPolicy: {
          dailySchedule: {
            retentionDuration: {
              count: 30  // FedRAMP compliant
              durationType: 'Days'
            }
          }
          weeklySchedule: {
            retentionDuration: {
              count: 12
              durationType: 'Weeks'
            }
          }
        }
      }
    }
    """
    
    result = analyzer.analyze(code, 'bicep', 'complete.bicep')
    findings = result.findings
    
    # Should have no HIGH findings with complete configuration
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0, "Complete configuration should have no HIGH findings"
    
    print("[PASS] Bicep complete configuration test passed")


def test_terraform_missing_azure_backup():
    """Test detection of missing Azure Backup in Terraform."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    resource "azurerm_virtual_machine" "vm" {
      name                = "production-vm"
      location            = azurerm_resource_group.rg.location
      resource_group_name = azurerm_resource_group.rg.name
      vm_size             = "Standard_D4s_v3"
    }
    
    resource "azurerm_mssql_database" "db" {
      name      = "production-db"
      server_id = azurerm_mssql_server.server.id
    }
    
    # No backup configuration
    """
    
    result = analyzer.analyze(code, 'terraform', 'main.tf')
    findings = result.findings
    
    azure_backup_findings = [f for f in findings if 'Missing Azure Backup Configuration' in f.title]
    assert len(azure_backup_findings) > 0, "Should detect missing Azure Backup"
    assert azure_backup_findings[0].severity == Severity.HIGH
    assert 'azurerm_recovery_services_vault' in azure_backup_findings[0].recommendation
    assert 'azurerm_backup_policy_vm' in azure_backup_findings[0].recommendation
    
    print("[PASS] Terraform missing Azure backup test passed")


def test_terraform_missing_aws_backup():
    """Test detection of missing AWS Backup in Terraform."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    resource "aws_instance" "web" {
      ami           = "ami-0c55b159cbfafe1f0"
      instance_type = "t3.large"
    }
    
    resource "aws_db_instance" "database" {
      engine         = "postgres"
      instance_class = "db.t3.large"
    }
    
    resource "aws_efs_file_system" "storage" {
      encrypted = true
    }
    
    # No AWS Backup configuration
    """
    
    result = analyzer.analyze(code, 'terraform', 'aws.tf')
    findings = result.findings
    
    aws_backup_findings = [f for f in findings if 'Missing AWS Backup Configuration' in f.title]
    assert len(aws_backup_findings) > 0, "Should detect missing AWS Backup"
    assert aws_backup_findings[0].severity == Severity.HIGH
    assert 'aws_backup_plan' in aws_backup_findings[0].recommendation
    assert 'aws_backup_vault' in aws_backup_findings[0].recommendation
    
    print("[PASS] Terraform missing AWS backup test passed")


def test_terraform_short_retention():
    """Test detection of insufficient retention in Terraform."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    resource "azurerm_backup_policy_vm" "policy" {
      name                = "short-retention-policy"
      resource_group_name = azurerm_resource_group.rg.name
      recovery_vault_name = azurerm_recovery_services_vault.vault.name
      
      backup {
        frequency = "Daily"
        time      = "02:00"
      }
      
      retention_daily {
        count = 14  # Too short - less than 30 days
      }
    }
    """
    
    result = analyzer.analyze(code, 'terraform', 'backup.tf')
    findings = result.findings
    
    retention_findings = [f for f in findings if 'Insufficient Backup Retention' in f.title]
    assert len(retention_findings) > 0, "Should detect short retention"
    assert retention_findings[0].severity == Severity.MEDIUM
    assert '14 days' in retention_findings[0].description
    
    print("[PASS] Terraform short retention test passed")


def test_terraform_missing_encryption():
    """Test detection of missing encryption in Terraform."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    resource "azurerm_recovery_services_vault" "vault" {
      name                = "backup-vault"
      location            = azurerm_resource_group.rg.location
      resource_group_name = azurerm_resource_group.rg.name
      sku                 = "Standard"
      # Missing encryption configuration
    }
    """
    
    result = analyzer.analyze(code, 'terraform', 'vault.tf')
    findings = result.findings
    
    encryption_findings = [f for f in findings if 'Encryption' in f.title]
    assert len(encryption_findings) > 0, "Should detect missing encryption"
    assert encryption_findings[0].severity == Severity.HIGH
    assert 'key_id' in encryption_findings[0].recommendation or 'encryption' in encryption_findings[0].recommendation
    
    print("[PASS] Terraform missing encryption test passed")


def test_terraform_complete_configuration():
    """Test complete Terraform backup configuration."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    resource "azurerm_recovery_services_vault" "vault" {
      name                = "backup-vault"
      location            = azurerm_resource_group.rg.location
      resource_group_name = azurerm_resource_group.rg.name
      sku                 = "Standard"
      soft_delete_enabled = true
      
      encryption {
        key_id                            = azurerm_key_vault_key.backup_key.id
        infrastructure_encryption_enabled = true
      }
    }
    
    resource "azurerm_backup_policy_vm" "policy" {
      name                = "daily-backup-policy"
      resource_group_name = azurerm_resource_group.rg.name
      recovery_vault_name = azurerm_recovery_services_vault.vault.name
      
      backup {
        frequency = "Daily"
        time      = "02:00"
      }
      
      retention_daily {
        count = 30
      }
      
      retention_weekly {
        count    = 12
        weekdays = ["Sunday"]
      }
    }
    """
    
    result = analyzer.analyze(code, 'terraform', 'complete.tf')
    findings = result.findings
    
    # Complete config should have no HIGH findings
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) == 0, "Complete configuration should have no HIGH findings"
    
    print("[PASS] Terraform complete configuration test passed")


def test_python_azure_backup_sdk():
    """Test detection of Azure Backup SDK usage in Python."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
    from azure.identity import DefaultAzureCredential
    
    credential = DefaultAzureCredential()
    backup_client = RecoveryServicesBackupClient(credential, subscription_id)
    
    # Create backup policy
    backup_policy = {
        'schedulePolicy': {
            'scheduleRunFrequency': 'Daily',
            'scheduleRunTimes': ['02:00:00']
        },
        'retentionPolicy': {
            'dailySchedule': {
                'retentionDuration': {'count': 30, 'durationType': 'Days'}
            },
            'weeklySchedule': {
                'retentionDuration': {'count': 12, 'durationType': 'Weeks'}
            }
        }
    }
    """
    
    result = analyzer.analyze(code, 'python', 'backup_automation.py')
    findings = result.findings
    
    info_findings = [f for f in findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0, "Should detect Azure Backup SDK usage"
    
    azure_findings = [f for f in info_findings if 'Azure Backup SDK' in f.title]
    assert len(azure_findings) > 0, "Should identify Azure Backup SDK"
    assert 'KSI-RPL-03' in azure_findings[0].description
    
    print("[PASS] Python Azure Backup SDK test passed")


def test_python_aws_backup():
    """Test detection of AWS backup operations in Python."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    import boto3
    
    backup_client = boto3.client('backup')
    
    # Create backup plan
    response = backup_client.create_backup_plan(
        BackupPlan={
            'BackupPlanName': 'daily-backup-plan',
            'Rules': [{
                'RuleName': 'daily_backup_rule',
                'TargetBackupVaultName': 'backup-vault',
                'ScheduleExpression': 'cron(0 2 * * ? *)',
                'Lifecycle': {
                    'DeleteAfter': 30
                }
            }]
        }
    )
    
    # Start backup job
    backup_job = backup_client.start_backup_job(
        BackupVaultName='backup-vault',
        ResourceArn=resource_arn,
        IamRoleArn=iam_role_arn
    )
    """
    
    result = analyzer.analyze(code, 'python', 'aws_backup.py')
    findings = result.findings
    
    aws_findings = [f for f in findings if 'AWS Backup' in f.title]
    assert len(aws_findings) > 0, "Should detect AWS Backup operations"
    assert aws_findings[0].severity == Severity.INFO
    assert 'boto3' in aws_findings[0].description.lower() or 'boto3' in aws_findings[0].title.lower()
    
    print("[PASS] Python AWS Backup test passed")


def test_python_gcp_backup():
    """Test detection of GCP backup operations in Python."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    from google.cloud import compute_v1
    from google.cloud import storage
    
    compute_client = compute_v1.DisksClient()
    storage_client = storage.Client()
    
    # Create disk snapshot
    snapshot = compute_client.create_snapshot(
        project='my-project',
        zone='us-central1-a',
        disk='production-disk',
        snapshot_resource=compute_v1.Snapshot(
            name='snapshot-2024-01-01',
            storage_locations=['us']
        )
    )
    """
    
    result = analyzer.analyze(code, 'python', 'gcp_backup.py')
    findings = result.findings
    
    gcp_findings = [f for f in findings if 'GCP' in f.title]
    assert len(gcp_findings) > 0, "Should detect GCP backup operations"
    assert gcp_findings[0].severity == Severity.INFO
    
    print("[PASS] Python GCP Backup test passed")


def test_csharp_azure_backup_sdk():
    """Test detection of Azure Backup SDK in C#."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    using Azure.ResourceManager.RecoveryServicesBackup;
    using Azure.ResourceManager.RecoveryServicesBackup.Models;
    using Azure.Identity;
    
    var credential = new DefaultAzureCredential();
    var client = new RecoveryServicesBackupClient(credential);
    
    var backupPolicy = new BackupProtectionPolicy
    {
        SchedulePolicy = new SimpleSchedulePolicy
        {
            ScheduleRunFrequency = ScheduleRunType.Daily,
            ScheduleRunTimes = { DateTimeOffset.Parse("02:00:00") }
        },
        RetentionPolicy = new LongTermRetentionPolicy
        {
            DailySchedule = new DailyRetentionSchedule
            {
                RetentionDuration = new RetentionDuration 
                { 
                    Count = 30, 
                    DurationType = RetentionDurationType.Days 
                }
            }
        }
    };
    """
    
    result = analyzer.analyze(code, 'csharp', 'BackupService.cs')
    findings = result.findings
    
    azure_findings = [f for f in findings if 'Azure Backup SDK' in f.title]
    assert len(azure_findings) > 0, "Should detect Azure Backup SDK"
    assert azure_findings[0].severity == Severity.INFO
    
    print("[PASS] C# Azure Backup SDK test passed")


def test_csharp_aws_backup():
    """Test detection of AWS Backup SDK in C#."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    using Amazon.Backup;
    using Amazon.Backup.Model;
    
    var backupClient = new AmazonBackupClient();
    
    var createPlanRequest = new CreateBackupPlanRequest
    {
        BackupPlan = new BackupPlanInput
        {
            BackupPlanName = "daily-backup-plan",
            Rules = new List<BackupRuleInput>
            {
                new BackupRuleInput
                {
                    RuleName = "daily_backup_rule",
                    TargetBackupVaultName = "backup-vault",
                    ScheduleExpression = "cron(0 2 * * ? *)",
                    Lifecycle = new Lifecycle
                    {
                        DeleteAfterDays = 30
                    }
                }
            }
        }
    };
    
    var response = await backupClient.CreateBackupPlanAsync(createPlanRequest);
    """
    
    result = analyzer.analyze(code, 'csharp', 'AwsBackupService.cs')
    findings = result.findings
    
    aws_findings = [f for f in findings if 'AWS Backup SDK' in f.title]
    assert len(aws_findings) > 0, "Should detect AWS Backup SDK"
    assert aws_findings[0].severity == Severity.INFO
    
    print("[PASS] C# AWS Backup SDK test passed")


def test_typescript_azure_backup():
    """Test detection of Azure Backup SDK in TypeScript."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    import { RecoveryServicesBackupClient } from '@azure/arm-recoveryservicesbackup';
    import { DefaultAzureCredential } from '@azure/identity';
    
    const credential = new DefaultAzureCredential();
    const client = new RecoveryServicesBackupClient(credential, subscriptionId);
    
    const backupPolicy = {
      schedulePolicy: {
        scheduleRunFrequency: 'Daily',
        scheduleRunTimes: ['02:00:00']
      },
      retentionPolicy: {
        dailySchedule: {
          retentionDuration: { count: 30, durationType: 'Days' }
        },
        weeklySchedule: {
          retentionDuration: { count: 12, durationType: 'Weeks' }
        }
      }
    };
    """
    
    result = analyzer.analyze(code, 'typescript', 'backup.ts')
    findings = result.findings
    
    azure_findings = [f for f in findings if 'Azure Backup SDK' in f.title]
    assert len(azure_findings) > 0, "Should detect Azure Backup SDK"
    assert azure_findings[0].severity == Severity.INFO
    
    print("[PASS] TypeScript Azure Backup SDK test passed")


def test_typescript_aws_backup():
    """Test detection of AWS Backup SDK in TypeScript."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    import { BackupClient, CreateBackupPlanCommand } from '@aws-sdk/client-backup';
    
    const client = new BackupClient({ region: 'us-east-1' });
    
    const command = new CreateBackupPlanCommand({
      BackupPlan: {
        BackupPlanName: 'daily-backup-plan',
        Rules: [{
          RuleName: 'daily_backup_rule',
          TargetBackupVaultName: 'backup-vault',
          ScheduleExpression: 'cron(0 2 * * ? *)',
          Lifecycle: {
            DeleteAfterDays: 30
          }
        }]
      }
    });
    
    const response = await client.send(command);
    """
    
    result = analyzer.analyze(code, 'typescript', 'awsBackup.ts')
    findings = result.findings
    
    aws_findings = [f for f in findings if 'AWS Backup SDK' in f.title]
    assert len(aws_findings) > 0, "Should detect AWS Backup SDK"
    assert aws_findings[0].severity == Severity.INFO
    
    print("[PASS] TypeScript AWS Backup SDK test passed")


def test_github_actions_backup_verification():
    """Test detection of backup verification in GitHub Actions."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    name: Backup Verification
    
    on:
      schedule:
        - cron: '0 3 * * *'  # Daily at 3 AM
    
    jobs:
      verify-backups:
        runs-on: ubuntu-latest
        steps:
          - name: Verify Backup Configuration
            run: |
              az backup policy show --name daily-backup-policy --vault-name backup-vault
              az backup protection check-vm --vm-id ${{ secrets.VM_ID }}
              
          - name: Test Backup Restore
            run: |
              # Test restore to staging storage
              az backup restore restore-disks \\
                --restore-to-staging-storage-account \\
                --storage-account staging-storage
    """
    
    result = analyzer.analyze(code, 'github_actions', '.github/workflows/backup-verify.yml')
    findings = result.findings
    
    verification_findings = [f for f in findings if 'Backup Verification' in f.title]
    assert len(verification_findings) > 0, "Should detect backup verification tests"
    assert verification_findings[0].severity == Severity.INFO
    assert 'KSI-RPL-03' in verification_findings[0].description
    
    print("[PASS] GitHub Actions backup verification test passed")


def test_azure_pipelines_backup_verification():
    """Test detection of backup verification in Azure Pipelines."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    trigger: none
    
    schedules:
      - cron: '0 3 * * *'
        displayName: Daily backup verification
        branches:
          include:
            - main
    
    jobs:
      - job: VerifyBackups
        displayName: 'Verify Backup Configuration'
        steps:
          - task: AzureCLI@2
            displayName: 'Check Backup Policy'
            inputs:
              azureSubscription: '$(azureSubscription)'
              scriptType: 'bash'
              scriptLocation: 'inlineScript'
              inlineScript: |
                az backup policy show --name daily-backup-policy
                retention=$(az backup policy show --name daily-backup-policy --query 'properties.retentionPolicy.dailySchedule.retentionDuration.count' -o tsv)
                if [ $retention -lt 30 ]; then
                  echo "ERROR: Retention period less than FedRAMP minimum (30 days)"
                  exit 1
                fi
    """
    
    result = analyzer.analyze(code, 'azure_pipelines', 'azure-pipelines.yml')
    findings = result.findings
    
    verification_findings = [f for f in findings if 'Backup Verification' in f.title]
    assert len(verification_findings) > 0, "Should detect backup verification"
    assert verification_findings[0].severity == Severity.INFO
    
    print("[PASS] Azure Pipelines backup verification test passed")


def test_gitlab_ci_backup_verification():
    """Test detection of backup verification in GitLab CI."""
    analyzer = KSI_RPL_03_Analyzer()
    
    code = """
    stages:
      - test
    
    backup:verify:
      stage: test
      script:
        - az backup policy show --name daily-backup-policy
        - az backup protection check-vm --vm-id $VM_ID
        - |
          # Verify backup encryption
          encryption=$(az backup vault show --query 'properties.encryption' -o json)
          if [ -z "$encryption" ]; then
            echo "ERROR: Backup encryption not configured"
            exit 1
          fi
      rules:
        - if: '$CI_PIPELINE_SOURCE == "schedule"'
    """
    
    result = analyzer.analyze(code, 'gitlab_ci', '.gitlab-ci.yml')
    findings = result.findings
    
    verification_findings = [f for f in findings if 'Backup Verification' in f.title]
    assert len(verification_findings) > 0, "Should detect backup verification"
    assert verification_findings[0].severity == Severity.INFO
    
    print("[PASS] GitLab CI backup verification test passed")


def test_factory_integration():
    """Test that RPL-03 enhanced is registered in factory."""
    factory = get_factory()
    
    # Test factory recognizes KSI-RPL-03
    ksi_list = factory.list_ksis()
    assert 'KSI-RPL-03' in ksi_list, "Factory should list KSI-RPL-03"
    
    # Test factory returns enhanced analyzer
    analyzer = factory.get_analyzer('KSI-RPL-03')
    assert analyzer is not None, "Factory should return analyzer for KSI-RPL-03"
    assert analyzer.__class__.__name__ == 'KSI_RPL_03_Analyzer', \
        "Factory should return enhanced analyzer, not original"
    
    # Test analyze via factory
    code = """
    resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {
      name: 'test-vm'
    }
    """
    
    result = factory.analyze('KSI-RPL-03', code, 'bicep', 'test.bicep')
    findings = result.findings
    assert len(findings) > 0, "Factory analysis should return findings"
    
    print("[PASS] Factory integration test passed")


def run_all_tests():
    """Run all RPL-03 enhanced tests."""
    print("\n" + "="*60)
    print("KSI-RPL-03 ENHANCED ANALYZER TESTS")
    print("="*60 + "\n")
    
    tests = [
        # Bicep tests (5)
        ("Bicep: Missing Backup Vault", test_bicep_missing_backup_vault),
        ("Bicep: Short Retention Period", test_bicep_short_retention),
        ("Bicep: Missing Geo-Redundancy", test_bicep_missing_geo_redundancy),
        ("Bicep: Missing Encryption", test_bicep_missing_encryption),
        ("Bicep: Complete Configuration", test_bicep_complete_configuration),
        
        # Terraform tests (6)
        ("Terraform: Missing Azure Backup", test_terraform_missing_azure_backup),
        ("Terraform: Missing AWS Backup", test_terraform_missing_aws_backup),
        ("Terraform: Short Retention", test_terraform_short_retention),
        ("Terraform: Missing Encryption", test_terraform_missing_encryption),
        ("Terraform: Complete Configuration", test_terraform_complete_configuration),
        
        # Application tests (7)
        ("Python: Azure Backup SDK", test_python_azure_backup_sdk),
        ("Python: AWS Backup", test_python_aws_backup),
        ("Python: GCP Backup", test_python_gcp_backup),
        ("C#: Azure Backup SDK", test_csharp_azure_backup_sdk),
        ("C#: AWS Backup SDK", test_csharp_aws_backup),
        ("TypeScript: Azure Backup SDK", test_typescript_azure_backup),
        ("TypeScript: AWS Backup SDK", test_typescript_aws_backup),
        
        # CI/CD tests (3)
        ("GitHub Actions: Backup Verification", test_github_actions_backup_verification),
        ("Azure Pipelines: Backup Verification", test_azure_pipelines_backup_verification),
        ("GitLab CI: Backup Verification", test_gitlab_ci_backup_verification),
        
        # Factory test (1)
        ("Factory Integration", test_factory_integration)
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        try:
            print(f"Running: {name}")
            test_func()
            passed += 1
        except AssertionError as e:
            print(f"FAILED: {name}")
            print(f"  Error: {e}\n")
            failed += 1
        except Exception as e:
            print(f"ERROR: {name}")
            print(f"  Exception: {e}\n")
            failed += 1
    
    print("\n" + "="*60)
    print(f"TEST RESULTS: {passed}/{len(tests)} passed")
    if failed == 0:
        print("ALL TESTS PASSED!")
    else:
        print(f"{failed} tests failed")
    print("="*60 + "\n")
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)

