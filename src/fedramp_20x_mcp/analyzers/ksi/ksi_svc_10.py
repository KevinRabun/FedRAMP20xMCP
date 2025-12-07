"""
KSI-SVC-10: Data Destruction

Remove unwanted federal customer data promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate; this typically applies when a customer spills information or when a customer seeks to remove information from a service due to a change in usage.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_SVC_10_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-SVC-10: Data Destruction
    
    **Official Statement:**
    Remove unwanted federal customer data promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate; this typically applies when a customer spills information or when a customer seeks to remove information from a service due to a change in usage.
    
    **Family:** SVC - Service Configuration
    
    **Impact Levels:**
    - Low: No
    - Moderate: Yes
    
    **NIST Controls:**
    - si-12.3
    - si-18.4
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-SVC-10"
    KSI_NAME = "Data Destruction"
    KSI_STATEMENT = """Remove unwanted federal customer data promptly when requested by an agency in alignment with customer agreements, including from backups if appropriate; this typically applies when a customer spills information or when a customer seeks to remove information from a service due to a change in usage."""
    FAMILY = "SVC"
    FAMILY_NAME = "Service Configuration"
    IMPACT_LOW = False
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["si-12.3", "si-18.4"]
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
        Analyze Python code for KSI-SVC-10 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Hard deletes without soft delete mechanism
        - Database operations without data retention policies
        - Missing backup deletion capabilities
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Hard delete without soft delete (MEDIUM)
        delete_match = self._find_line(lines, r'\.(delete|remove)\(')
        
        if delete_match:
            line_num = delete_match['line_num']
            # Check if there's a soft delete field (is_deleted, deleted_at, etc.)
            context_start = max(0, line_num - 10)
            context_end = min(len(lines), line_num + 10)
            context = lines[context_start:context_end]
            
            has_soft_delete = any(re.search(r'(is_deleted|deleted_at|deleted|status\s*=\s*["\']deleted)', line, re.IGNORECASE) 
                                 for line in context)
            
            if not has_soft_delete:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Hard Delete Without Soft Delete Mechanism",
                    description=(
                        "Database record deleted with .delete() or .remove() without soft delete mechanism. "
                        "KSI-SVC-10 requires removing customer data promptly when requested (SI-12.3, SI-18.4) - "
                        "hard deletes cannot be audited or recovered. Implement soft delete to track deletion requests "
                        "and allow verification of data removal compliance."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Implement soft delete mechanism:\n"
                        "# Django ORM Example\n"
                        "from django.db import models\n"
                        "from django.utils import timezone\n\n"
                        "class SoftDeleteModel(models.Model):\n"
                        "    deleted_at = models.DateTimeField(null=True, blank=True)\n"
                        "    \n"
                        "    def soft_delete(self):\n"
                        "        self.deleted_at = timezone.now()\n"
                        "        self.save()\n"
                        "    \n"
                        "    class Meta:\n"
                        "        abstract = True\n\n"
                        "# SQLAlchemy Example\n"
                        "from sqlalchemy import Column, DateTime\n"
                        "from datetime import datetime\n\n"
                        "class SoftDeleteMixin:\n"
                        "    deleted_at = Column(DateTime, nullable=True)\n"
                        "    \n"
                        "    def soft_delete(self):\n"
                        "        self.deleted_at = datetime.utcnow()\n\n"
                        "# Usage\n"
                        "record.soft_delete()  # Instead of record.delete()\n\n"
                        "# Query filtering\n"
                        "active_records = Model.objects.filter(deleted_at__isnull=True)\n\n"
                        "Ref: Django Soft Delete Pattern (https://docs.djangoproject.com/en/stable/topics/db/managers/)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Backup operations without retention policy (LOW)
        backup_match = self._find_line(lines, r'(backup|snapshot|export)')
        
        if backup_match:
            line_num = backup_match['line_num']
            # Check if retention or expiration is set
            has_retention = any(re.search(r'(retention|expire|ttl|lifecycle)', line, re.IGNORECASE) 
                               for line in lines[line_num:min(line_num+20, len(lines))])
            
            if not has_retention:
                findings.append(Finding(
                    severity=Severity.LOW,
                    title="Backup Operation Without Retention Policy",
                    description=(
                        "Backup or snapshot operation without retention/expiration policy. "
                        "KSI-SVC-10 requires removing customer data from backups when requested (SI-12.3, SI-18.4) - "
                        "indefinite backup retention may violate data deletion requirements. "
                        "Set retention policies to ensure old backups are automatically removed."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Implement backup retention policies:\n"
                        "# Azure Blob Storage with lifecycle management\n"
                        "from azure.storage.blob import BlobServiceClient\n\n"
                        "blob_service_client = BlobServiceClient.from_connection_string(conn_str)\n"
                        "container_client = blob_service_client.get_container_client(container)\n\n"
                        "# Upload backup with metadata\n"
                        "blob_client = container_client.get_blob_client(\"backup.tar.gz\")\n"
                        "blob_client.upload_blob(\n"
                        "    data=backup_data,\n"
                        "    metadata={\n"
                        "        'retention_days': '30',\n"
                        "        'expires_at': (datetime.now() + timedelta(days=30)).isoformat()\n"
                        "    }\n"
                        ")\n\n"
                        "# AWS S3 with lifecycle policy\n"
                        "import boto3\n\n"
                        "s3 = boto3.client('s3')\n"
                        "s3.put_object(\n"
                        "    Bucket='backups',\n"
                        "    Key='backup.tar.gz',\n"
                        "    Body=backup_data,\n"
                        "    Tagging='retention=30days'\n"
                        ")\n\n"
                        "# Configure lifecycle rule to delete after 30 days\n"
                        "s3.put_bucket_lifecycle_configuration(\n"
                        "    Bucket='backups',\n"
                        "    LifecycleConfiguration={\n"
                        "        'Rules': [{\n"
                        "            'Id': 'DeleteOldBackups',\n"
                        "            'Status': 'Enabled',\n"
                        "            'Expiration': {'Days': 30}\n"
                        "        }]\n"
                        "    }\n"
                        ")\n\n"
                        "Ref: Azure Blob Lifecycle Management (https://learn.microsoft.com/azure/storage/blobs/lifecycle-management-overview)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-SVC-10 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Hard deletes in Entity Framework without soft delete
        - Missing data retention policies
        - No audit trail for deletions
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: EF Core Remove() without soft delete (MEDIUM)
        remove_match = self._find_line(lines, r'\.(Remove|RemoveRange)\(')
        
        if remove_match:
            line_num = remove_match['line_num']
            # Check if entity has IsDeleted or DeletedAt property
            context_start = max(0, line_num - 20)
            context_end = min(len(lines), line_num + 10)
            context = lines[context_start:context_end]
            
            has_soft_delete = any(re.search(r'(IsDeleted|DeletedAt|Deleted)', line, re.IGNORECASE) 
                                 for line in context)
            
            if not has_soft_delete:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Hard Delete Without Soft Delete (Entity Framework)",
                    description=(
                        "Entity Framework Remove() or RemoveRange() without soft delete implementation. "
                        "KSI-SVC-10 requires removing customer data promptly when requested (SI-12.3, SI-18.4) - "
                        "hard deletes cannot be audited or traced for compliance verification. "
                        "Implement soft delete to track deletion requests and verify data removal."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Implement soft delete in Entity Framework:\n"
                        "// 1. Add soft delete properties to entity\n"
                        "public class Customer\n"
                        "{\n"
                        "    public int Id { get; set; }\n"
                        "    public string Name { get; set; }\n"
                        "    public DateTime? DeletedAt { get; set; }\n"
                        "    public bool IsDeleted => DeletedAt.HasValue;\n"
                        "}\n\n"
                        "// 2. Configure global query filter in DbContext\n"
                        "protected override void OnModelCreating(ModelBuilder modelBuilder)\n"
                        "{\n"
                        "    modelBuilder.Entity<Customer>()\n"
                        "        .HasQueryFilter(c => c.DeletedAt == null);\n"
                        "}\n\n"
                        "// 3. Implement soft delete method\n"
                        "public async Task SoftDeleteCustomerAsync(int id)\n"
                        "{\n"
                        "    var customer = await _context.Customers\n"
                        "        .IgnoreQueryFilters()  // To find soft-deleted records\n"
                        "        .FirstOrDefaultAsync(c => c.Id == id);\n"
                        "    \n"
                        "    if (customer != null && !customer.IsDeleted)\n"
                        "    {\n"
                        "        customer.DeletedAt = DateTime.UtcNow;\n"
                        "        await _context.SaveChangesAsync();\n"
                        "    }\n"
                        "}\n\n"
                        "// 4. Hard delete after verification (compliance-driven)\n"
                        "public async Task HardDeleteAfterVerificationAsync(int id)\n"
                        "{\n"
                        "    var customer = await _context.Customers\n"
                        "        .IgnoreQueryFilters()\n"
                        "        .FirstOrDefaultAsync(c => c.Id == id);\n"
                        "    \n"
                        "    if (customer?.IsDeleted == true)\n"
                        "    {\n"
                        "        _context.Customers.Remove(customer);\n"
                        "        await _context.SaveChangesAsync();\n"
                        "        // Log permanent deletion for audit\n"
                        "        _logger.LogInformation(\"Hard deleted customer {Id}\", id);\n"
                        "    }\n"
                        "}\n\n"
                        "Ref: EF Core Query Filters (https://learn.microsoft.com/ef/core/querying/filters)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-SVC-10 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - JPA/Hibernate delete operations without soft delete
        - Missing @SQLDelete annotations
        - No audit trail for data removal
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: repository.delete() without soft delete (MEDIUM)
        delete_match = self._find_line(lines, r'(repository|entityManager)\.(delete|remove)\(')
        
        if delete_match:
            line_num = delete_match['line_num']
            # Check if entity has @SQLDelete annotation or deletedAt field
            context_start = max(0, line_num - 30)
            context_end = min(len(lines), line_num + 10)
            context = lines[context_start:context_end]
            
            has_soft_delete = any(re.search(r'(@SQLDelete|deletedAt|isDeleted)', line, re.IGNORECASE) 
                                 for line in context)
            
            if not has_soft_delete:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Hard Delete Without Soft Delete (JPA/Hibernate)",
                    description=(
                        "JPA/Hibernate delete() or remove() operation without soft delete implementation. "
                        "KSI-SVC-10 requires removing customer data promptly when requested (SI-12.3, SI-18.4) - "
                        "hard deletes cannot be audited or traced for compliance verification. "
                        "Implement soft delete with @SQLDelete annotation to track deletion requests."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Implement soft delete in JPA/Hibernate:\n"
                        "// 1. Add soft delete fields to entity\n"
                        "import org.hibernate.annotations.SQLDelete;\n"
                        "import org.hibernate.annotations.Where;\n"
                        "import javax.persistence.*;\n"
                        "import java.time.LocalDateTime;\n\n"
                        "@Entity\n"
                        "@SQLDelete(sql = \"UPDATE customer SET deleted_at = NOW() WHERE id = ?\")\n"
                        "@Where(clause = \"deleted_at IS NULL\")\n"
                        "public class Customer {\n"
                        "    @Id\n"
                        "    @GeneratedValue(strategy = GenerationType.IDENTITY)\n"
                        "    private Long id;\n"
                        "    \n"
                        "    private String name;\n"
                        "    \n"
                        "    @Column(name = \"deleted_at\")\n"
                        "    private LocalDateTime deletedAt;\n"
                        "    \n"
                        "    public boolean isDeleted() {\n"
                        "        return deletedAt != null;\n"
                        "    }\n"
                        "}\n\n"
                        "// 2. Repository method for soft delete\n"
                        "@Repository\n"
                        "public interface CustomerRepository extends JpaRepository<Customer, Long> {\n"
                        "    @Modifying\n"
                        "    @Query(\"UPDATE Customer c SET c.deletedAt = CURRENT_TIMESTAMP WHERE c.id = :id\")\n"
                        "    void softDelete(@Param(\"id\") Long id);\n"
                        "    \n"
                        "    @Query(\"SELECT c FROM Customer c WHERE c.deletedAt IS NOT NULL\")\n"
                        "    List<Customer> findDeleted();\n"
                        "}\n\n"
                        "// 3. Service method for hard delete after verification\n"
                        "@Service\n"
                        "public class CustomerService {\n"
                        "    @Transactional\n"
                        "    public void hardDeleteAfterVerification(Long id) {\n"
                        "        Customer customer = customerRepository.findById(id)\n"
                        "            .orElseThrow(() -> new EntityNotFoundException());\n"
                        "        \n"
                        "        if (customer.isDeleted()) {\n"
                        "            customerRepository.delete(customer);\n"
                        "            log.info(\"Hard deleted customer {}\", id);\n"
                        "        }\n"
                        "    }\n"
                        "}\n\n"
                        "Ref: Hibernate @SQLDelete (https://docs.jboss.org/hibernate/orm/current/userguide/html_single/Hibernate_User_Guide.html#annotations-hibernate-sqldelete)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-SVC-10 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - ORM delete operations without soft delete
        - Missing deletedAt/isDeleted fields
        - No data retention tracking
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: ORM delete without soft delete (MEDIUM)
        delete_match = self._find_line(lines, r'\.(delete|remove|destroy)\(')
        
        if delete_match:
            line_num = delete_match['line_num']
            # Check if soft delete field is set
            context_start = max(0, line_num - 15)
            context_end = min(len(lines), line_num + 10)
            context = lines[context_start:context_end]
            
            has_soft_delete = any(re.search(r'(deletedAt|isDeleted|deleted)', line, re.IGNORECASE) 
                                 for line in context)
            
            if not has_soft_delete:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Hard Delete Without Soft Delete (ORM)",
                    description=(
                        "ORM delete() or remove() operation without soft delete mechanism. "
                        "KSI-SVC-10 requires removing customer data promptly when requested (SI-12.3, SI-18.4) - "
                        "hard deletes cannot be audited or traced for compliance verification. "
                        "Implement soft delete to track deletion requests and verify data removal."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Implement soft delete in TypeScript/JavaScript:\n"
                        "// 1. Prisma ORM with soft delete\n"
                        "// schema.prisma\n"
                        "model Customer {\n"
                        "  id        Int       @id @default(autoincrement())\n"
                        "  name      String\n"
                        "  deletedAt DateTime? @map(\"deleted_at\")\n"
                        "  @@index([deletedAt])\n"
                        "}\n\n"
                        "// Prisma middleware for soft delete\n"
                        "prisma.$use(async (params, next) => {\n"
                        "  if (params.model === 'Customer') {\n"
                        "    if (params.action === 'delete') {\n"
                        "      params.action = 'update';\n"
                        "      params.args['data'] = { deletedAt: new Date() };\n"
                        "    }\n"
                        "    if (params.action === 'findMany' || params.action === 'findFirst') {\n"
                        "      params.args.where = { deletedAt: null, ...params.args.where };\n"
                        "    }\n"
                        "  }\n"
                        "  return next(params);\n"
                        "});\n\n"
                        "// 2. TypeORM with soft delete\n"
                        "import { Entity, Column, DeleteDateColumn } from 'typeorm';\n\n"
                        "@Entity()\n"
                        "export class Customer {\n"
                        "  @PrimaryGeneratedColumn()\n"
                        "  id: number;\n"
                        "  \n"
                        "  @Column()\n"
                        "  name: string;\n"
                        "  \n"
                        "  @DeleteDateColumn()\n"
                        "  deletedAt?: Date;\n"
                        "}\n\n"
                        "// Usage\n"
                        "await customerRepository.softDelete(id);  // Soft delete\n"
                        "await customerRepository.recover(id);     // Restore\n\n"
                        "// Hard delete after verification\n"
                        "const customer = await customerRepository.findOne({\n"
                        "  where: { id },\n"
                        "  withDeleted: true\n"
                        "});\n"
                        "if (customer?.deletedAt) {\n"
                        "  await customerRepository.remove(customer);\n"
                        "  logger.info(`Hard deleted customer ${id}`);\n"
                        "}\n\n"
                        "Ref: TypeORM Soft Delete (https://typeorm.io/delete-query-builder#soft-delete)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-SVC-10 compliance.
        
        Detects:
        - Storage without lifecycle management
        - Databases without backup retention policies
        - Missing data deletion automation
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Storage Account without lifecycle management (MEDIUM)
        storage_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts@")
        
        if storage_match:
            line_num = storage_match['line_num']
            # Check if there's a managementPolicies resource for lifecycle
            has_lifecycle = any('Microsoft.Storage/storageAccounts/managementPolicies' in line 
                               for line in lines[line_num:min(len(lines), line_num+100)])
            
            if not has_lifecycle:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Storage Account Without Lifecycle Management",
                    description=(
                        "Storage Account without lifecycle management policy. "
                        "KSI-SVC-10 requires removing customer data promptly when requested (SI-12.3, SI-18.4) - "
                        "without lifecycle policies, data removal must be manual and may not include all storage tiers. "
                        "Configure lifecycle management to automate data deletion after retention period."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure lifecycle management for automated data deletion:\n"
                        "resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
                        "  name: storageAccountName\n"
                        "  location: location\n"
                        "  sku: {\n"
                        "    name: 'Standard_LRS'\n"
                        "  }\n"
                        "  kind: 'StorageV2'\n"
                        "}\n\n"
                        "// Lifecycle management policy\n"
                        "resource lifecyclePolicy 'Microsoft.Storage/storageAccounts/managementPolicies@2023-01-01' = {\n"
                        "  parent: storageAccount\n"
                        "  name: 'default'\n"
                        "  properties: {\n"
                        "    policy: {\n"
                        "      rules: [\n"
                        "        {\n"
                        "          name: 'DeleteOldCustomerData'\n"
                        "          enabled: true\n"
                        "          type: 'Lifecycle'\n"
                        "          definition: {\n"
                        "            filters: {\n"
                        "              blobTypes: ['blockBlob']\n"
                        "              prefixMatch: ['customer-data/']\n"
                        "            }\n"
                        "            actions: {\n"
                        "              baseBlob: {\n"
                        "                delete: {\n"
                        "                  daysAfterModificationGreaterThan: 365  // Delete after 1 year\n"
                        "                }\n"
                        "              }\n"
                        "              snapshot: {\n"
                        "                delete: {\n"
                        "                  daysAfterCreationGreaterThan: 90  // Delete snapshots after 90 days\n"
                        "                }\n"
                        "              }\n"
                        "            }\n"
                        "          }\n"
                        "        }\n"
                        "      ]\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure Blob Lifecycle Management (https://learn.microsoft.com/azure/storage/blobs/lifecycle-management-policy-configure)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: SQL Database without backup retention (LOW)
        sql_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Sql/servers/databases@")
        
        if sql_match:
            line_num = sql_match['line_num']
            has_retention = any(re.search(r'(retentionDays|backupRetention)', line) 
                               for line in lines[line_num:min(line_num+30, len(lines))])
            
            if not has_retention:
                findings.append(Finding(
                    severity=Severity.LOW,
                    title="SQL Database Without Backup Retention Policy",
                    description=(
                        "SQL Database without explicit backup retention policy configuration. "
                        "KSI-SVC-10 requires removing customer data from backups when requested (SI-12.3, SI-18.4) - "
                        "configure backup retention to align with data deletion requirements."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure SQL Database backup retention:\n"
                        "resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {\n"
                        "  parent: sqlServer\n"
                        "  name: databaseName\n"
                        "  location: location\n"
                        "  sku: {\n"
                        "    name: 'S0'\n"
                        "    tier: 'Standard'\n"
                        "  }\n"
                        "  properties: {\n"
                        "    // ... other properties\n"
                        "  }\n"
                        "}\n\n"
                        "// Short-term backup retention (7-35 days)\n"
                        "resource shortTermRetention 'Microsoft.Sql/servers/databases/backupShortTermRetentionPolicies@2023-05-01-preview' = {\n"
                        "  parent: sqlDatabase\n"
                        "  name: 'default'\n"
                        "  properties: {\n"
                        "    retentionDays: 7  // Minimum 7 days, maximum 35 days\n"
                        "  }\n"
                        "}\n\n"
                        "// Long-term backup retention (optional)\n"
                        "resource longTermRetention 'Microsoft.Sql/servers/databases/backupLongTermRetentionPolicies@2023-05-01-preview' = {\n"
                        "  parent: sqlDatabase\n"
                        "  name: 'default'\n"
                        "  properties: {\n"
                        "    weeklyRetention: 'P4W'   // 4 weeks\n"
                        "    monthlyRetention: 'P12M' // 12 months\n"
                        "    yearlyRetention: 'P1Y'   // 1 year\n"
                        "    weekOfYear: 1\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure SQL Backup Retention (https://learn.microsoft.com/azure/azure-sql/database/automated-backups-overview)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-SVC-10 compliance.
        
        Detects:
        - Storage without lifecycle rules
        - Databases without retention policies
        - Missing automated data deletion
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: azurerm_storage_account without lifecycle management (MEDIUM)
        storage_match = self._find_line(lines, r'resource\s+"azurerm_storage_account"')
        
        if storage_match:
            line_num = storage_match['line_num']
            # Check if azurerm_storage_management_policy exists
            has_lifecycle = any('azurerm_storage_management_policy' in line 
                               for line in lines[line_num:min(len(lines), line_num+100)])
            
            if not has_lifecycle:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Storage Account Without Lifecycle Management",
                    description=(
                        "azurerm_storage_account without azurerm_storage_management_policy. "
                        "KSI-SVC-10 requires removing customer data promptly when requested (SI-12.3, SI-18.4) - "
                        "without lifecycle management, data removal must be manual. "
                        "Configure lifecycle rules to automate data deletion after retention period."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure lifecycle management for automated data deletion:\n"
                        'resource "azurerm_storage_account" "example" {\n'
                        '  name                     = "examplestorageacct"\n'
                        '  resource_group_name      = azurerm_resource_group.example.name\n'
                        '  location                 = azurerm_resource_group.example.location\n'
                        '  account_tier             = "Standard"\n'
                        '  account_replication_type = "GRS"\n'
                        '}\n\n'
                        'resource "azurerm_storage_management_policy" "example" {\n'
                        '  storage_account_id = azurerm_storage_account.example.id\n\n'
                        '  rule {\n'
                        '    name    = "DeleteOldCustomerData"\n'
                        '    enabled = true\n\n'
                        '    filters {\n'
                        '      prefix_match = ["customer-data/"]\n'
                        '      blob_types   = ["blockBlob"]\n'
                        '    }\n\n'
                        '    actions {\n'
                        '      base_blob {\n'
                        '        delete_after_days_since_modification_greater_than = 365  # 1 year\n'
                        '      }\n'
                        '      snapshot {\n'
                        '        delete_after_days_since_creation_greater_than = 90  # 90 days\n'
                        '      }\n'
                        '    }\n'
                        '  }\n'
                        '}\n\n'
                        "Ref: azurerm_storage_management_policy (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_management_policy)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: azurerm_mssql_database without backup retention (LOW)
        sql_match = self._find_line(lines, r'resource\s+"azurerm_mssql_database"')
        
        if sql_match:
            line_num = sql_match['line_num']
            # Check if short_term_retention_policy or long_term_retention_policy exists
            has_retention = any('retention_policy' in line 
                               for line in lines[line_num:min(len(lines), line_num+100)])
            
            if not has_retention:
                findings.append(Finding(
                    severity=Severity.LOW,
                    title="SQL Database Without Backup Retention Policy",
                    description=(
                        "azurerm_mssql_database without short_term_retention_policy or long_term_retention_policy. "
                        "KSI-SVC-10 requires removing customer data from backups when requested (SI-12.3, SI-18.4) - "
                        "configure backup retention to align with data deletion requirements."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure SQL Database backup retention:\n"
                        'resource "azurerm_mssql_database" "example" {\n'
                        '  name      = "example-db"\n'
                        '  server_id = azurerm_mssql_server.example.id\n'
                        '  sku_name  = "S0"\n'
                        '}\n\n'
                        '# Short-term retention (7-35 days)\n'
                        'resource "azurerm_mssql_database_extended_auditing_policy" "example" {\n'
                        '  database_id = azurerm_mssql_database.example.id\n'
                        '  \n'
                        '  short_term_retention_policy {\n'
                        '    retention_days = 7  # Minimum 7, maximum 35 days\n'
                        '  }\n'
                        '}\n\n'
                        '# Long-term retention (optional)\n'
                        'resource "azurerm_mssql_database_long_term_retention_policy" "example" {\n'
                        '  database_id     = azurerm_mssql_database.example.id\n'
                        '  weekly_retention  = "P4W"   # 4 weeks\n'
                        '  monthly_retention = "P12M"  # 12 months\n'
                        '  yearly_retention  = "P1Y"   # 1 year\n'
                        '  week_of_year      = 1\n'
                        '}\n\n'
                        "Ref: azurerm_mssql_database (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_database#backup-and-restore-settings)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-SVC-10 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-SVC-10 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-SVC-10 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], pattern: str) -> Optional[Dict[str, Any]]:
        """
        Find line matching regex pattern.
        
        Returns dict with 'line_num' (1-indexed) and 'line' content, or None if not found.
        """
        import re
        regex = re.compile(pattern, re.IGNORECASE)
        for i, line in enumerate(lines, 1):
            if regex.search(line):
                return {'line_num': i, 'line': line}
        return None
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number with bounds checking."""
        if line_number == 0 or line_number > len(lines):
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
