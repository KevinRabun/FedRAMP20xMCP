"""
FRR-ICP-05: Incident Report Availability

Providers MUST make _incident_ report information available in their secure FedRAMP repository (such as USDA Connect) or _trust center_.

Official FedRAMP 20x Requirement
Source: FRR-ICP (ICP) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import Dict, List, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ICP_05_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ICP-05: Incident Report Availability
    
    **Official Statement:**
    Providers MUST make _incident_ report information available in their secure FedRAMP repository (such as USDA Connect) or _trust center_.
    
    **Family:** ICP - ICP
    
    **Primary Keyword:** MUST
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    - High: Yes
    
    **NIST Controls:**
    - TODO: Add relevant NIST controls
    
    **Related KSIs:**
    - TODO: Add related KSI IDs
    
    **Detectability:** No
    
    **Detection Strategy:**
    TODO: This requirement is not directly code-detectable. This analyzer provides:
        1. Evidence collection guidance and automation recommendations
        2. Manual validation procedures and checklists
        3. Related documentation and artifact requirements
        4. Integration points with other compliance tools
    """
    
    FRR_ID = "FRR-ICP-05"
    FRR_NAME = "Incident Report Availability"
    FRR_STATEMENT = """Providers MUST make _incident_ report information available in their secure FedRAMP repository (such as USDA Connect) or _trust center_."""
    FAMILY = "ICP"
    FAMILY_NAME = "ICP"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("IR-4", "Incident Handling"),
        ("IR-6", "Incident Reporting"),
        ("IR-5", "Incident Monitoring"),
        ("IR-8", "Incident Response Plan"),
    ]
    CODE_DETECTABLE = True  # Detects repository integrations and secure storage mechanisms
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize FRR-ICP-05 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (AST-first for supported languages)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for FRR-ICP-05 compliance using AST.
        
        Detects:
        - File upload mechanisms
        - Repository integrations (USDA Connect, trust center)
        - Document generation for incident reports
        """
        findings = []
        
        # Check for file upload/storage mechanisms
        has_file_upload = bool(re.search(
            r'upload|blob.*client|storage.*account|file.*share|azure\.storage',
            code, re.IGNORECASE
        ))
        
        # Check for repository integrations
        has_repository = bool(re.search(
            r'repository|trust.*center|usda.*connect|secure.*storage|artifact.*upload',
            code, re.IGNORECASE
        ))
        
        # Check for document generation
        has_doc_generation = bool(re.search(
            r'generate.*report|create.*document|pdf|markdown.*report|incident.*report',
            code, re.IGNORECASE
        ))
        
        if not has_file_upload:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.HIGH,
                message="No file upload mechanism detected",
                details=(
                    "FRR-ICP-05 requires making incident reports available in a secure repository. "
                    "Implement file upload to Azure Blob Storage or equivalent."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Implement file upload mechanism (Azure Blob Storage, SharePoint)."
            ))
        
        if not has_repository:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.MEDIUM,
                message="No repository integration detected",
                details=(
                    "FRR-ICP-05 requires integration with secure FedRAMP repository or trust center. "
                    "Consider integrating with USDA Connect or similar."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Implement repository integration (USDA Connect, trust center)."
            ))
        
        if not has_doc_generation:
            findings.append(Finding(
                frr_id=self.FRR_ID,
                severity=Severity.LOW,
                message="No document generation detected",
                details=(
                    "Consider implementing automated incident report generation."
                ),
                file_path=file_path,
                line_number=1,
                remediation="Implement automated incident report generation."
            ))
        # Example from FRR-VDR-08:
        # try:
        #     parser = ASTParser(CodeLanguage.PYTHON)
        #     tree = parser.parse(code)
        #     code_bytes = code.encode('utf8')
        #     
        #     if tree and tree.root_node:
        #         # Find relevant nodes
        #         nodes = parser.find_nodes_by_type(tree.root_node, 'node_type')
        #         for node in nodes:
        #             node_text = parser.get_node_text(node, code_bytes)
        #             # Check for violations
        #         
        #         return findings
        # except Exception:
        #     pass
        
        # TODO: Implement regex fallback
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze C# for repository/storage integration."""
        findings = []
        has_storage = bool(re.search(r'(BlobClient|StorageAccount|FileShare|Azure\.Storage)', code))
        if not has_storage:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No storage integration", description=f"FRR-ICP-05 requires secure repository availability.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement storage: BlobClient, Azure.Storage, or FileShare"
            ))
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Java for repository/storage integration."""
        findings = []
        has_storage = bool(re.search(r'(BlobClient|S3Client|StorageClient|FileUpload)', code))
        if not has_storage:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No storage integration", description=f"FRR-ICP-05 requires secure repository availability.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement storage: BlobClient, S3Client, or StorageClient"
            ))
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze TypeScript for repository/storage integration."""
        findings = []
        has_storage = bool(re.search(r'(BlobServiceClient|@azure/storage|aws-sdk.*s3|multer)', code, re.IGNORECASE))
        if not has_storage:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No storage integration", description=f"FRR-ICP-05 requires secure repository availability.",
                severity=Severity.HIGH, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Implement storage: @azure/storage-blob, aws-sdk/s3, or multer"
            ))
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Bicep for secure storage infrastructure."""
        findings = []
        has_storage = bool(re.search(r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts", code))
        if not has_storage:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No storage infrastructure", description=f"FRR-ICP-05 requires secure repository for incident reports.",
                severity=Severity.MEDIUM, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Deploy storage: Microsoft.Storage/storageAccounts with blob containers"
            ))
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Terraform for secure storage infrastructure."""
        findings = []
        has_storage = bool(re.search(r'resource\s+"(azurerm_storage_account|aws_s3_bucket)"', code))
        if not has_storage:
            findings.append(Finding(
                ksi_id=self.FRR_ID, requirement_id=self.FRR_ID,
                title="No storage infrastructure", description=f"FRR-ICP-05 requires secure repository for incident reports.",
                severity=Severity.MEDIUM, file_path=file_path, line_number=1, code_snippet="",
                recommendation="Deploy storage: azurerm_storage_account or aws_s3_bucket"
            ))
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitHub Actions for artifact upload."""
        return []  # Report availability is runtime operational, not CI/CD
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze Azure Pipelines for artifact upload."""
        return []  # Report availability is runtime operational
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """Analyze GitLab CI for artifact upload."""
        return []  # Report availability is runtime operational
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> Dict[str, Any]:
        """Get automated queries for FRR-ICP-05 evidence (incident report repository availability)."""
        return {
            'automated_queries': [
                "Resources | where type == 'microsoft.storage/storageaccounts' | extend blobEnabled = properties.enableBlobServices | project name, resourceGroup, location, blobEnabled",
                "AzureActivity | where ResourceProviderValue == 'Microsoft.Storage' and OperationNameValue contains 'blobServices' | summarize by ResourceId, Properties",
                "Resources | where type contains 'storage' or type contains 's3' | project name, type, resourceGroup"
            ]
        }
    
    def get_evidence_artifacts(self) -> Dict[str, Any]:
        """Get evidence artifacts for FRR-ICP-05 (incident report repository availability)."""
        return {
            'evidence_artifacts': [
                "Incident report repository documentation (USDA Connect access, trust center URL)",
                "Storage account/S3 bucket configuration exports",
                "Access control policies for repository (RBAC, IAM)",
                "Historical incident report uploads (list, timestamps)",
                "Repository integration testing evidence",
                "Secure file upload mechanism documentation",
                "Trust center or repository availability SLA",
                "FedRAMP repository access credentials/configuration"
            ]
        }
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """Get automation recommendations for FRR-ICP-05 (incident report repository availability)."""
        return {
            'implementation_notes': [
                "Deploy secure storage infrastructure (Azure Storage Account, AWS S3)",
                "Configure integration with FedRAMP repository (USDA Connect) or trust center",
                "Implement secure file upload mechanisms (encryption in transit and at rest)",
                "Configure access controls (RBAC, IAM policies) for repository",
                "Test incident report upload and availability",
                "Document repository access procedures for FedRAMP and agency customers",
                "Monitor storage availability and access logs"
            ]
        }
