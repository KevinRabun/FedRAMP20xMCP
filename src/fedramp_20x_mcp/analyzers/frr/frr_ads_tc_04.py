"""
FRR-ADS-TC-04: Self-Service Access Management

_Trust centers_ SHOULD include features that encourage all necessary parties to provision and manage access to _authorization data_ for their users and services directly.

Official FedRAMP 20x Requirement
Source: FRR-ADS (Authorization Data Sharing) family
Primary Keyword: SHOULD
Impact Levels: Low, Moderate, High
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ADS_TC_04_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-TC-04: Self-Service Access Management
    
    **Official Statement:**
    _Trust centers_ SHOULD include features that encourage all necessary parties to provision and manage access to _authorization data_ for their users and services directly.
    
    **Family:** ADS - Authorization Data Sharing
    
    **Primary Keyword:** SHOULD
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    - High: Yes
    
    **NIST Controls:**
    - TODO: Add relevant NIST controls
    
    **Related KSIs:**
    - TODO: Add related KSI IDs
    
    **Detectability:** Unknown
    
    **Detection Strategy:**
    TODO: Describe what this analyzer detects and how:
        1. Application code patterns (Python, C#, Java, TypeScript) - Use AST
        2. Infrastructure patterns (Bicep, Terraform) - Use regex
        3. CI/CD patterns (GitHub Actions, Azure Pipelines, GitLab CI) - Use regex
    
    """
    
    FRR_ID = "FRR-ADS-TC-04"
    FRR_NAME = "Self-Service Access Management"
    FRR_STATEMENT = """_Trust centers_ SHOULD include features that encourage all necessary parties to provision and manage access to _authorization data_ for their users and services directly."""
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("AC-2", "Account Management"),
        ("AC-3", "Access Enforcement"),
        ("SA-9", "External System Services"),
    ]
    CODE_DETECTABLE = "Partial"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
    ]
    RELATED_KSIS = [
        # TODO: Add related KSI IDs (e.g., "KSI-VDR-01")
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-TC-04 analyzer."""
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
        Analyze Python code for FRR-ADS-TC-04 compliance using AST.
        
        Detects self-service access management:
        - Self-service portal routes
        - Access provisioning functions
        - User/service management endpoints
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect function definitions for self-service features
                function_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in function_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_name_lower = func_text.lower()
                    
                    if any(keyword in func_name_lower for keyword in ['self_service', 'provision_access', 'manage_access', 'user_portal', 'grant_access', 'revoke_access', 'access_request']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Self-service access function detected",
                            description="Found function for self-service access management",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure self-service features encourage parties to manage access directly."
                        ))
                
                # Check decorators for portal routes
                decorators = parser.find_nodes_by_type(tree.root_node, 'decorator')
                for decorator in decorators:
                    decorator_text = parser.get_node_text(decorator, code_bytes).lower()
                    if any(keyword in decorator_text for keyword in ['/portal', '/self-service', '/access-management', '/provision']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Self-service portal route detected",
                            description="Found route for self-service portal",
                            severity=Severity.INFO,
                            line_number=decorator.start_point[0] + 1,
                            code_snippet=decorator_text.split('\n')[0],
                            recommendation="Verify portal encourages self-service access management."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        self_service_patterns = [
            r'self.*service',
            r'provision.*access',
            r'manage.*access',
            r'user.*portal',
            r'access.*request',
            r'grant.*access',
            r'revoke.*access',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in self_service_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Self-service pattern detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure trust center includes self-service features for access management."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-TC-04 compliance using AST.
        
        Detects self-service access management in C#.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect method declarations
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_name_lower = method_text.lower()
                    
                    if any(keyword in method_name_lower for keyword in ['selfservice', 'provisionaccess', 'manageaccess', 'userportal', 'grantaccess', 'revokeaccess', 'accessrequest']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Self-service method detected",
                            description="Found method for self-service access management",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure self-service features encourage direct access management."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:SelfService|ProvisionAccess|ManageAccess|UserPortal|AccessRequest)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Self-service feature detected",
                    description="Found self-service access management reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify self-service features for access management."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-TC-04 compliance using AST.
        
        Detects self-service access management in Java.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect method declarations
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_name_lower = method_text.lower()
                    
                    if any(keyword in method_name_lower for keyword in ['selfservice', 'provisionaccess', 'manageaccess', 'userportal', 'grantaccess', 'revokeaccess', 'accessrequest']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Self-service method detected",
                            description="Found method for self-service access management",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure self-service features encourage direct access management."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:selfService|provisionAccess|manageAccess|userPortal|accessRequest)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Self-service feature detected",
                    description="Found self-service access management reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify self-service features for access management."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-TC-04 compliance using AST.
        
        Detects self-service access management in TypeScript/JavaScript.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Detect function declarations
                function_declarations = parser.find_nodes_by_type(tree.root_node, 'function_declaration')
                for func_decl in function_declarations:
                    func_text = parser.get_node_text(func_decl, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['selfservice', 'provisionaccess', 'manageaccess', 'userportal', 'grantaccess', 'revokeaccess', 'accessrequest']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Self-service function detected",
                            description="Found function for self-service access management",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure self-service features encourage direct access management."
                        ))
                
                # Check arrow functions
                arrow_functions = parser.find_nodes_by_type(tree.root_node, 'arrow_function')
                for arrow_func in arrow_functions:
                    func_text = parser.get_node_text(arrow_func, code_bytes)
                    if any(keyword in func_text.lower() for keyword in ['selfservice', 'provision', 'portal', 'access']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Self-service handler detected",
                            description="Found handler for self-service features",
                            severity=Severity.INFO,
                            line_number=arrow_func.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify self-service access management."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:selfService|provisionAccess|manageAccess|userPortal|accessRequest)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Self-service feature detected",
                    description="Found self-service access management reference",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify self-service features for access management."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-TC-04 compliance.
        
        NOT APPLICABLE: Self-service access management features (user portals, access
        provisioning UIs, access request workflows) are application-level features, not
        infrastructure configuration. The requirement mandates that trust centers provide
        user interfaces and workflows for parties to manage their own access, which is
        implemented through:
        
        1. Application code (portal pages, forms, workflows)
        2. Web framework UI components (React, Angular, Blazor)
        3. Access management business logic
        4. User authentication and authorization flows
        
        These are application design concerns, not infrastructure concerns.
        """
        return []
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-TC-04 compliance.
        
        NOT APPLICABLE: Self-service access management features (user portals, access
        provisioning UIs, access request workflows) are application-level features, not
        infrastructure configuration. The requirement mandates that trust centers provide
        user interfaces and workflows for parties to manage their own access, which is
        implemented through:
        
        1. Application code (portal pages, forms, workflows)
        2. Web framework UI components (React, Angular, Vue)
        3. Access management business logic
        4. User authentication and authorization flows
        
        These are application design concerns, not infrastructure concerns.
        """
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-TC-04 compliance.
        
        NOT APPLICABLE: Self-service access management features are application-level UI
        and workflow concerns, not CI/CD pipeline concerns. The requirement mandates that
        trust center applications provide self-service portals and workflows, which is an
        application design decision, not a build or deployment automation concern.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-TC-04 compliance.
        
        NOT APPLICABLE: Self-service access management features are application-level UI
        and workflow concerns, not CI/CD pipeline concerns. The requirement mandates that
        trust center applications provide self-service portals and workflows, which is an
        application design decision, not a build or deployment automation concern.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-TC-04 compliance.
        
        NOT APPLICABLE: Self-service access management features are application-level UI
        and workflow concerns, not CI/CD pipeline concerns. The requirement mandates that
        trust center applications provide self-service portals and workflows, which is an
        application design decision, not a build or deployment automation concern.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_collection_queries(self) -> List[str]:
        """
        Provide specific queries for collecting evidence of FRR-ADS-TC-04 compliance.
        
        Returns:
            List of queries for various tools and platforms to collect evidence
            of self-service access management features.
        """
        return [
            # Azure Resource Graph queries
            "Resources | where type =~ 'Microsoft.Web/sites' | extend selfServiceEnabled = properties.siteConfig.appSettings | where selfServiceEnabled contains 'SelfService' | project name, resourceGroup, location, selfServiceEnabled",
            
            # Azure Monitor Log Analytics queries
            "AppRequests | where Url contains 'self-service' or Url contains 'portal' or Url contains 'provision' or Url contains 'access-management' | summarize RequestCount = count(), UniqueUsers = dcount(UserId) by Url, bin(TimeGenerated, 1d)",
            
            # Application Insights custom events
            "customEvents | where name in ('AccessProvisioned', 'AccessRevoked', 'SelfServiceRequest', 'UserProvisioned') | extend UserId = tostring(customDimensions.UserId), Action = tostring(customDimensions.Action) | summarize count() by name, Action, bin(timestamp, 1h)",
            
            # Azure AD audit logs
            "AuditLogs | where OperationName contains 'self-service' or OperationName contains 'provision' | extend Initiator = tostring(InitiatedBy.user.userPrincipalName), Target = tostring(TargetResources[0].displayName) | project TimeGenerated, OperationName, Initiator, Target, Result",
            
            # Activity logs for access management
            "AzureActivity | where OperationNameValue contains 'MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS' | where ActivityStatusValue == 'Success' | extend Caller = tostring(Caller), Resource = tostring(Resource) | project TimeGenerated, OperationNameValue, Caller, Resource, ActivityStatusValue",
            
            # Custom application logs
            "traces | where message contains 'self-service' or message contains 'access provisioning' or message contains 'user portal' | extend severity = tostring(severityLevel) | summarize count() by severity, bin(timestamp, 1h)"
        ]
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        List artifacts that serve as evidence for FRR-ADS-TC-04 compliance.
        
        Returns:
            List of evidence artifacts including documents, logs, screenshots,
            and configurations that demonstrate self-service access management.
        """
        return [
            "Self-service portal screenshots showing user access request workflows",
            "User provisioning feature documentation",
            "Access management API documentation (Swagger/OpenAPI specs)",
            "Self-service portal access logs (last 90 days)",
            "User provisioning audit logs showing self-service operations",
            "Access request approval workflow diagrams",
            "Self-service portal user guide or help documentation",
            "Authentication and authorization configuration for portal",
            "Role-based access control (RBAC) configuration for self-service features",
            "Self-service feature release notes or change history"
        ]
    
    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Provide recommendations for automating evidence collection for FRR-ADS-TC-04.
        
        Returns guidance on automated evidence collection for:
        - Self-service access management features
        - User provisioning capabilities
        - Access management workflows
        """
        return {
            "frr_id": self.FRR_ID,
            "frr_name": self.FRR_NAME,
            "powershell_scripts": [
                {
                    "name": "query_self_service_features",
                    "description": "Query application for self-service portal features",
                    "script": """
# Query self-service access management features
$webAppName = "<web-app-name>"
$resourceGroup = "<resource-group>"

# Check web app configuration
Get-AzWebApp -ResourceGroupName $resourceGroup -Name $webAppName | 
    Select-Object Name, State, Enabled, @{N='SelfServiceEnabled';E={$_.SiteConfig.AppSettings | Where-Object {$_.Name -like '*SelfService*'}}}

# Check authentication settings
Get-AzWebAppAuthSettings -ResourceGroupName $resourceGroup -Name $webAppName
                    """
                },
                {
                    "name": "check_access_provisioning",
                    "description": "Check for access provisioning and management features",
                    "script": """
# Check for user provisioning capabilities
$appServiceId = "<app-service-id>"

# Query managed identities
Get-AzResource -ResourceId $appServiceId | Select-Object Identity

# Check role assignments for access management
Get-AzRoleAssignment -Scope $appServiceId
                    """
                }
            ],
            "cli_commands": [
                {
                    "tool": "az",
                    "command": "az webapp show --name <app-name> --resource-group <rg> --query '{name:name, enabled:enabled, state:state, selfService:siteConfig.appSettings[?name==\"SelfServiceEnabled\"]}'",
                    "description": "Check web app self-service configuration"
                },
                {
                    "tool": "az",
                    "command": "az ad app list --query \"[?contains(displayName, 'SelfService') || contains(displayName, 'Portal')].{Name:displayName, AppId:appId}\"",
                    "description": "List AD applications with self-service portals"
                },
                {
                    "tool": "az",
                    "command": "az role assignment list --scope <resource-id> --query '[].{Principal:principalName, Role:roleDefinitionName}'",
                    "description": "Check role assignments for access management"
                }
            ],
            "api_queries": [
                {
                    "service": "Microsoft Graph API",
                    "endpoint": "GET https://graph.microsoft.com/v1.0/applications",
                    "description": "Query applications with self-service access management",
                    "filter": "displayName eq 'SelfServicePortal' or contains(displayName, 'AccessManagement')"
                },
                {
                    "service": "Azure Resource Manager API",
                    "endpoint": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{site}/config/appsettings",
                    "description": "Get application settings for self-service features"
                }
            ],
            "monitoring_queries": [
                {
                    "service": "Azure Monitor",
                    "query": "AppRequests | where Url contains 'self-service' or Url contains 'portal' or Url contains 'access-management' | summarize count() by Url, ResultCode",
                    "description": "Track usage of self-service portal endpoints"
                },
                {
                    "service": "Azure Application Insights",
                    "query": "customEvents | where name == 'AccessProvisioned' or name == 'AccessRevoked' or name == 'SelfServiceRequest' | summarize count() by name, bin(timestamp, 1h)",
                    "description": "Monitor self-service access management events"
                }
            ],
            "collection_notes": [
                "Capture screenshots of self-service portal UI showing access request workflows",
                "Document user provisioning features available through the portal",
                "Export access management audit logs showing self-service operations",
                "Collect user feedback or surveys on self-service feature usability",
                "Capture API documentation for programmatic self-service access"
            ],
            "best_practices": [
                "Enable detailed logging for all self-service access management operations",
                "Configure alerts for self-service provisioning activities",
                "Maintain audit trails of access requests and approvals",
                "Document self-service workflows in system security plan (SSP)",
                "Implement automated testing for self-service portal functionality",
                "Regularly review self-service access patterns for anomalies"
            ]
        }
