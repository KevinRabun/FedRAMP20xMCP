"""
FRR-ADS-05: Responsible Information Sharing

Providers MUST provide sufficient information in _authorization data_ to support authorization decisions but SHOULD NOT include sensitive information that would _likely_ enable a threat actor to gain unauthorized access, cause harm, disrupt operations, or otherwise have a negative adverse impact on the _cloud service offering_. 

Official FedRAMP 20x Requirement
Source: FRR-ADS (Authorization Data Sharing) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class FRR_ADS_05_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-05: Responsible Information Sharing
    
    **Official Statement:**
    Providers MUST provide sufficient information in _authorization data_ to support authorization decisions but SHOULD NOT include sensitive information that would _likely_ enable a threat actor to gain unauthorized access, cause harm, disrupt operations, or otherwise have a negative adverse impact on the _cloud service offering_. 
    
    **Family:** ADS - Authorization Data Sharing
    
    **Primary Keyword:** MUST
    
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
    
    FRR_ID = "FRR-ADS-05"
    FRR_NAME = "Responsible Information Sharing"
    FRR_STATEMENT = """Providers MUST provide sufficient information in _authorization data_ to support authorization decisions but SHOULD NOT include sensitive information that would _likely_ enable a threat actor to gain unauthorized access, cause harm, disrupt operations, or otherwise have a negative adverse impact on the _cloud service offering_. """
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("AC-4", "Information Flow Enforcement"),
        ("SC-4", "Information in Shared System Resources"),
        ("SI-12", "Information Management and Retention"),
        ("AU-9", "Protection of Audit Information"),
    ]
    CODE_DETECTABLE = "Yes"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
        "KSI-MLA-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-05 analyzer."""
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
        Analyze Python code for FRR-ADS-05 compliance using AST.
        
        Detects responsible information sharing:
        - Data sanitization/redaction
        - Masking sensitive fields
        - Filtering/scrubbing functions
        - Preventing information leakage
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis first
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for sanitization/redaction functions
                function_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func in function_defs:
                    func_text = parser.get_node_text(func, code_bytes).lower()
                    if any(pattern in func_text for pattern in ['sanitize', 'redact', 'mask', 'scrub', 'filter_sensitive']):
                        line_num = func.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Data sanitization detected",
                            description="Found data sanitization/redaction function",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else "",
                            recommendation="Ensure sensitive information is properly sanitized before sharing authorization data."
                        ))
                
                # Look for potential information leakage
                calls = parser.find_nodes_by_type(tree.root_node, 'call')
                for call in calls:
                    call_text = parser.get_node_text(call, code_bytes).lower()
                    # Check for risky operations that might expose sensitive data
                    if any(pattern in call_text for pattern in ['print(password', 'print(secret', 'print(key', 'log(password', 'log(secret']):
                        line_num = call.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Potential sensitive information leakage",
                            description="Found logging/printing of sensitive data",
                            severity=Severity.HIGH,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else "",
                            recommendation="Do not expose passwords, secrets, or keys in logs or output."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        sanitization_patterns = [
            r'def.*sanitize',
            r'def.*redact',
            r'def.*mask',
            r'def.*scrub',
            r'filter.*sensitive',
            r'\.mask\(',
            r'\.redact\(',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in sanitization_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Data sanitization detected",
                        description=f"Found sanitization pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure authorization data includes sufficient info without sensitive details."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-05 compliance using AST.
        
        Detects responsible information sharing in C#:
        - Data sanitization methods
        - Masking/redaction functions
        - Sensitive data filtering
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for sanitization methods
                methods = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in methods:
                    method_text = parser.get_node_text(method, code_bytes).decode('utf8').lower()
                    if any(pattern in method_text for pattern in ['sanitize', 'redact', 'mask', 'scrub']):
                        line_num = method.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Data sanitization detected (C#)",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else ""
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        for i, line in enumerate(lines, 1):
            if re.search(r'(sanitize|redact|mask|scrub)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Data sanitization detected (C#)",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip()
                ))
                break
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-05 compliance using AST.
        
        Detects responsible information sharing in Java:
        - Data sanitization methods
        - Masking utilities
        - Sensitive data filtering
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for sanitization methods
                methods = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in methods:
                    method_text = parser.get_node_text(method, code_bytes).decode('utf8').lower()
                    if any(pattern in method_text for pattern in ['sanitize', 'redact', 'mask', 'scrub']):
                        line_num = method.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Data sanitization detected (Java)",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else ""
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        for i, line in enumerate(lines, 1):
            if re.search(r'(sanitize|redact|mask|scrub)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Data sanitization detected (Java)",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip()
                ))
                break
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-05 compliance using AST.
        
        Detects responsible information sharing in TypeScript:
        - Data sanitization functions
        - Masking utilities
        - Sensitive data filtering
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for sanitization functions
                functions = parser.find_nodes_by_type(tree.root_node, 'function_declaration')
                functions.extend(parser.find_nodes_by_type(tree.root_node, 'method_definition'))
                
                for func in functions:
                    func_text = parser.get_node_text(func, code_bytes).decode('utf8').lower()
                    if any(pattern in func_text for pattern in ['sanitize', 'redact', 'mask', 'scrub']):
                        line_num = func.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Data sanitization detected (TypeScript)",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else ""
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        for i, line in enumerate(lines, 1):
            if re.search(r'(sanitize|redact|mask|scrub)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Data sanitization detected (TypeScript)",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip()
                ))
                break
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-05 compliance.
        
        Detects responsible information sharing in infrastructure:
        - Key Vault for secret management
        - Managed identities
        - Secure parameter handling
        """
        findings = []
        lines = code.split('\n')
        
        # Secret management resources
        secret_mgmt_resources = [
            r"resource\s+\w+\s+'Microsoft\.KeyVault/vaults",  # Key Vault
            r"resource\s+\w+\s+'Microsoft\.ManagedIdentity",  # Managed Identity
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in secret_mgmt_resources:
                if re.search(pattern, line):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Secret management resource detected",
                        description="Found resource for responsible secret handling",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure secrets are not exposed in authorization data sharing."
                    ))
                    break
        
        # Check for @secure decorator on parameters
        if re.search(r'@secure\(\)', code):
            for i, line in enumerate(lines, 1):
                if re.search(r'@secure\(\)', line):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Secure parameter detected",
                        description="Found @secure decorator for sensitive parameter",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip()
                    ))
                    break
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-05 compliance.
        
        Detects responsible information sharing in infrastructure:
        - Key Vault usage
        - Managed identities
        - Sensitive variable handling
        """
        findings = []
        lines = code.split('\n')
        
        # Secret management resources
        secret_resources = [
            r'resource\s+"azurerm_key_vault"',
            r'resource\s+"azurerm_user_assigned_identity"',
            r'data\s+"azurerm_key_vault_secret"',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in secret_resources:
                if re.search(pattern, line):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Secret management resource detected",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure secrets are not exposed in authorization data."
                    ))
                    break
        
        # Check for sensitive variables
        if re.search(r'sensitive\s*=\s*true', code):
            for i, line in enumerate(lines, 1):
                if re.search(r'sensitive\s*=\s*true', line):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Sensitive variable detected",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip()
                    ))
                    break
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-05 compliance.
        
        Detects responsible information sharing automation:
        - Secret scanning
        - Sensitive data detection
        - Sanitization steps
        """
        findings = []
        lines = code.split('\n')
        
        # Responsible sharing patterns
        responsible_patterns = [
            r'secret.*scan',
            r'gitleaks',
            r'truffleHog',
            r'detect.*secrets',
            r'sanitize',
            r'redact',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in responsible_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Secret scanning/sanitization detected",
                        description="Found step for responsible information handling",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure secrets are detected and sanitized before sharing."
                    ))
                    break
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-05 compliance.
        
        Detects responsible information sharing automation.
        """
        findings = []
        lines = code.split('\n')
        
        # Responsible sharing patterns
        responsible_patterns = [
            r'secret.*scan',
            r'credential.*scan',
            r'detect.*secrets',
            r'sanitize',
            r'redact',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in responsible_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Secret scanning/sanitization detected",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure secrets are sanitized before sharing."
                    ))
                    break
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-05 compliance.
        
        Detects responsible information sharing automation.
        """
        findings = []
        lines = code.split('\n')
        
        # Responsible sharing patterns
        responsible_patterns = [
            r'secret.*detection',
            r'gitleaks',
            r'detect.*secrets',
            r'sanitize',
            r'redact',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in responsible_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Secret scanning/sanitization detected",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure secrets are sanitized before sharing."
                    ))
                    break
        
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-05.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Yes',
            'automation_feasibility': 'High - Can automate detection of data sanitization functions, secret scanning, sensitive information redaction, and information leakage prevention',
            'automation_approach': 'Automated detection of responsible information sharing through code analysis (redaction functions, data masking, sanitization), secret scanning (hardcoded credentials, API keys), and documentation review (sensitive detail exposure)',
            'evidence_artifacts': [
                'Code implementing data sanitization/redaction for authorization data',
                'Secret scanning reports (no hardcoded credentials in public repos)',
                'Data classification policy showing sensitive vs. public information',
                'Redacted authorization data examples (SSP with sensitive details masked)',
                'Documentation review showing appropriate detail level',
                'Threat modeling showing no sensitive info enables attacks'
            ],
            'collection_queries': [
                'Code scan: Detect sanitization functions (redact, mask, sanitize)',
                'Secret scan: GitHub Advanced Security secret scanning alerts',
                'Documentation review: Public SSP vs. detailed internal SSP comparison',
                'Git history: Check for accidental sensitive information commits',
                'API responses: Verify no sensitive data in public endpoints'
            ],
            'manual_validation_steps': [
                '1. Review authorization data (SSP, service list) for appropriate detail level',
                '2. Verify sensitive information (IP addresses, internal hostnames, credentials) is redacted',
                '3. Confirm sufficient detail for authorization decisions (architecture, controls, procedures)',
                '4. Check that no hardcoded secrets exist in public repositories',
                '5. Validate data classification policy defines sensitive vs. public information',
                '6. Review threat model confirms no sensitive info enables threat actor attacks'
            ],
            'recommended_services': [
                'GitHub Advanced Security - secret scanning and vulnerability detection',
                'Azure Key Vault - secure credential storage (prevent hardcoding)',
                'Azure Information Protection - data classification labels',
                'Microsoft Purview - data governance and sensitive info discovery',
                'Azure Security Center - security posture and threat detection'
            ],
            'azure_services': [
                'GitHub Advanced Security (secret scanning for hardcoded credentials)',
                'Azure Key Vault (secure storage preventing hardcoded secrets)',
                'Microsoft Purview (data classification and sensitive info discovery)',
                'Azure Information Protection (automated sensitive data labeling)',
                'Azure DevOps Credential Scanner (detect secrets in code)'
            ],
            'collection_methods': [
                'Static code analysis for hardcoded secrets and sensitive data exposure',
                'Secret scanning with GitHub Advanced Security or Trufflehog',
                'Documentation comparison (public SSP vs. detailed internal SSP)',
                'Data classification review to identify sensitive vs. public info',
                'API endpoint testing to verify no sensitive data leakage',
                'Git commit history review for accidental sensitive info exposure'
            ],
            'implementation_steps': [
                '1. Enable secret scanning on all repositories (GitHub Advanced Security or GitGuardian)',
                '2. Implement data redaction functions in code (mask IPs, hostnames, credentials)',
                '3. Create data classification policy defining sensitive vs. public authorization data',
                '4. Review public SSP/documentation and redact sensitive details (internal IPs, system names)',
                '5. Ensure sufficient detail remains for authorization decisions (architecture diagrams, control descriptions)',
                '6. Configure pre-commit hooks to prevent accidental sensitive info commits',
                '7. Conduct quarterly reviews to verify appropriate information sharing balance'
            ],
            'integration_points': [
                'Secret scanning integrated with CI/CD to block commits with secrets',
                'Data classification labels applied to OSCAL SSP documents',
                'Threat modeling integrated with security review process',
                'Pre-commit hooks enforce secret detection before git push'
            ]
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get specific queries for collecting FRR-ADS-05 evidence.
        
        Returns:
            List of evidence collection queries specific to responsible information sharing verification
        """
        return [
            {
                'method_type': 'Secret Scanning',
                'name': 'Hardcoded Credential and Sensitive Data Detection',
                'description': 'Scan code repositories for hardcoded credentials, API keys, passwords, and other sensitive information',
                'command': 'trufflehog git https://github.com/{owner}/{repo} --json | jq ".[] | {file: .File, secret_type: .Reason, line: .Line}"',
                'purpose': 'Identify hardcoded secrets or sensitive information that SHOULD NOT be included in authorization data per FRR-ADS-05',
                'evidence_type': 'Secret scanning report',
                'validation_checks': [
                    'Zero hardcoded passwords, API keys, or credentials found',
                    'No database connection strings with embedded passwords',
                    'No private keys or certificates in code',
                    'All secrets stored in Azure Key Vault or environment variables'
                ],
                'storage_location': 'Evidence/ADS-05/secret-scanning/'
            },
            {
                'method_type': 'Code Analysis',
                'name': 'Data Sanitization and Redaction Function Detection',
                'description': 'Scan code for functions that sanitize, redact, or mask sensitive information before sharing authorization data',
                'command': 'grep -r -E "(redact|sanitize|mask|scrub|filter).*[Pp]assword|[Ii][Pp]|[Hh]ostname|[Cc]redential" src/ --include="*.py" --include="*.cs" --include="*.java"',
                'purpose': 'Verify code implements data sanitization to prevent sensitive information exposure per FRR-ADS-05',
                'evidence_type': 'Data sanitization implementation report',
                'validation_checks': [
                    'Functions exist to redact sensitive fields (IPs, hostnames, credentials)',
                    'Sanitization applied before exporting authorization data (SSP, service lists)',
                    'Masking preserves sufficient detail for authorization decisions',
                    'Unit tests verify redaction functions work correctly'
                ],
                'storage_location': 'Evidence/ADS-05/sanitization-functions/'
            },
            {
                'method_type': 'Documentation Review',
                'name': 'Public vs. Detailed Authorization Data Comparison',
                'description': 'Compare public-facing authorization data (SSP, README) with detailed internal versions to verify appropriate redaction',
                'command': 'python scripts/compare_ssp_versions.py --public public-ssp.json --internal internal-ssp.json --report redaction-analysis.json',
                'purpose': 'Confirm sufficient information provided for authorization decisions while sensitive details are redacted per FRR-ADS-05',
                'evidence_type': 'SSP comparison and redaction analysis report',
                'validation_checks': [
                    'Public SSP includes architecture diagrams (but with internal IPs/hostnames redacted)',
                    'Control descriptions sufficiently detailed for authorization decisions',
                    'Sensitive system names, internal network details redacted',
                    'Threat modeling confirms no sensitive info enables attacker reconnaissance'
                ],
                'storage_location': 'Evidence/ADS-05/documentation-comparison/'
            },
            {
                'method_type': 'Data Classification',
                'name': 'Authorization Data Classification Policy Review',
                'description': 'Review data classification policy to verify it defines what information is sensitive vs. public for authorization data',
                'command': '# Manual review of data classification policy document: policies/data-classification-policy.pdf',
                'purpose': 'Validate organization has clear policy defining sensitive information that SHOULD NOT be shared per FRR-ADS-05',
                'evidence_type': 'Data classification policy document',
                'validation_checks': [
                    'Policy explicitly defines sensitive authorization data (internal IPs, hostnames, credentials, detailed architecture)',
                    'Policy specifies public authorization data (high-level architecture, control descriptions, service lists)',
                    'Policy addresses FRR-ADS-05 requirement for balanced information sharing',
                    'Policy reviewed and approved by security team'
                ],
                'storage_location': 'Evidence/ADS-05/policies/'
            },
            {
                'method_type': 'API Endpoint Testing',
                'name': 'Public Authorization Data Endpoint Verification',
                'description': 'Test public-facing APIs and documentation endpoints to verify no sensitive information exposed',
                'command': 'curl -s https://{authorizationDataEndpoint}/ssp.json | jq \'.. | select(type=="string") | select(test("(?i)(password|secret|key|token|10\\\\.|192\\\\.168\\\\.)"))\'',
                'purpose': 'Confirm public authorization data endpoints do not leak sensitive information per FRR-ADS-05',
                'evidence_type': 'API endpoint security test report',
                'validation_checks': [
                    'No passwords, secrets, or API keys in API responses',
                    'No internal IP addresses (10.x.x.x, 192.168.x.x) exposed',
                    'No internal hostnames or system names revealed',
                    'Error messages do not expose sensitive system details'
                ],
                'storage_location': 'Evidence/ADS-05/api-testing/'
            },
            {
                'method_type': 'Git History Analysis',
                'name': 'Accidental Sensitive Information Commit Detection',
                'description': 'Scan Git commit history for accidental commits of sensitive information that should be redacted',
                'command': 'git log --all --full-history -- "*ssp*" "*auth*" | git grep -E "(password|secret|10\\.|192\\.168\\.)" $(git rev-list --all) -- "*ssp*"',
                'purpose': 'Identify and remediate any accidental sensitive information exposure in version control history',
                'evidence_type': 'Git history sensitive info audit report',
                'validation_checks': [
                    'No commits contain hardcoded passwords or secrets',
                    'No internal IP addresses or hostnames committed to public repos',
                    'If sensitive info found, verify commits scrubbed using BFG Repo-Cleaner or git-filter-repo',
                    'Pre-commit hooks configured to prevent future sensitive info commits'
                ],
                'storage_location': 'Evidence/ADS-05/git-history-audit/'
            }
        ]
    
    def get_evidence_artifacts(self) -> List[dict]:
        """
        Get list of evidence artifacts for FRR-ADS-04 compliance.
        
        Returns:
            List of evidence artifacts specific to responsible information sharing verification
        """
        return [
            {
                'artifact_name': 'Secret Scanning Report',
                'artifact_type': 'Security Scan Results',
                'description': 'Report from GitHub Advanced Security, Trufflehog, or GitGuardian showing no hardcoded secrets in repositories',
                'collection_method': 'Run secret scanning tool across all repositories, export results showing zero findings',
                'validation_checks': [
                    'Zero hardcoded passwords, API keys, or credentials detected',
                    'Scan covers all repositories containing authorization data',
                    'Historical commits scanned (not just current HEAD)',
                    'Findings (if any) documented with remediation status'
                ],
                'storage_location': 'Evidence/ADS-05/secret-scanning/report.json',
                'retention_period': '7 years per FedRAMP requirements'
            },
            {
                'artifact_name': 'Data Sanitization Implementation',
                'artifact_type': 'Source Code + Unit Tests',
                'description': 'Source code implementing data redaction functions (mask IPs, hostnames, credentials) with unit tests',
                'collection_method': 'Export code files containing sanitization functions, include unit test coverage report',
                'validation_checks': [
                    'Functions exist to redact sensitive fields (redact_ip, mask_hostname, sanitize_credentials)',
                    'Unit tests verify redaction works correctly (90%+ coverage)',
                    'Functions applied before exporting authorization data to public',
                    'Code review confirms no bypasses of sanitization'
                ],
                'storage_location': 'Evidence/ADS-05/code/sanitization-functions/',
                'retention_period': '7 years'
            },
            {
                'artifact_name': 'Public vs. Detailed SSP Comparison',
                'artifact_type': 'Compliance Analysis Report',
                'description': 'Side-by-side comparison of public SSP (redacted) vs. detailed internal SSP showing appropriate information balance',
                'collection_method': 'Use automated diff tool to compare SSP versions, generate report highlighting redacted sections',
                'validation_checks': [
                    'Public SSP redacts internal IPs, hostnames, detailed network topology',
                    'Public SSP retains sufficient detail (high-level architecture, control descriptions)',
                    'Redaction policy applied consistently across all sections',
                    'Security review confirms balance meets FRR-ADS-05 (sufficient + not sensitive)'
                ],
                'storage_location': 'Evidence/ADS-05/ssp-comparison/redaction-analysis.pdf',
                'retention_period': '7 years'
            },
            {
                'artifact_name': 'Data Classification Policy',
                'artifact_type': 'Policy Document',
                'description': 'Organization policy defining sensitive vs. public information for authorization data sharing',
                'collection_method': 'Export approved data classification policy document from policy management system',
                'validation_checks': [
                    'Policy explicitly addresses authorization data classification',
                    'Defines sensitive information (internal IPs, hostnames, credentials, detailed arch)',
                    'Defines public information (service lists, high-level architecture, controls)',
                    'Policy approved by CISO and references FRR-ADS-05 requirement'
                ],
                'storage_location': 'Evidence/ADS-05/policies/data-classification-policy.pdf',
                'retention_period': '7 years'
            },
            {
                'artifact_name': 'API Endpoint Security Test Results',
                'artifact_type': 'Security Testing Report',
                'description': 'Results from automated testing of public authorization data API endpoints verifying no sensitive information exposure',
                'collection_method': 'Run automated security tests against public APIs, generate pass/fail report',
                'validation_checks': [
                    'No passwords, secrets, or API keys in API responses',
                    'No internal IP addresses or hostnames exposed',
                    'Error messages do not reveal sensitive system details',
                    'Tests run monthly and all pass'
                ],
                'storage_location': 'Evidence/ADS-05/api-testing/endpoint-security-report.json',
                'retention_period': '7 years (monthly snapshots)'
            },
            {
                'artifact_name': 'Threat Model - Information Sharing Balance',
                'artifact_type': 'Threat Modeling Document',
                'description': 'Threat model analyzing whether public authorization data exposes information useful to threat actors',
                'collection_method': 'Conduct threat modeling workshop, document findings, verify no sensitive info enables reconnaissance or attacks',
                'validation_checks': [
                    'Threat model considers attacker perspective on public authorization data',
                    'Confirms no exposed information enables unauthorized access',
                    'Validates redaction of sensitive details (IPs, hostnames, network topology)',
                    'Security team approval that information sharing balance meets FRR-ADS-05'
                ],
                'storage_location': 'Evidence/ADS-05/threat-modeling/threat-model.pdf',
                'retention_period': '7 years'
            }
        ]
