"""
KSI-TPR-03: Supply Chain Risk Management

Identify and prioritize mitigation of potential supply chain risks.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


class KSI_TPR_03_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-TPR-03: Supply Chain Risk Management
    
    **Official Statement:**
    Identify and prioritize mitigation of potential supply chain risks.
    
    **Family:** TPR - Third-Party Information Resources
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - ac-20
    - ra-3.1
    - sa-9
    - sa-10
    - sa-11
    - sa-15.3
    - sa-22
    - si-7.1
    - sr-5
    - sr-6
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-TPR-03"
    KSI_NAME = "Supply Chain Risk Management"
    KSI_STATEMENT = """Identify and prioritize mitigation of potential supply chain risks."""
    FAMILY = "TPR"
    FAMILY_NAME = "Third-Party Information Resources"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("ac-20", "Use of External Systems"),
        ("ra-3.1", "Supply Chain Risk Assessment"),
        ("sa-9", "External System Services"),
        ("sa-10", "Developer Configuration Management"),
        ("sa-11", "Developer Testing and Evaluation"),
        ("sa-15.3", "Criticality Analysis"),
        ("sa-22", "Unsupported System Components"),
        ("si-7.1", "Integrity Checks"),
        ("sr-5", "Acquisition Strategies, Tools, and Methods"),
        ("sr-6", "Supplier Assessments and Reviews")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RETIRED = False
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    # ============================================================================
    # APPLICATION LANGUAGE ANALYZERS
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Python code for KSI-TPR-03 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Vulnerable dependencies (deferred to scan_dependency_file tool)
        - Insecure package sources (HTTP PyPI mirrors)
        - Missing integrity checks (pip --require-hashes)
        - Unpinned dependencies (pip install without version)
        """
        # Try AST-based analysis first
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        if tree:
            return self._analyze_python_ast(code, file_path, parser, tree)
        
        # Fallback to regex
        return self._analyze_python_regex(code, file_path)
    
    def _analyze_python_ast(self, code: str, file_path: str, parser, tree) -> List[Finding]:
        """AST-based analysis for Python using tree-sitter."""
        findings = []
        lines = code.split('\n')
        code_bytes = code.encode('utf-8')
        
        # Pattern 1: subprocess.run/call with pip/HTTP (AST detection)
        for call_node in parser.find_nodes_by_type(tree.root_node, "call"):
            call_text = parser.get_node_text(call_node, code_bytes)
            
            # Check for subprocess calls with pip and HTTP
            if 'subprocess' in call_text and 'pip' in call_text and 'http://' in call_text:
                line_num = code[:call_node.start_byte].count('\n') + 1
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Insecure Package Source (HTTP PyPI Mirror)",
                    description=(
                        f"HTTP package index URL at line {line_num}. Using HTTP for package downloads "
                        f"exposes supply chain to man-in-the-middle attacks where attackers can inject "
                        f"malicious packages. Use HTTPS to protect package integrity."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use HTTPS for package sources:\n"
                        "pip install --index-url https://pypi.org/simple/ package_name\n"
                        "Or use default PyPI (already HTTPS): pip install package_name"
                    ),
                    ksi_id=self.KSI_ID
                ))
                break
        
        # Pattern 2: requirements.txt files - use regex (file content analysis)
        if 'requirements.txt' in file_path.lower():
            findings.extend(self._analyze_python_requirements(code, lines, file_path))
        
        return findings
    
    def _analyze_python_requirements(self, code: str, lines: List[str], file_path: str) -> List[Finding]:
        """Analyze requirements.txt for missing hashes."""
        findings = []
        
        if re.search(r'^\w+[<>=]', code, re.MULTILINE):
            has_hashes = re.search(r'--hash=', code)
            if not has_hashes:
                result = self._find_line(lines, r'^\w+[<>=]')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Missing Package Integrity Checks",
                    description=(
                        f"Requirements file at line {line_num} without hash verification. "
                        f"Hashes protect against supply chain attacks by ensuring downloaded packages "
                        f"match expected content. Without hashes, compromised packages could be installed."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Generate hashed requirements:\n"
                        "pip-compile --generate-hashes requirements.in\n"
                        "Or use pip-tools: pip install --require-hashes -r requirements.txt\n"
                        "Example format: package==1.2.3 --hash=sha256:abc123..."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def _analyze_python_regex(self, code: str, file_path: str) -> List[Finding]:
        """Fallback regex-based analysis for Python."""
        # Note: Using regex - fallback when tree-sitter unavailable
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTP PyPI mirror usage (HIGH)
        if re.search(r'--index-url\s+http://', code) or re.search(r'--extra-index-url\s+http://', code):
            result = self._find_line(lines, r'--index-url.*http://|--extra-index-url.*http://')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Insecure Package Source (HTTP PyPI Mirror)",
                description=(
                    f"HTTP package index URL at line {line_num}. Using HTTP for package downloads "
                    f"exposes supply chain to man-in-the-middle attacks where attackers can inject "
                    f"malicious packages. Use HTTPS to protect package integrity."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use HTTPS for package sources:\n"
                    "pip install --index-url https://pypi.org/simple/ package_name\n"
                    "Or use default PyPI (already HTTPS): pip install package_name"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: requirements.txt files
        if 'requirements.txt' in file_path.lower():
            findings.extend(self._analyze_python_requirements(code, lines, file_path))
        
        return findings
        if re.search(r'--index-url\s+http://', code) or re.search(r'--extra-index-url\s+http://', code):
            result = self._find_line(lines, r'--index-url.*http://|--extra-index-url.*http://')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Insecure Package Source (HTTP PyPI Mirror)",
                description=(
                    f"HTTP package index URL at line {line_num}. Using HTTP for package downloads "
                    f"exposes supply chain to man-in-the-middle attacks where attackers can inject "
                    f"malicious packages. Use HTTPS to protect package integrity."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use HTTPS for package sources:\n"
                    "pip install --index-url https://pypi.org/simple/ package_name\n"
                    "Or use default PyPI (already HTTPS): pip install package_name"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: requirements.txt without hashes (MEDIUM)
        if 'requirements.txt' in file_path.lower() and re.search(r'^\w+[<>=]', code, re.MULTILINE):
            has_hashes = re.search(r'--hash=', code)
            if not has_hashes:
                result = self._find_line(lines, r'^\w+[<>=]')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Missing Package Integrity Checks",
                    description=(
                        f"Requirements file at line {line_num} without hash verification. "
                        f"Hashes protect against supply chain attacks by ensuring downloaded packages "
                        f"match expected content. Without hashes, compromised packages could be installed."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Generate hashed requirements:\n"
                        "pip-compile --generate-hashes requirements.in\n"
                        "Or use pip-tools: pip install --require-hashes -r requirements.txt\n"
                        "Example format: package==1.2.3 --hash=sha256:abc123..."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-TPR-03 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Vulnerable NuGet packages (deferred to scan_dependency_file tool)
        - HTTP NuGet sources in nuget.config
        - Missing package signature validation
        - Floating version ranges (wildcards)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTP NuGet source (HIGH)
        if re.search(r'<add\s+key="[^"]+"\s+value="http://', code, re.IGNORECASE):
            result = self._find_line(lines, r'<add\s+key.*value="http://')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Insecure NuGet Package Source (HTTP)",
                description=(
                    f"HTTP NuGet source at line {line_num}. Using HTTP for package downloads "
                    f"exposes supply chain to man-in-the-middle attacks. Attackers can inject "
                    f"malicious packages during download. Use HTTPS to protect package integrity."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use HTTPS for NuGet sources in nuget.config:\n"
                    "<add key=\"nuget.org\" value=\"https://api.nuget.org/v3/index.json\" />\n"
                    "Remove or update HTTP sources to HTTPS equivalents."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Disabled package signature validation (MEDIUM)
        # Check both element format and attribute format
        if (re.search(r'<signatureValidationMode>.*none.*</signatureValidationMode>', code, re.IGNORECASE) or
            re.search(r'key="signatureValidationMode"\s+value="none"', code, re.IGNORECASE)):
            result = self._find_line(lines, r'signatureValidationMode.*none')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="NuGet Package Signature Validation Disabled",
                description=(
                    f"Package signature validation disabled at line {line_num}. Signature validation "
                    f"ensures packages are from trusted publishers and haven't been tampered with. "
                    f"Disabling this check increases supply chain risk."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Enable package signature validation in nuget.config:\n"
                    "<signatureValidationMode>require</signatureValidationMode>\n"
                    "Or use:\n"
                    '<add key="signatureValidationMode" value="require" />\n'
                    "This ensures packages are signed by trusted publishers."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-TPR-03 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Vulnerable Maven/Gradle dependencies (deferred to scan_dependency_file tool)
        - HTTP Maven repositories
        - Missing dependency verification
        - Dynamic versions (LATEST, RELEASE, +)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTP Maven repository (HIGH)
        if re.search(r'<url>http://', code) or re.search(r'maven\s*\{\s*url\s+["\']http://', code):
            result = self._find_line(lines, r'<url>http://|maven.*url.*http://')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Insecure Maven Repository (HTTP)",
                description=(
                    f"HTTP Maven repository at line {line_num}. Using HTTP for dependency downloads "
                    f"exposes supply chain to man-in-the-middle attacks. Attackers can inject malicious "
                    f"artifacts. Use HTTPS to protect dependency integrity."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use HTTPS for Maven repositories:\n"
                    "Maven (pom.xml): <url>https://repo.maven.apache.org/maven2</url>\n"
                    "Gradle (build.gradle): maven { url 'https://repo.maven.apache.org/maven2' }"
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Dynamic versions (MEDIUM)
        if re.search(r'<version>(LATEST|RELEASE|\+)', code) or re.search(r"['\"][^'\"]+:\+['\"]", code):
            result = self._find_line(lines, r'<version>(LATEST|RELEASE|\+)|:\+', use_regex=True)
            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Dynamic Dependency Versions Increase Supply Chain Risk",
                description=(
                    f"Dynamic version specifier at line {line_num}. Using LATEST, RELEASE, or + "
                    f"allows automatic updates to new versions without review. This increases supply "
                    f"chain risk as compromised versions could be automatically introduced."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Pin dependency versions:\n"
                    "Maven: <version>1.2.3</version> (specific version)\n"
                    "Gradle: implementation 'group:artifact:1.2.3'\n"
                    "Use Dependabot or Renovate for controlled updates."
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-TPR-03 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Vulnerable npm packages (deferred to scan_dependency_file tool)
        - HTTP npm registries (.npmrc)
        - Missing package lock files
        - Version ranges too broad (^, ~, *, x)
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: HTTP npm registry (HIGH)
        # Check both .npmrc format and package.json publishConfig format
        if ('.npmrc' in file_path.lower() and re.search(r'registry\s*=\s*http://', code)) or \
           ('package.json' in file_path.lower() and re.search(r'"registry"\s*:\s*"http://', code)):
            result = self._find_line(lines, r'registry.*http://')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.HIGH,
                title="Insecure npm Registry (HTTP)",
                description=(
                    f"HTTP npm registry at line {line_num}. Using HTTP for package downloads "
                    f"exposes supply chain to man-in-the-middle attacks. Attackers can inject "
                    f"malicious packages. Use HTTPS to protect package integrity."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Use HTTPS for npm registry:\n"
                    ".npmrc: registry=https://registry.npmjs.org/\n"
                    'package.json: "registry": "https://registry.npmjs.org"\n'
                    "Remove HTTP registry configurations."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Very broad version ranges (MEDIUM)
        if 'package.json' in file_path.lower():
            if re.search(r'"\*":|"latest":|">="', code):
                result = self._find_line(lines, r'"\*":|"latest":|">="')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Overly Broad Dependency Version Ranges",
                    description=(
                        f"Very broad version range at line {line_num}. Using *, latest, or >= "
                        f"allows automatic updates to any version without review. This increases "
                        f"supply chain risk as breaking changes or compromised versions could be "
                        f"automatically introduced."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Use more restrictive version ranges:\n"
                        "\"^1.2.3\" - allows patch and minor updates (recommended)\n"
                        "\"~1.2.3\" - allows only patch updates\n"
                        "\"1.2.3\" - exact version (most restrictive)\n"
                        "Always commit package-lock.json or yarn.lock for reproducible builds."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-TPR-03 compliance.
        
        Detects:
        - Container images from untrusted registries
        - Missing image digest/SHA pinning
        - Public container images without vulnerability scanning
        - Latest tag usage
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Container image with :latest tag (MEDIUM)
        if re.search(r'image\s*:\s*["\'][^"\']+:latest["\']', code):
            result = self._find_line(lines, r'image.*:latest')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Container Image Using :latest Tag",
                description=(
                    f"Container image with :latest tag at line {line_num}. The :latest tag is mutable "
                    f"and can point to different images over time, making builds non-reproducible and "
                    f"introducing supply chain risk. Compromised images could be automatically pulled."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Pin container images to specific versions or digests:\n"
                    "image: 'myregistry.azurecr.io/app:v1.2.3'\n"
                    "Or use SHA256 digest:\n"
                    "image: 'myregistry.azurecr.io/app@sha256:abc123...'\n"
                    "Enable Azure Container Registry image scanning."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Public Docker Hub image without digest (MEDIUM)
        if re.search(r'image\s*:\s*["\'][^/]+/[^@"\']+["\']', code):
            has_digest = re.search(r'image\s*:\s*["\'][^"\']+@sha256:', code)
            if not has_digest:
                result = self._find_line(lines, r'image\s*:\s*["\'][^/]+/[^@"\']')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Container Image Without Digest Pinning",
                    description=(
                        f"Container image at line {line_num} without SHA256 digest. Tags can be "
                        f"overwritten, making builds non-reproducible. Use digest pinning to ensure "
                        f"exact image version and protect against supply chain attacks."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Pin to SHA256 digest:\n"
                        "image: 'nginx@sha256:abc123def456...'\\n\"\n"
                        "Or use Azure Container Registry with Content Trust enabled."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-TPR-03 compliance.
        
        Detects:
        - Container images from untrusted registries
        - Missing image digest/SHA pinning
        - Public container images without vulnerability scanning
        - Latest tag usage
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Container image with :latest tag (MEDIUM)
        if re.search(r'image\s*=\s*"[^"]+:latest"', code):
            result = self._find_line(lines, r'image.*:latest')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Container Image Using :latest Tag",
                description=(
                    f"Container image with :latest tag at line {line_num}. The :latest tag is mutable "
                    f"and can reference different images over time. This makes deployments non-reproducible "
                    f"and increases supply chain risk from compromised images."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num),
                remediation=(
                    "Pin container images to specific versions or digests:\n"
                    "image = \"myregistry.azurecr.io/app:v1.2.3\"\n"
                    "Or use SHA256 digest:\n"
                    "image = \"myregistry.azurecr.io/app@sha256:abc123...\"\n"
                    "Enable azurerm_container_registry with image scanning."
                ),
                ksi_id=self.KSI_ID
            ))
        
        # Pattern 2: Public Docker Hub image without digest (MEDIUM)
        if re.search(r'image\s*=\s*"[^/]+/[^@"]+"', code):
            has_digest = re.search(r'image\s*=\s*"[^"]+@sha256:', code)
            if not has_digest:
                result = self._find_line(lines, r'image\s*=\s*"[^/]+/[^@"]')

                line_num = result['line_num'] if result else 0
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Container Image Without Digest Pinning",
                    description=(
                        f"Container image at line {line_num} without SHA256 digest. Tags are mutable "
                        f"and can be overwritten. Use digest pinning to ensure exact image version "
                        f"and protect against supply chain tampering."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num),
                    remediation=(
                        "Pin to SHA256 digest:\n"
                        "image = \"nginx@sha256:abc123def456...\"\n"
                        "Or use Azure Container Registry with Content Trust:\n"
                        "azurerm_container_registry with trust_policy enabled."
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-TPR-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-TPR-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-TPR-03 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-TPR-03.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Supply Chain Risk Management",
            "evidence_type": "process-based",
            "automation_feasibility": "high",
            "azure_services": [
                "Microsoft Defender for Cloud",
                "Azure DevOps",
                "Microsoft Purview",
                "Azure Policy",
                "Microsoft Dataverse"
            ],
            "collection_methods": [
                "Microsoft Defender for Cloud supply chain security recommendations (vulnerable dependencies, container images, OSS risks)",
                "Azure DevOps Boards to track vendor assessments, SBOM generation, and supply chain risk remediation work items",
                "Microsoft Purview Data Map to inventory third-party data integrations and assess data sharing risks",
                "Azure Policy to enforce SBOM requirements and approved vendor lists for cloud resources",
                "Microsoft Dataverse to centralize vendor risk assessments, audit logs, and mitigation tracking"
            ],
            "implementation_steps": [
                "1. Enable Microsoft Defender for Cloud supply chain protection: (a) Activate Defender for Containers with vulnerability scanning, (b) Enable Defender for DevOps with dependency scanning (GitHub/Azure Repos), (c) Configure SBOM generation in build pipelines, (d) Set critical/high vulnerability blocking policies",
                "2. Create Azure DevOps Boards supply chain risk tracking: (a) Work item template 'Vendor Risk Assessment' with fields: Vendor name, Risk level, Assessment date, Approver, Mitigation plan, (b) Work item template 'Supply Chain Incident' for upstream vulnerabilities, (c) Automated creation from Defender alerts, (d) Link to remediation PRs and deployments",
                "3. Configure Microsoft Purview for third-party data lineage: (a) Scan data sources to identify third-party integrations (APIs, SaaS, data feeds), (b) Tag third-party data assets with vendor classification, (c) Track data sharing agreements and compliance requirements, (d) Generate monthly third-party data flow reports",
                "4. Deploy Azure Policy initiative 'Supply Chain Security Controls': (a) Require SBOM metadata tags on container images, (b) Audit resources deployed from unapproved registries, (c) Deny deployment of images with HIGH/CRITICAL vulnerabilities, (d) Require vendor approval tags on third-party resources",
                "5. Build Microsoft Dataverse Vendor Risk Table: (a) Columns: VendorID, VendorName, RiskLevel, AssessmentDate, Assessor, Findings, MitigationStatus, NextReviewDate, (b) Automate vendor review reminders via Power Automate, (c) Integrate with Defender alerts for real-time risk updates, (d) Track SBOM completeness and vulnerability remediation SLAs",
                "6. Generate quarterly evidence package: (a) Export Defender supply chain security findings with remediation status, (b) Export DevOps vendor assessment work items with completion proofs, (c) Export Purview third-party data lineage reports, (d) Export Dataverse vendor risk assessments with mitigation tracking"
            ],
            "evidence_artifacts": [
                "Microsoft Defender for Cloud Supply Chain Security Report showing vulnerable dependencies and container image risks",
                "Azure DevOps Vendor Risk Assessment Work Items with approval workflows and mitigation plans",
                "Microsoft Purview Third-Party Data Lineage Report identifying all external data integrations and sharing agreements",
                "Azure Policy Compliance Report for supply chain controls (SBOM requirements, approved vendor lists, vulnerability blocking)",
                "Microsoft Dataverse Vendor Risk Registry with assessment history, risk ratings, and continuous monitoring status"
            ],
            "update_frequency": "quarterly",
            "responsible_party": "Vendor Risk Management Team / Supply Chain Security Team"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "Microsoft Defender for Cloud REST API",
                "query_name": "Supply chain security findings (dependencies, container vulnerabilities)",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01&$filter=properties/displayName contains 'vulnerabilities' or properties/displayName contains 'supply chain'",
                "purpose": "Retrieve supply chain security findings including vulnerable dependencies and container image risks"
            },
            {
                "query_type": "Azure DevOps REST API",
                "query_name": "Vendor risk assessment work items",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/wit/wiql?api-version=7.0\nBody: {\"query\": \"SELECT [System.Id], [System.Title], [Custom.VendorName], [Custom.RiskLevel], [Custom.AssessmentDate], [Custom.MitigationStatus] FROM WorkItems WHERE [System.WorkItemType] = 'Vendor Risk Assessment' ORDER BY [Custom.AssessmentDate] DESC\"}",
                "purpose": "Retrieve vendor risk assessment work items with approval workflows and mitigation tracking"
            },
            {
                "query_type": "Microsoft Purview REST API",
                "query_name": "Third-party data integration inventory",
                "query": "POST https://{purview-account}.purview.azure.com/catalog/api/search/query?api-version=2022-03-01-preview\nBody: {\"keywords\": \"*\", \"filter\": {\"classifications\": [\"ThirdPartyData\"], \"entityType\": [\"azure_sql_table\", \"azure_storage_blob\", \"azure_data_lake\"]}}",
                "purpose": "Identify all third-party data integrations and assess data sharing risks using Purview Data Map"
            },
            {
                "query_type": "Azure Policy REST API",
                "query_name": "Supply chain security policy compliance",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01&$filter=policyDefinitionCategory eq 'Security' and (policyDefinitionName contains 'SBOM' or policyDefinitionName contains 'ContainerRegistry')",
                "purpose": "Retrieve policy compliance for supply chain security controls (SBOM, approved registries, vulnerability blocking)"
            },
            {
                "query_type": "Microsoft Dataverse Web API",
                "query_name": "Vendor risk registry with assessment history",
                "query": "GET https://{organization}.api.crm.dynamics.com/api/data/v9.2/vendor_risk_records?$select=vendorid,vendorname,risklevel,assessmentdate,mitigationstatus,nextreviewdate&$filter=assessmentdate ge {quarterStartDate}&$orderby=risklevel desc,assessmentdate desc",
                "purpose": "Retrieve vendor risk assessments with prioritized mitigation tracking for quarterly reporting"
            }
        ]

    def get_evidence_artifacts(self) -> List[Dict[str, str]]:
        """
        Get descriptions of evidence artifacts to collect.
        
        Returns:
            List of artifact dictionaries
        """
        return [
            {
                "artifact_name": "Defender Supply Chain Security Report",
                "artifact_type": "Security Assessment Export",
                "description": "Comprehensive report of supply chain vulnerabilities including dependencies, container images, and SBOM coverage",
                "collection_method": "Microsoft Defender for Cloud REST API to retrieve supply chain security assessments and remediation status",
                "storage_location": "Azure Storage Account with quarterly exports organized by severity (CRITICAL, HIGH, MEDIUM)"
            },
            {
                "artifact_name": "Azure DevOps Vendor Risk Assessment Work Items",
                "artifact_type": "Work Item Export",
                "description": "Complete set of vendor risk assessments with approval workflows, risk ratings, and mitigation plans",
                "collection_method": "Azure DevOps REST API to export vendor risk assessment work items with full history",
                "storage_location": "Azure DevOps database with 7-year retention for vendor assessment audit trail"
            },
            {
                "artifact_name": "Purview Third-Party Data Lineage Report",
                "artifact_type": "Data Governance Export",
                "description": "Data lineage report identifying all third-party integrations, data flows, and sharing agreements",
                "collection_method": "Microsoft Purview REST API to export data catalog with third-party classification and lineage",
                "storage_location": "Azure Storage Account with JSON exports showing external data dependencies"
            },
            {
                "artifact_name": "Azure Policy Supply Chain Compliance Report",
                "artifact_type": "Policy Compliance Export",
                "description": "Policy compliance status for supply chain security controls (SBOM requirements, approved vendors, vulnerability blocking)",
                "collection_method": "Azure Policy Insights API to export compliance for supply chain security initiative",
                "storage_location": "Azure Storage Account with monthly compliance snapshots and non-compliant resource lists"
            },
            {
                "artifact_name": "Dataverse Vendor Risk Registry",
                "artifact_type": "Vendor Assessment Database",
                "description": "Centralized vendor risk registry with assessment history, risk ratings, mitigation tracking, and review schedules",
                "collection_method": "Microsoft Dataverse Web API to export vendor_risk_records with quarterly assessments",
                "storage_location": "Microsoft Dataverse with automated backup to Azure Storage for audit retention"
            }
        ]
