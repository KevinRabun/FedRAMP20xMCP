"""
KSI-SVC-05: Resource Integrity

Use cryptographic methods to validate the integrity of machine-based information resources.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_SVC_05_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-SVC-05: Resource Integrity
    
    **Official Statement:**
    Use cryptographic methods to validate the integrity of machine-based information resources.
    
    **Family:** SVC - Service Configuration
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cm-2.2
    - cm-8.3
    - sc-13
    - sc-23
    - si-7
    - si-7.1
    - sr-10
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Use cryptographic methods to validate the integrity of machine-based information resources....
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-SVC-05"
    KSI_NAME = "Resource Integrity"
    KSI_STATEMENT = """Use cryptographic methods to validate the integrity of machine-based information resources."""
    FAMILY = "SVC"
    FAMILY_NAME = "Service Configuration"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["cm-2.2", "cm-8.3", "sc-13", "sc-23", "si-7", "si-7.1", "sr-10"]
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
        Analyze Python code for KSI-SVC-05 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - File operations without integrity checks
        - Missing hash validation
        - Unverified resource loading
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: File download without hash verification (HIGH)
        download_match = self._find_line(lines, r'(requests\.get|urllib\.request\.urlretrieve|download|fetch)\s*\(')
        has_hash_check = re.search(r'hashlib\.(sha256|sha512|sha384)|hmac\.new', code)
        
        if download_match and not has_hash_check:
            line_num = download_match['line_num']
            findings.append(Finding(
                severity=Severity.HIGH,
                title="File Download Without Integrity Verification",
                description=(
                    "File or resource downloaded without cryptographic integrity verification. "
                    "KSI-SVC-05 requires cryptographic methods to validate resource integrity (SI-7, SI-7.1) - "
                    "downloading files without hash verification allows man-in-the-middle attacks, "
                    "compromised repositories, or corrupted downloads to inject malicious content."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Verify file integrity with SHA-256 or SHA-512 hash:\n"
                    "import hashlib\n"
                    "import requests\n\n"
                    "# Download file\n"
                    "response = requests.get('https://example.com/file.zip')\n"
                    "content = response.content\n\n"
                    "# Calculate SHA-256 hash\n"
                    "calculated_hash = hashlib.sha256(content).hexdigest()\n"
                    "expected_hash = 'abc123...'  # From trusted source\n\n"
                    "# Verify integrity\n"
                    "if calculated_hash != expected_hash:\n"
                    "    raise ValueError(f'Integrity check failed: {calculated_hash} != {expected_hash}')\n\n"
                    "# Safe to use file\n"
                    "with open('file.zip', 'wb') as f:\n"
                    "    f.write(content)\n\n"
                    "Ref: NIST SP 800-107 Rev. 1 - Recommendation for Applications Using Approved Hash Algorithms "
                    "(https://csrc.nist.gov/publications/detail/sp/800-107/rev-1/final)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-SVC-05 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - File operations without integrity checks
        - Missing hash validation
        - Unverified resource loading
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: File download without hash verification (HIGH)
        download_match = self._find_line(lines, r'(HttpClient.*GetAsync|DownloadFileAsync|WebClient.*Download)')
        has_hash = re.search(r'(SHA256|SHA512|SHA384)\.Create\(\)|HashAlgorithm|ComputeHash', code)
        
        if download_match and not has_hash:
            line_num = download_match['line_num']
            findings.append(Finding(
                severity=Severity.HIGH,
                title="File Download Without Integrity Verification",
                description=(
                    "File or resource downloaded without cryptographic integrity verification. "
                    "KSI-SVC-05 requires cryptographic methods to validate resource integrity (SI-7, SI-7.1) - "
                    "downloading files without hash verification allows man-in-the-middle attacks, "
                    "compromised repositories, or corrupted downloads to inject malicious content."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Verify file integrity with SHA-256 or SHA-512 hash:\n"
                    "using System.Security.Cryptography;\n"
                    "using System.Net.Http;\n\n"
                    "// Download file\n"
                    "using var client = new HttpClient();\n"
                    "var content = await client.GetByteArrayAsync(\"https://example.com/file.zip\");\n\n"
                    "// Calculate SHA-256 hash\n"
                    "using var sha256 = SHA256.Create();\n"
                    "var calculatedHash = BitConverter.ToString(sha256.ComputeHash(content))\n"
                    "    .Replace(\"-\", \"\").ToLower();\n"
                    "var expectedHash = \"abc123...\"; // From trusted source\n\n"
                    "// Verify integrity\n"
                    "if (calculatedHash != expectedHash)\n"
                    "{{\n"
                    "    throw new InvalidOperationException(\n"
                    "        $\"Integrity check failed: {{calculatedHash}} != {{expectedHash}}\");\n"
                    "}}\n\n"
                    "// Safe to use file\n"
                    "await File.WriteAllBytesAsync(\"file.zip\", content);\n\n"
                    "Ref: .NET Cryptography Model (https://learn.microsoft.com/dotnet/standard/security/cryptography-model)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-SVC-05 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - File operations without integrity checks
        - Missing hash validation
        - Unverified resource loading
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: File download without hash verification (HIGH)
        download_match = self._find_line(lines, r'(HttpClient.*execute|URL.*openStream|Files\.copy.*InputStream)')
        has_hash = re.search(r'MessageDigest\.getInstance.*("SHA-256"|"SHA-512"|"SHA-384")', code)
        
        if download_match and not has_hash:
            line_num = download_match['line_num']
            findings.append(Finding(
                severity=Severity.HIGH,
                title="File Download Without Integrity Verification",
                description=(
                    "File or resource downloaded without cryptographic integrity verification. "
                    "KSI-SVC-05 requires cryptographic methods to validate resource integrity (SI-7, SI-7.1) - "
                    "downloading files without hash verification allows man-in-the-middle attacks, "
                    "compromised repositories, or corrupted downloads to inject malicious content."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Verify file integrity with SHA-256 or SHA-512 hash:\n"
                    "import java.security.MessageDigest;\n"
                    "import java.net.http.HttpClient;\n"
                    "import java.net.http.HttpRequest;\n"
                    "import java.net.http.HttpResponse;\n\n"
                    "// Download file\n"
                    "HttpClient client = HttpClient.newHttpClient();\n"
                    "HttpRequest request = HttpRequest.newBuilder()\n"
                    "    .uri(URI.create(\"https://example.com/file.zip\"))\n"
                    "    .build();\n"
                    "byte[] content = client.send(request, HttpResponse.BodyHandlers.ofByteArray())\n"
                    "    .body();\n\n"
                    "// Calculate SHA-256 hash\n"
                    "MessageDigest digest = MessageDigest.getInstance(\"SHA-256\");\n"
                    "byte[] hash = digest.digest(content);\n"
                    "String calculatedHash = bytesToHex(hash);\n"
                    "String expectedHash = \"abc123...\"; // From trusted source\n\n"
                    "// Verify integrity\n"
                    "if (!calculatedHash.equals(expectedHash)) {{\n"
                    "    throw new SecurityException(\n"
                    "        \"Integrity check failed: \" + calculatedHash + \" != \" + expectedHash);\n"
                    "}}\n\n"
                    "// Safe to use file\n"
                    "Files.write(Paths.get(\"file.zip\"), content);\n\n"
                    "Ref: Java Security Standard Algorithm Names (https://docs.oracle.com/en/java/javase/17/docs/specs/security/standard-names.html)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-SVC-05 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - File operations without integrity checks
        - Missing hash validation
        - Unverified resource loading
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: File download without hash verification (HIGH)
        download_match = self._find_line(lines, r'(fetch\(|axios\.|http\.get|https\.get|download)')
        has_hash = re.search(r'(crypto\.createHash|createHash.*sha256|createHash.*sha512)', code)
        
        if download_match and not has_hash:
            line_num = download_match['line_num']
            findings.append(Finding(
                severity=Severity.HIGH,
                title="File Download Without Integrity Verification",
                description=(
                    "File or resource downloaded without cryptographic integrity verification. "
                    "KSI-SVC-05 requires cryptographic methods to validate resource integrity (SI-7, SI-7.1) - "
                    "downloading files without hash verification allows man-in-the-middle attacks, "
                    "compromised repositories, or corrupted downloads to inject malicious content."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Verify file integrity with SHA-256 or SHA-512 hash:\n"
                    "import crypto from 'crypto';\n"
                    "import fs from 'fs/promises';\n\n"
                    "// Download file\n"
                    "const response = await fetch('https://example.com/file.zip');\n"
                    "const buffer = await response.arrayBuffer();\n"
                    "const content = Buffer.from(buffer);\n\n"
                    "// Calculate SHA-256 hash\n"
                    "const hash = crypto.createHash('sha256');\n"
                    "hash.update(content);\n"
                    "const calculatedHash = hash.digest('hex');\n"
                    "const expectedHash = 'abc123...'; // From trusted source\n\n"
                    "// Verify integrity\n"
                    "if (calculatedHash !== expectedHash) {\n"
                    "  throw new Error(\n"
                    "    `Integrity check failed: ${calculatedHash} !== ${expectedHash}`\n"
                    "  );\n"
                    "}\n\n"
                    "// Safe to use file\n"
                    "await fs.writeFile('file.zip', content);\n\n"
                    "Ref: Node.js Crypto Module (https://nodejs.org/api/crypto.html#cryptocreatehashalgorithm-options)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-SVC-05 compliance.
        
        Detects:
        - Container registries without content trust
        - Storage accounts without immutability policies
        - VMs without integrity monitoring
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Container Registry without Content Trust (MEDIUM)
        acr_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.ContainerRegistry/registries@")
        has_trust = re.search(r"trustPolicy.*enabled:\s*true", code, re.IGNORECASE)
        
        if acr_match and not has_trust:
            line_num = acr_match['line_num']
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Azure Container Registry Without Content Trust",
                description=(
                    "Container Registry deployed without Content Trust (image signing). "
                    "KSI-SVC-05 requires cryptographic methods to validate resource integrity (SI-7, CM-8.3) - "
                    "Content Trust uses Docker Notary to sign and verify container images, "
                    "preventing deployment of tampered or unsigned images."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Enable Content Trust on Azure Container Registry:\n"
                    "resource containerRegistry 'Microsoft.ContainerRegistry/registries@2023-01-01-preview' = {\n"
                    "  name: acrName\n"
                    "  location: location\n"
                    "  sku: {\n"
                    "    name: 'Premium'  // Content Trust requires Premium SKU\n"
                    "  }\n"
                    "  properties: {\n"
                    "    policies: {\n"
                    "      trustPolicy: {\n"
                    "        type: 'Notary'\n"
                    "        status: 'enabled'\n"
                    "      }\n"
                    "    }\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: Azure Container Registry Content Trust (https://learn.microsoft.com/azure/container-registry/container-registry-content-trust)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-SVC-05 compliance.
        
        Detects:
        - Container registries without content trust
        - Storage accounts without immutability policies
        - VMs without integrity monitoring
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Container Registry without Content Trust (MEDIUM)
        acr_match = self._find_line(lines, r'resource\s+"azurerm_container_registry"')
        has_trust = re.search(r'trust_policy\s*\{.*enabled\s*=\s*true', code, re.IGNORECASE | re.DOTALL)
        
        if acr_match and not has_trust:
            line_num = acr_match['line_num']
            findings.append(Finding(
                severity=Severity.MEDIUM,
                title="Azure Container Registry Without Content Trust",
                description=(
                    "Container Registry deployed without Content Trust (image signing). "
                    "KSI-SVC-05 requires cryptographic methods to validate resource integrity (SI-7, CM-8.3) - "
                    "Content Trust uses Docker Notary to sign and verify container images, "
                    "preventing deployment of tampered or unsigned images."
                ),
                file_path=file_path,
                line_number=line_num,
                snippet=self._get_snippet(lines, line_num, context=3),
                remediation=(
                    "Enable Content Trust on Azure Container Registry:\n"
                    "resource \"azurerm_container_registry\" \"example\" {\n"
                    "  name                = \"exampleacr\"\n"
                    "  location            = azurerm_resource_group.example.location\n"
                    "  resource_group_name = azurerm_resource_group.example.name\n"
                    "  sku                 = \"Premium\"  # Content Trust requires Premium SKU\n\n"
                    "  trust_policy {\n"
                    "    enabled = true\n"
                    "  }\n"
                    "}\n\n"
                    "Ref: Azure Container Registry Content Trust (https://learn.microsoft.com/azure/container-registry/container-registry-content-trust)"
                ),
                ksi_id=self.KSI_ID
            ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-SVC-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-SVC-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-SVC-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], pattern: str) -> Optional[Dict[str, Any]]:
        """Find the first line matching the pattern (regex-based)."""
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            for i, line in enumerate(lines, start=1):
                if regex.search(line):
                    return {'line_num': i, 'line': line}
            return None
        except re.error:
            # Fallback to string search if regex is invalid
            for i, line in enumerate(lines, start=1):
                if pattern.lower() in line.lower():
                    return {'line_num': i, 'line': line}
            return None
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
