"""
KSI-SVC-08: Shared Resources

Do not introduce or leave behind residual elements that could negatively affect confidentiality, integrity, or availability of federal customer data during operations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_SVC_08_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-SVC-08: Shared Resources
    
    **Official Statement:**
    Do not introduce or leave behind residual elements that could negatively affect confidentiality, integrity, or availability of federal customer data during operations.
    
    **Family:** SVC - Service Configuration
    
    **Impact Levels:**
    - Low: No
    - Moderate: Yes
    
    **NIST Controls:**
    - sc-4
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-SVC-08"
    KSI_NAME = "Shared Resources"
    KSI_STATEMENT = """Do not introduce or leave behind residual elements that could negatively affect confidentiality, integrity, or availability of federal customer data during operations."""
    FAMILY = "SVC"
    FAMILY_NAME = "Service Configuration"
    IMPACT_LOW = False
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["sc-4"]
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
        Analyze Python code for KSI-SVC-08 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Temporary files without secure deletion
        - In-memory data without explicit clearing
        - Shared resources without proper cleanup
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Temporary file creation without secure deletion (HIGH)
        tempfile_match = self._find_line(lines, r'tempfile\.(NamedTemporaryFile|mkstemp|mkdtemp)')
        
        if tempfile_match:
            line_num = tempfile_match['line_num']
            # Check if delete=False or manual cleanup without secure deletion
            has_delete_false = any('delete=False' in line for line in lines[line_num:min(line_num+5, len(lines))])
            has_secure_delete = any('os.unlink' in line or 'shutil.rmtree' in line 
                                   for line in lines[line_num:min(line_num+30, len(lines))])
            
            if has_delete_false and not has_secure_delete:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Temporary File Without Secure Deletion",
                    description=(
                        "Temporary file created with delete=False but no secure deletion mechanism. "
                        "KSI-SVC-08 requires not introducing residual elements that could affect confidentiality (SC-4) - "
                        "temporary files may contain sensitive data that persists on disk after process termination."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Ensure secure deletion of temporary files:\n"
                        "# Option 1: Use auto-deletion (recommended)\n"
                        "import tempfile\n\n"
                        "with tempfile.NamedTemporaryFile(mode='w', delete=True) as tmp:\n"
                        "    tmp.write(sensitive_data)\n"
                        "    tmp.flush()\n"
                        "    # File automatically deleted on close\n\n"
                        "# Option 2: Manual secure deletion with overwrite\n"
                        "import os\n"
                        "import tempfile\n\n"
                        "tmp = tempfile.NamedTemporaryFile(mode='w', delete=False)\n"
                        "try:\n"
                        "    tmp.write(sensitive_data)\n"
                        "    tmp.flush()\n"
                        "    # ... use file ...\n"
                        "finally:\n"
                        "    tmp.close()\n"
                        "    # Overwrite with zeros before deletion\n"
                        "    with open(tmp.name, 'wb') as f:\n"
                        "        f.write(b'\\x00' * os.path.getsize(tmp.name))\n"
                        "    os.unlink(tmp.name)\n\n"
                        "Ref: Python tempfile Module (https://docs.python.org/3/library/tempfile.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Sensitive data in-memory without explicit clearing (MEDIUM)
        password_var_match = self._find_line(lines, r'(password|secret|token|api_key)\s*=\s*["\']')
        
        if password_var_match:
            line_num = password_var_match['line_num']
            # Check if variable is explicitly cleared later
            var_name_match = re.search(r'(\w+)\s*=', lines[line_num - 1])
            if var_name_match:
                var_name = var_name_match.group(1)
                has_clear = any(f'{var_name} = None' in line or f'del {var_name}' in line 
                               for line in lines[line_num:min(line_num+50, len(lines))])
                
                if not has_clear:
                    findings.append(Finding(
                        severity=Severity.MEDIUM,
                        title="Sensitive Data Not Explicitly Cleared From Memory",
                        description=(
                            f"Sensitive variable '{var_name}' assigned but never explicitly cleared. "
                            "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                            "sensitive data in memory may persist in Python's heap, core dumps, or swap space."
                        ),
                        file_path=file_path,
                        line_number=line_num,
                        snippet=self._get_snippet(lines, line_num, context=3),
                        remediation=(
                            "Explicitly clear sensitive data from memory:\n"
                            "import ctypes\n\n"
                            "# Store sensitive data\n"
                            f"{var_name} = 'sensitive_value'\n\n"
                            "try:\n"
                            "    # Use the sensitive data\n"
                            "    process_data(password)\n"
                            "finally:\n"
                            "    # Clear from memory\n"
                            f"    if {var_name} is not None:\n"
                            f"        # Overwrite memory before deletion\n"
                            f"        ctypes.memset(id({var_name}), 0, len({var_name}))\n"
                            f"        {var_name} = None\n\n"
                            "# Or use secure string handling library\n"
                            "from cryptography.fernet import Fernet\n"
                            "# Store encrypted in memory, decrypt only when needed\n\n"
                            "Ref: Python Memory Management (https://docs.python.org/3/c-api/memory.html)"
                        ),
                        ksi_id=self.KSI_ID
                    ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-SVC-08 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - IDisposable resources not properly disposed
        - SecureString not cleared
        - Sensitive data in memory without zeroing
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: IDisposable resource without using statement (HIGH)
        stream_match = self._find_line(lines, r'new\s+(FileStream|MemoryStream|StreamWriter|StreamReader)')
        
        if stream_match:
            line_num = stream_match['line_num']
            # Check if used within using statement or explicit Dispose()
            has_using = any('using' in line for line in lines[max(0, line_num-3):line_num+1])
            has_dispose = any('.Dispose()' in line for line in lines[line_num:min(line_num+20, len(lines))])
            
            if not has_using and not has_dispose:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Disposable Resource Not Properly Disposed",
                    description=(
                        "IDisposable resource created without using statement or explicit Dispose() call. "
                        "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                        "undisposed streams may leave sensitive data in memory or locked file handles."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Use using statement for automatic disposal:\n"
                        "// Option 1: using statement (C# 8.0+)\n"
                        "using var stream = new FileStream(\"file.txt\", FileMode.Open);\n"
                        "// Stream automatically disposed at end of scope\n\n"
                        "// Option 2: using block\n"
                        "using (var stream = new FileStream(\"file.txt\", FileMode.Open))\n"
                        "{\n"
                        "    // Use stream\n"
                        "} // Automatically disposed here\n\n"
                        "// Option 3: Manual disposal with try-finally\n"
                        "FileStream stream = null;\n"
                        "try\n"
                        "{\n"
                        "    stream = new FileStream(\"file.txt\", FileMode.Open);\n"
                        "    // Use stream\n"
                        "}\n"
                        "finally\n"
                        "{\n"
                        "    stream?.Dispose();\n"
                        "}\n\n"
                        "Ref: IDisposable Pattern (https://learn.microsoft.com/dotnet/standard/garbage-collection/implementing-dispose)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: SecureString not disposed (MEDIUM)
        securestring_match = self._find_line(lines, r'new\s+SecureString\(\)')
        
        if securestring_match:
            line_num = securestring_match['line_num']
            has_dispose = any('Dispose()' in line for line in lines[line_num:min(line_num+20, len(lines))])
            
            if not has_dispose:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="SecureString Not Disposed",
                    description=(
                        "SecureString created but never disposed. "
                        "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                        "undisposed SecureString may leave encrypted sensitive data in memory."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Dispose SecureString after use:\n"
                        "using System.Security;\n\n"
                        "using (var securePassword = new SecureString())\n"
                        "{\n"
                        "    // Append characters\n"
                        "    foreach (char c in password)\n"
                        "    {\n"
                        "        securePassword.AppendChar(c);\n"
                        "    }\n"
                        "    securePassword.MakeReadOnly();\n"
                        "    \n"
                        "    // Use securePassword\n"
                        "    ProcessSecureString(securePassword);\n"
                        "} // Automatically disposed and memory cleared\n\n"
                        "Ref: SecureString Class (https://learn.microsoft.com/dotnet/api/system.security.securestring)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-SVC-08 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - AutoCloseable resources not used in try-with-resources
        - Sensitive data arrays not zeroed
        - Missing resource cleanup
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: FileInputStream/FileOutputStream without try-with-resources (HIGH)
        stream_match = self._find_line(lines, r'new\s+(FileInputStream|FileOutputStream|BufferedReader|BufferedWriter)')
        
        if stream_match:
            line_num = stream_match['line_num']
            # Check if used within try-with-resources
            has_try_resources = any('try (' in line for line in lines[max(0, line_num-3):line_num+1])
            has_finally_close = any('close()' in line for line in lines[line_num:min(line_num+30, len(lines))])
            
            if not has_try_resources and not has_finally_close:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="AutoCloseable Resource Not Properly Closed",
                    description=(
                        "AutoCloseable resource created without try-with-resources or explicit close(). "
                        "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                        "unclosed streams may leave sensitive data in buffers or locked file handles."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Use try-with-resources for automatic cleanup:\n"
                        "// Option 1: try-with-resources (Java 7+)\n"
                        "try (FileInputStream fis = new FileInputStream(\"file.txt\")) {\n"
                        "    // Use stream\n"
                        "} // Automatically closed\n\n"
                        "// Option 2: Multiple resources\n"
                        "try (FileInputStream fis = new FileInputStream(\"input.txt\");\n"
                        "     FileOutputStream fos = new FileOutputStream(\"output.txt\")) {\n"
                        "    // Use both streams\n"
                        "} // Both automatically closed\n\n"
                        "// Option 3: Manual cleanup\n"
                        "FileInputStream fis = null;\n"
                        "try {\n"
                        "    fis = new FileInputStream(\"file.txt\");\n"
                        "    // Use stream\n"
                        "} finally {\n"
                        "    if (fis != null) {\n"
                        "        fis.close();\n"
                        "    }\n"
                        "}\n\n"
                        "Ref: try-with-resources (https://docs.oracle.com/javase/tutorial/essential/exceptions/tryResourceClose.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: char[] or byte[] for password without zeroing (MEDIUM)
        password_array_match = self._find_line(lines, r'(char\[\]|byte\[\])\s+\w*(password|secret|token)')
        
        if password_array_match:
            line_num = password_array_match['line_num']
            # Check if Arrays.fill() is called to zero the array
            has_array_fill = any('Arrays.fill(' in line for line in lines[line_num:min(line_num+30, len(lines))])
            
            if not has_array_fill:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Sensitive Array Not Zeroed After Use",
                    description=(
                        "Sensitive data stored in char[] or byte[] array but not zeroed after use. "
                        "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                        "sensitive data in arrays may persist in memory or heap dumps."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Zero sensitive arrays after use:\n"
                        "import java.util.Arrays;\n\n"
                        "char[] password = getPassword();\n"
                        "try {\n"
                        "    // Use password\n"
                        "    authenticate(password);\n"
                        "} finally {\n"
                        "    // Zero the array\n"
                        "    Arrays.fill(password, (char) 0);\n"
                        "}\n\n"
                        "// For byte arrays:\n"
                        "byte[] sensitiveData = getSensitiveData();\n"
                        "try {\n"
                        "    // Use data\n"
                        "    process(sensitiveData);\n"
                        "} finally {\n"
                        "    // Zero the array\n"
                        "    Arrays.fill(sensitiveData, (byte) 0);\n"
                        "}\n\n"
                        "Note: Prefer char[] over String for passwords - Strings are immutable\n"
                        "and cannot be cleared, remaining in memory until garbage collected.\n\n"
                        "Ref: Arrays.fill() (https://docs.oracle.com/javase/8/docs/api/java/util/Arrays.html#fill-char:A-char-)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-SVC-08 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - File descriptors not closed
        - Buffers with sensitive data not cleared
        - Event listeners not removed
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: fs.openSync without fs.closeSync (HIGH)
        open_sync_match = self._find_line(lines, r'fs\.openSync\(')
        
        if open_sync_match:
            line_num = open_sync_match['line_num']
            # Check if fs.closeSync is called
            has_close = any('fs.closeSync' in line for line in lines[line_num:min(line_num+30, len(lines))])
            
            if not has_close:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="File Descriptor Not Closed",
                    description=(
                        "File opened with fs.openSync() but never closed with fs.closeSync(). "
                        "KSI-SVC-08 requires not leaving residual elements that could affect availability (SC-4) - "
                        "unclosed file descriptors cause resource exhaustion and may lock files."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Close file descriptors explicitly:\n"
                        "import * as fs from 'fs';\n\n"
                        "// Option 1: Use try-finally\n"
                        "let fd: number | undefined;\n"
                        "try {\n"
                        "  fd = fs.openSync('file.txt', 'r');\n"
                        "  // Use file descriptor\n"
                        "  const buffer = Buffer.alloc(1024);\n"
                        "  fs.readSync(fd, buffer, 0, 1024, 0);\n"
                        "} finally {\n"
                        "  if (fd !== undefined) {\n"
                        "    fs.closeSync(fd);\n"
                        "  }\n"
                        "}\n\n"
                        "// Option 2: Use higher-level APIs (recommended)\n"
                        "const data = fs.readFileSync('file.txt', 'utf8');\n"
                        "// File automatically closed\n\n"
                        "Ref: Node.js fs Module (https://nodejs.org/api/fs.html)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Buffer with sensitive data not cleared (MEDIUM)
        buffer_alloc_match = self._find_line(lines, r'Buffer\.(alloc|from)\(')
        
        if buffer_alloc_match:
            line_num = buffer_alloc_match['line_num']
            # Check if buffer.fill(0) is called
            has_fill = any('fill(0)' in line or 'fill(\'\\x00\')' in line 
                          for line in lines[line_num:min(line_num+30, len(lines))])
            
            # Only flag if variable name suggests sensitive data
            line_text = lines[line_num - 1]
            is_sensitive = re.search(r'(password|secret|token|key)', line_text, re.IGNORECASE)
            
            if is_sensitive and not has_fill:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Sensitive Buffer Not Cleared After Use",
                    description=(
                        "Buffer containing sensitive data not explicitly zeroed after use. "
                        "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                        "sensitive data in buffers may persist in memory or core dumps."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Clear sensitive buffers after use:\n"
                        "const passwordBuffer = Buffer.from(password, 'utf8');\n"
                        "try {\n"
                        "  // Use buffer\n"
                        "  await encryptData(passwordBuffer);\n"
                        "} finally {\n"
                        "  // Zero the buffer\n"
                        "  passwordBuffer.fill(0);\n"
                        "}\n\n"
                        "// For Buffer.alloc:\n"
                        "const keyBuffer = Buffer.alloc(32);\n"
                        "try {\n"
                        "  // Fill with sensitive data\n"
                        "  generateKey(keyBuffer);\n"
                        "  // Use buffer\n"
                        "} finally {\n"
                        "  // Zero the buffer\n"
                        "  keyBuffer.fill(0);\n"
                        "}\n\n"
                        "Ref: Node.js Buffer (https://nodejs.org/api/buffer.html#buffer_buf_fill_value_offset_end_encoding)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-SVC-08 compliance.
        
        Detects:
        - Storage without soft delete
        - VMs without ephemeral OS disk
        - Resources without proper deletion policies
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Storage Account without blob soft delete (MEDIUM)
        storage_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Storage/storageAccounts@")
        
        if storage_match:
            line_num = storage_match['line_num']
            # Check if deleteRetentionPolicy is configured
            has_soft_delete = any('deleteRetentionPolicy' in line 
                                 for line in lines[line_num:min(line_num+50, len(lines))])
            
            if not has_soft_delete:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Storage Account Without Blob Soft Delete",
                    description=(
                        "Storage Account without blob soft delete retention policy. "
                        "KSI-SVC-08 requires not introducing residual elements that negatively affect confidentiality (SC-4) - "
                        "without soft delete, accidentally deleted blobs containing customer data cannot be recovered "
                        "and may be immediately overwritten, risking data exposure."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure blob soft delete for data protection:\n"
                        "resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
                        "  name: storageAccountName\n"
                        "  location: location\n"
                        "  sku: {\n"
                        "    name: 'Standard_LRS'\n"
                        "  }\n"
                        "  kind: 'StorageV2'\n"
                        "  properties: {\n"
                        "    // ... other properties\n"
                        "  }\n"
                        "}\n\n"
                        "// Blob services with soft delete\n"
                        "resource blobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {\n"
                        "  parent: storageAccount\n"
                        "  name: 'default'\n"
                        "  properties: {\n"
                        "    deleteRetentionPolicy: {\n"
                        "      enabled: true\n"
                        "      days: 7  // Retain deleted blobs for 7 days\n"
                        "    }\n"
                        "    containerDeleteRetentionPolicy: {\n"
                        "      enabled: true\n"
                        "      days: 7\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure Blob Soft Delete (https://learn.microsoft.com/azure/storage/blobs/soft-delete-blob-overview)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: VM without ephemeral OS disk (LOW)
        vm_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Compute/virtualMachines@")
        
        if vm_match:
            line_num = vm_match['line_num']
            has_ephemeral = any('diffDiskSettings' in line 
                               for line in lines[line_num:min(line_num+50, len(lines))])
            
            if not has_ephemeral:
                findings.append(Finding(
                    severity=Severity.LOW,
                    title="VM Without Ephemeral OS Disk",
                    description=(
                        "Virtual Machine without ephemeral OS disk configuration. "
                        "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                        "persistent OS disks may retain sensitive data after VM deletion. "
                        "Consider ephemeral OS disks for stateless workloads to ensure no data residue."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure ephemeral OS disk for stateless VMs:\n"
                        "resource vm 'Microsoft.Compute/virtualMachines@2023-03-01' = {\n"
                        "  name: vmName\n"
                        "  location: location\n"
                        "  properties: {\n"
                        "    storageProfile: {\n"
                        "      osDisk: {\n"
                        "        createOption: 'FromImage'\n"
                        "        caching: 'ReadOnly'\n"
                        "        diffDiskSettings: {\n"
                        "          option: 'Local'  // Ephemeral disk\n"
                        "          placement: 'CacheDisk'  // or 'ResourceDisk'\n"
                        "        }\n"
                        "      }\n"
                        "    }\n"
                        "    // ... other properties\n"
                        "  }\n"
                        "}\n\n"
                        "Note: Only suitable for stateless workloads. Data is lost on VM stop/restart.\n\n"
                        "Ref: Azure Ephemeral OS Disks (https://learn.microsoft.com/azure/virtual-machines/ephemeral-os-disks)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-SVC-08 compliance.
        
        Detects:
        - Storage without blob retention
        - Compute instances without ephemeral storage
        - Resources without proper lifecycle policies
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: azurerm_storage_account without blob retention (MEDIUM)
        storage_match = self._find_line(lines, r'resource\s+"azurerm_storage_account"')
        
        if storage_match:
            line_num = storage_match['line_num']
            # Check if blob_properties with delete_retention_policy exists
            has_retention = any('delete_retention_policy' in line 
                               for line in lines[line_num:min(line_num+50, len(lines))])
            
            if not has_retention:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Storage Account Without Blob Retention Policy",
                    description=(
                        "azurerm_storage_account without blob delete_retention_policy. "
                        "KSI-SVC-08 requires not introducing residual elements that negatively affect confidentiality (SC-4) - "
                        "without retention policy, deleted blobs containing customer data cannot be recovered "
                        "and may be immediately overwritten, risking data exposure."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure blob soft delete retention:\n"
                        'resource "azurerm_storage_account" "example" {\n'
                        '  name                     = "examplestorageacct"\n'
                        '  resource_group_name      = azurerm_resource_group.example.name\n'
                        '  location                 = azurerm_resource_group.example.location\n'
                        '  account_tier             = "Standard"\n'
                        '  account_replication_type = "GRS"\n\n'
                        '  blob_properties {\n'
                        '    delete_retention_policy {\n'
                        '      days = 7  # Retain deleted blobs for 7 days\n'
                        '    }\n'
                        '    container_delete_retention_policy {\n'
                        '      days = 7\n'
                        '    }\n'
                        '  }\n'
                        '}\n\n'
                        "Ref: azurerm_storage_account blob_properties (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#blob_properties)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: azurerm_linux_virtual_machine without ephemeral OS disk (LOW)
        vm_match = self._find_line(lines, r'resource\s+"azurerm_(linux|windows)_virtual_machine"')
        
        if vm_match:
            line_num = vm_match['line_num']
            # Check if os_disk has diff_disk_settings
            has_ephemeral = any('diff_disk_settings' in line 
                               for line in lines[line_num:min(line_num+50, len(lines))])
            
            if not has_ephemeral:
                findings.append(Finding(
                    severity=Severity.LOW,
                    title="VM Without Ephemeral OS Disk",
                    description=(
                        "Virtual Machine without ephemeral OS disk (diff_disk_settings). "
                        "KSI-SVC-08 requires not leaving residual elements that could affect confidentiality (SC-4) - "
                        "persistent OS disks may retain sensitive data after VM deletion. "
                        "Consider ephemeral OS disks for stateless workloads to ensure no data residue."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Configure ephemeral OS disk for stateless VMs:\n"
                        'resource "azurerm_linux_virtual_machine" "example" {\n'
                        '  name                = "example-vm"\n'
                        '  resource_group_name = azurerm_resource_group.example.name\n'
                        '  location            = azurerm_resource_group.example.location\n'
                        '  size                = "Standard_DS1_v2"\n\n'
                        '  os_disk {\n'
                        '    caching              = "ReadOnly"\n'
                        '    storage_account_type = "Standard_LRS"\n'
                        '    diff_disk_settings {\n'
                        '      option    = "Local"  # Ephemeral disk\n'
                        '      placement = "CacheDisk"  # or "ResourceDisk"\n'
                        '    }\n'
                        '  }\n\n'
                        '  # ... other configuration\n'
                        '}\n\n'
                        "Note: Only suitable for stateless workloads. Data is lost on VM stop/restart.\n\n"
                        "Ref: azurerm_linux_virtual_machine os_disk (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine#os_disk)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-SVC-08 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-SVC-08 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-SVC-08 compliance.
        
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
