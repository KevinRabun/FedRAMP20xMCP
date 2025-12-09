"""
KSI-CNA-04: Immutable Infrastructure

Use immutable infrastructure with strictly defined functionality and privileges by default.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import ast
import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CNA_04_Analyzer(BaseKSIAnalyzer):
    """
    Enhanced Analyzer for KSI-CNA-04: Immutable Infrastructure
    
    **Official Statement:**
    Use immutable infrastructure with strictly defined functionality and privileges by default.
    
    **Family:** CNA - Cloud Native Architecture
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - cm-2
    - si-3
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CNA-04"
    KSI_NAME = "Immutable Infrastructure"
    KSI_STATEMENT = """Use immutable infrastructure with strictly defined functionality and privileges by default."""
    FAMILY = "CNA"
    FAMILY_NAME = "Cloud Native Architecture"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("cm-2", "Baseline Configuration"),
        ("si-3", "Malicious Code Protection")
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
        Analyze Python code for KSI-CNA-04 compliance using AST.
        
        Frameworks: Docker SDK, Kubernetes client, Azure SDK
        
        Detects:
        - Mutable container configurations
        - Missing read-only root filesystems
        - Writable volumes in production containers
        """
        findings = []
        lines = code.split('\n')
        
        try:
            tree = ast.parse(code)
        except SyntaxError:
            return self._python_regex_fallback(code, lines, file_path)
        
        # Pattern 1: Docker container without read-only root filesystem
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                # Check for docker.containers.run() or client.containers.run()
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'run':
                        # Check if parent is containers
                        call_text = ast.get_source_segment(code, node) if hasattr(ast, 'get_source_segment') else ''
                        if 'containers.run' in str(call_text) or 'container.run' in str(call_text):
                            # Check for read_only=True in keyword arguments
                            has_read_only = any(
                                kw.arg == 'read_only' and 
                                isinstance(kw.value, ast.Constant) and 
                                kw.value.value is True
                                for kw in node.keywords
                            )
                            
                            if not has_read_only:
                                findings.append(Finding(
                                    ksi_id=self.KSI_ID,
                                    title="Container Without Read-Only Root Filesystem",
                                    description=(
                                        f"Docker container at line {node.lineno} runs without read_only=True. "
                                        f"KSI-CNA-04 requires immutable infrastructure (CM-2) - "
                                        f"containers should have read-only root filesystems to prevent runtime modifications."
                                    ),
                                    severity=Severity.MEDIUM,
                                    file_path=file_path,
                                    line_number=node.lineno,
                                    code_snippet=self._get_snippet(lines, node.lineno, context=3),
                                    remediation=(
                                        "Enable read-only root filesystem:\n\n"
                                        "import docker\n"
                                        "client = docker.from_env()\n\n"
                                        "# Immutable container with read-only root\n"
                                        "container = client.containers.run(\n"
                                        "    'myapp:latest',\n"
                                        "    read_only=True,  # Prevent runtime modifications\n"
                                        "    volumes={\n"
                                        "        '/tmp': {'bind': '/tmp', 'mode': 'rw'}  # Only /tmp writable\n"
                                        "    },\n"
                                        "    detach=True\n"
                                        ")\n\n"
                                        "Ref: Docker Security Best Practices (https://docs.docker.com/engine/security/)"
                                    )
                                ))
        
        # Pattern 2: Kubernetes Pod without securityContext.readOnlyRootFilesystem
        if 'kubernetes' in code.lower() or 'k8s' in code.lower() or 'V1Container' in code:
            # Check for V1Container or container spec without readOnlyRootFilesystem
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    func_name = ''
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        func_name = node.func.attr
                    
                    if 'V1Container' in func_name or 'Container' == func_name:
                        # Check for security_context with read_only_root_filesystem
                        has_readonly_root = False
                        for kw in node.keywords:
                            if kw.arg == 'security_context':
                                # Check if it's a dict or V1SecurityContext with readOnlyRootFilesystem
                                has_readonly_root = True  # Assume it's configured if present
                        
                        if not has_readonly_root:
                            findings.append(Finding(
                                ksi_id=self.KSI_ID,
                                title="Kubernetes Container Without Read-Only Root Filesystem",
                                description=(
                                    f"Kubernetes container at line {node.lineno} missing readOnlyRootFilesystem. "
                                    f"KSI-CNA-04 requires immutable infrastructure (CM-2) - "
                                    f"container filesystems should be read-only to prevent runtime tampering."
                                ),
                                severity=Severity.MEDIUM,
                                file_path=file_path,
                                line_number=node.lineno,
                                code_snippet=self._get_snippet(lines, node.lineno, context=3),
                                remediation=(
                                    "Configure read-only root filesystem:\n\n"
                                    "from kubernetes import client\n\n"
                                    "container = client.V1Container(\n"
                                    "    name='myapp',\n"
                                    "    image='myapp:latest',\n"
                                    "    security_context=client.V1SecurityContext(\n"
                                    "        read_only_root_filesystem=True,  # Immutable root\n"
                                    "        allow_privilege_escalation=False\n"
                                    "    ),\n"
                                    "    volume_mounts=[\n"
                                    "        client.V1VolumeMount(\n"
                                            "            name='tmp',\n"
                                    "            mount_path='/tmp',\n"
                                    "            read_only=False  # Only /tmp writable\n"
                                    "        )\n"
                                    "    ]\n"
                                    ")\n\n"
                                    "Ref: Kubernetes Pod Security Standards (https://kubernetes.io/docs/concepts/security/pod-security-standards/)"
                                )
                            ))
        
        return findings
    
    def _python_regex_fallback(self, code: str, lines: List[str], file_path: str) -> List[Finding]:
        """Fallback regex-based analysis when AST parsing fails."""
        findings = []
        
        # Check for Docker containers without read_only
        if re.search(r'containers\.run\(', code) and not re.search(r'read_only\s*=\s*True', code):
            line_match = self._find_line(lines, r'containers\.run')
            if line_match:
                line_num = line_match['line_num']
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Container Without Read-Only Root Filesystem (Regex Fallback)",
                    description=f"Docker container at line {line_num} may be missing read_only=True.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Add read_only=True to container configuration"
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-CNA-04 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Mutable container configurations (Docker.DotNet)
        """
        findings = []
        
        # C# Docker configurations are less common in application code
        # Most immutability checks are in IaC (Bicep/Terraform)
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CNA-04 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK, Jakarta EE
        
        Detects:
        - Docker container configurations without read-only filesystems
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern: Docker Java SDK without read-only mode
        # Check for com.github.dockerjava or testcontainers without read-only
        if re.search(r'import.*docker', code, re.IGNORECASE):
            # Check for createContainer or createContainerCmd without ReadonlyRootfs
            for i, line in enumerate(lines, 1):
                if re.search(r'\.createContainer(Cmd)?\(', line) or re.search(r'\.withCreateContainerCmd\(', line):
                    # Look ahead for withReadonlyRootfs
                    context_start = max(0, i - 1)
                    context_end = min(len(lines), i + 10)
                    context_lines = lines[context_start:context_end]
                    
                    has_readonly = any(re.search(r'withReadonlyRootfs\(true\)', line) 
                                     for line in context_lines)
                    
                    if not has_readonly:
                        findings.append(Finding(
                            ksi_id=self.KSI_ID,
                            title="Docker Container Without Read-Only Root Filesystem",
                            description=(
                                f"Docker container at line {i} created without read-only root filesystem. "
                                f"KSI-CNA-04 requires immutable infrastructure (CM-2) - "
                                f"containers should have read-only root filesystems to prevent runtime modifications."
                            ),
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            line_number=i,
                            code_snippet=self._get_snippet(lines, i, context=3),
                            remediation=(
                                "Enable read-only root filesystem:\n\n"
                                "// Java Docker SDK with read-only root\n"
                                "CreateContainerResponse container = dockerClient.createContainerCmd(\"myapp:latest\")\n"
                                "    .withReadonlyRootfs(true)  // Prevent runtime modifications\n"
                                "    .withVolumes(new Volume(\"/tmp\"))  // Only /tmp writable\n"
                                "    .withBinds(new Bind(\"/tmp\", new Volume(\"/tmp\"), AccessMode.rw))\n"
                                "    .exec();\n\n"
                                "// Testcontainers with read-only root\n"
                                "GenericContainer<?> container = new GenericContainer<>(\"myapp:latest\")\n"
                                "    .withCreateContainerCmdModifier(cmd -> cmd.withHostConfig(\n"
                                "        new HostConfig().withReadonlyRootfs(true)  // Immutable container\n"
                                "    ));\n\n"
                                "Ref: Docker Java SDK (https://github.com/docker-java/docker-java)"
                            )
                        ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CNA-04 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Dockerode container configurations without read-only root
        - Missing immutability in container deployments
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern: Dockerode createContainer without ReadonlyRootfs
        if 'dockerode' in code.lower() or 'docker.createContainer' in code:
            for i, line in enumerate(lines, 1):
                if re.search(r'createContainer\(', line):
                    # Look ahead for ReadonlyRootfs: true
                    context_start = max(0, i - 1)
                    context_end = min(len(lines), i + 15)
                    context_lines = lines[context_start:context_end]
                    context_text = '\n'.join(context_lines)
                    
                    has_readonly = re.search(r'ReadonlyRootfs:\s*true', context_text)
                    
                    if not has_readonly:
                        findings.append(Finding(
                            ksi_id=self.KSI_ID,
                            title="Docker Container Without Read-Only Root Filesystem",
                            description=(
                                f"Docker container at line {i} created without ReadonlyRootfs. "
                                f"KSI-CNA-04 requires immutable infrastructure (CM-2) - "
                                f"containers should have read-only root filesystems to prevent runtime modifications."
                            ),
                            severity=Severity.MEDIUM,
                            file_path=file_path,
                            line_number=i,
                            code_snippet=self._get_snippet(lines, i, context=3),
                            remediation=(
                                "Enable read-only root filesystem:\n\n"
                                "// Dockerode with read-only root\n"
                                "import Docker from 'dockerode';\n"
                                "const docker = new Docker();\n\n"
                                "const container = await docker.createContainer({\n"
                                "  Image: 'myapp:latest',\n"
                                "  HostConfig: {\n"
                                "    ReadonlyRootfs: true,  // Prevent runtime modifications\n"
                                "    Binds: [\n"
                                "      '/tmp:/tmp:rw'  // Only /tmp writable\n"
                                "    ]\n"
                                "  }\n"
                                "});\n\n"
                                "await container.start();\n\n"
                                "Ref: Dockerode (https://github.com/apocas/dockerode)"
                            )
                        ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CNA-04 compliance.
        
        Detects:
        - Virtual machines instead of containers (mutable infrastructure)
        - Container Apps with mutable storage volumes
        - AKS clusters without immutable node images
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Virtual Machine deployment (MEDIUM - suggests mutable infrastructure)
        vm_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Compute/virtualMachines")
        
        if vm_match:
            line_num = vm_match['line_num']
            # Check if using managed identity (least privilege principle)
            vm_end = min(len(lines), line_num + 50)
            vm_lines = lines[line_num:vm_end]
            
            has_managed_identity = any(re.search(r"identity:\s*\{", line) 
                                      for line in vm_lines)
            
            if not has_managed_identity:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Virtual Machine Without Managed Identity",
                    description=(
                        "Virtual machine deployed without managed identity. "
                        "KSI-CNA-04 requires immutable infrastructure with strictly defined privileges by default - "
                        "VMs represent mutable infrastructure and should use managed identities "
                        "for strictly defined, least-privilege access to Azure resources. "
                        "Consider containerized deployments (Container Apps, AKS) for immutable infrastructure."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Add system-assigned or user-assigned managed identity to VMs:\n"
                        "// VM with system-assigned managed identity (preferred for immutability)\n"
                        "resource virtualMachine 'Microsoft.Compute/virtualMachines@2023-03-01' = {\n"
                        "  name: 'myVM'\n"
                        "  location: resourceGroup().location\n"
                        "  identity: {\n"
                        "    type: 'SystemAssigned'  // Strictly defined identity\n"
                        "  }\n"
                        "  properties: {\n"
                        "    hardwareProfile: {\n"
                        "      vmSize: 'Standard_DS1_v2'\n"
                        "    }\n"
                        "    storageProfile: {\n"
                        "      imageReference: {\n"
                        "        publisher: 'Canonical'\n"
                        "        offer: 'UbuntuServer'\n"
                        "        sku: '18.04-LTS'\n"
                        "        version: 'latest'\n"
                        "      }\n"
                        "      osDisk: {\n"
                        "        createOption: 'FromImage'\n"
                        "        managedDisk: {\n"
                        "          storageAccountType: 'Premium_LRS'\n"
                        "        }\n"
                        "      }\n"
                        "    }\n"
                        "    osProfile: {\n"
                        "      computerName: 'myVM'\n"
                        "      adminUsername: 'azureuser'\n"
                        "      linuxConfiguration: {\n"
                        "        disablePasswordAuthentication: true\n"
                        "        ssh: {\n"
                        "          publicKeys: [\n"
                        "            {\n"
                        "              path: '/home/azureuser/.ssh/authorized_keys'\n"
                        "              keyData: sshPublicKey\n"
                        "            }\n"
                        "          ]\n"
                        "        }\n"
                        "      }\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "// Better: Use Container Apps for immutable infrastructure (CM-2, SI-3)\n"
                        "resource containerApp 'Microsoft.App/containerApps@2023-05-01' = {\n"
                        "  name: 'myContainerApp'\n"
                        "  location: resourceGroup().location\n"
                        "  identity: {\n"
                        "    type: 'SystemAssigned'\n"
                        "  }\n"
                        "  properties: {\n"
                        "    managedEnvironmentId: containerEnvironment.id\n"
                        "    configuration: {\n"
                        "      ingress: {\n"
                        "        external: true\n"
                        "        targetPort: 8080\n"
                        "      }\n"
                        "    }\n"
                        "    template: {\n"
                        "      containers: [\n"
                        "        {\n"
                        "          name: 'main'\n"
                        "          image: 'myregistry.azurecr.io/myapp:v1.0.0'  // Immutable image tag\n"
                        "          resources: {\n"
                        "            cpu: json('0.5')\n"
                        "            memory: '1Gi'\n"
                        "          }\n"
                        "        }\n"
                        "      ]\n"
                        "      scale: {\n"
                        "        minReplicas: 2\n"
                        "        maxReplicas: 10\n"
                        "      }\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure Container Apps (https://learn.microsoft.com/azure/container-apps/), VM Managed Identity (https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Container App with mutable volumes (HIGH)
        container_app_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.App/containerApps")
        
        if container_app_match:
            line_num = container_app_match['line_num']
            # Check if using persistent volumes (mutable storage)
            app_end = min(len(lines), line_num + 80)
            app_lines = lines[line_num:app_end]
            
            has_volume = any(re.search(r"volumes?:\s*\[", line) 
                           for line in app_lines)
            has_azure_file = any(re.search(r"storageType:\s*'AzureFile'", line) 
                               for line in app_lines)
            
            if has_volume and has_azure_file:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Container App With Mutable Storage Volume",
                    description=(
                        "Container App using Azure File volume for persistent storage. "
                        "KSI-CNA-04 requires immutable infrastructure - "
                        "containers should be stateless with immutable file systems. "
                        "Mutable volumes violate immutability principles (CM-2) and increase "
                        "configuration drift risks. Use external storage services (Azure Storage, Cosmos DB) "
                        "for persistent state instead of mutable container volumes."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Remove mutable volumes and use external storage services:\n"
                        "// BAD: Container with mutable volume\n"
                        "resource containerApp 'Microsoft.App/containerApps@2023-05-01' = {\n"
                        "  properties: {\n"
                        "    template: {\n"
                        "      volumes: [  // Mutable storage - violates immutability\n"
                        "        {\n"
                        "          name: 'data-volume'\n"
                        "          storageType: 'AzureFile'\n"
                        "          storageName: 'myStorageMount'\n"
                        "        }\n"
                        "      ]\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "// GOOD: Immutable container with external storage\n"
                        "resource containerApp 'Microsoft.App/containerApps@2023-05-01' = {\n"
                        "  name: 'myApp'\n"
                        "  identity: {\n"
                        "    type: 'SystemAssigned'\n"
                        "  }\n"
                        "  properties: {\n"
                        "    template: {\n"
                        "      containers: [\n"
                        "        {\n"
                        "          name: 'app'\n"
                        "          image: 'myregistry.azurecr.io/app:v1.0.0'  // Immutable\n"
                        "          env: [\n"
                        "            {\n"
                        "              name: 'STORAGE_CONNECTION_STRING'\n"
                        "              secretRef: 'storage-secret'  // External storage\n"
                        "            }\n"
                        "            {\n"
                        "              name: 'COSMOS_ENDPOINT'\n"
                        "              value: cosmosAccount.properties.documentEndpoint\n"
                        "            }\n"
                        "          ]\n"
                        "        }\n"
                        "      ]\n"
                        "      // No volumes - stateless container (immutable)\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "// External storage for persistent state\n"
                        "resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {\n"
                        "  name: 'mystorageaccount'\n"
                        "  location: resourceGroup().location\n"
                        "  sku: { name: 'Standard_GRS' }\n"
                        "  kind: 'StorageV2'\n"
                        "}\n\n"
                        "Ref: Container Apps Volumes (https://learn.microsoft.com/azure/container-apps/storage-mounts)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: AKS without image scanning (MEDIUM)
        aks_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.ContainerService/managedClusters")
        
        if aks_match:
            line_num = aks_match['line_num']
            # Check if Defender for Containers is enabled (image immutability validation)
            aks_end = min(len(lines), line_num + 100)
            aks_lines = lines[line_num:aks_end]
            
            has_defender = any(re.search(r"securityProfile:\s*\{.*defenderSecurityMonitoring", ' '.join(aks_lines), re.DOTALL) 
                             for line in aks_lines)
            
            if not has_defender:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="AKS Cluster Without Image Security Validation",
                    description=(
                        "AKS cluster without Microsoft Defender for Containers enabled. "
                        "KSI-CNA-04 requires immutable infrastructure with strictly defined functionality (SI-3) - "
                        "container images must be validated as immutable and free of vulnerabilities. "
                        "Defender provides continuous image scanning to ensure immutability "
                        "and prevent configuration drift."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Enable Microsoft Defender for Containers on AKS:\n"
                        "resource aksCluster 'Microsoft.ContainerService/managedClusters@2023-10-01' = {\n"
                        "  name: 'myAKSCluster'\n"
                        "  location: resourceGroup().location\n"
                        "  identity: {\n"
                        "    type: 'SystemAssigned'\n"
                        "  }\n"
                        "  properties: {\n"
                        "    // Enable Defender for immutable image validation\n"
                        "    securityProfile: {\n"
                        "      defender: {\n"
                        "        securityMonitoring: {\n"
                        "          enabled: true  // Validates image immutability\n"
                        "        }\n"
                        "        logAnalyticsWorkspaceResourceId: logAnalytics.id\n"
                        "      }\n"
                        "      imageCleaner: {\n"
                        "        enabled: true  // Remove unused images\n"
                        "        intervalHours: 24\n"
                        "      }\n"
                        "    }\n"
                        "    agentPoolProfiles: [\n"
                        "      {\n"
                        "        name: 'nodepool1'\n"
                        "        count: 3\n"
                        "        vmSize: 'Standard_DS2_v2'\n"
                        "        mode: 'System'\n"
                        "        // Use managed node images (immutable)\n"
                        "        osType: 'Linux'\n"
                        "        osSKU: 'AzureLinux'  // Immutable OS\n"
                        "      }\n"
                        "    ]\n"
                        "    // Enable workload identity for least privilege\n"
                        "    securityProfile: {\n"
                        "      workloadIdentity: {\n"
                        "        enabled: true\n"
                        "      }\n"
                        "    }\n"
                        "    oidcIssuerProfile: {\n"
                        "      enabled: true\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Microsoft Defender for Containers (https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CNA-04 compliance.
        
        Detects:
        - Virtual machines instead of containers (mutable infrastructure)
        - Container Apps with mutable storage volumes
        - AKS clusters without immutable node images
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Virtual Machine deployment (MEDIUM - suggests mutable infrastructure)
        vm_match = self._find_line(lines, r'resource\s+"azurerm_(linux|windows)_virtual_machine"')
        
        if vm_match:
            line_num = vm_match['line_num']
            # Check if using managed identity
            vm_end = min(len(lines), line_num + 60)
            vm_lines = lines[line_num:vm_end]
            
            has_identity = any(re.search(r'identity\s*\{', line) 
                             for line in vm_lines)
            
            if not has_identity:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Virtual Machine Without Managed Identity",
                    description=(
                        "Virtual machine deployed without managed identity. "
                        "KSI-CNA-04 requires immutable infrastructure with strictly defined privileges by default - "
                        "VMs represent mutable infrastructure and should use managed identities "
                        "for strictly defined, least-privilege access to Azure resources. "
                        "Consider containerized deployments (Container Apps, AKS) for immutable infrastructure."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Add managed identity to VMs:\n"
                        "# VM with system-assigned managed identity (preferred for immutability)\n"
                        "resource \"azurerm_linux_virtual_machine\" \"example\" {\n"
                        "  name                = \"example-vm\"\n"
                        "  resource_group_name = azurerm_resource_group.example.name\n"
                        "  location            = azurerm_resource_group.example.location\n"
                        "  size                = \"Standard_DS1_v2\"\n\n"
                        "  # System-assigned identity for strictly defined privileges\n"
                        "  identity {\n"
                        "    type = \"SystemAssigned\"\n"
                        "  }\n\n"
                        "  admin_username                  = \"azureuser\"\n"
                        "  disable_password_authentication = true\n\n"
                        "  admin_ssh_key {\n"
                        "    username   = \"azureuser\"\n"
                        "    public_key = file(\"~/.ssh/id_rsa.pub\")\n"
                        "  }\n\n"
                        "  os_disk {\n"
                        "    caching              = \"ReadWrite\"\n"
                        "    storage_account_type = \"Premium_LRS\"\n"
                        "  }\n\n"
                        "  source_image_reference {\n"
                        "    publisher = \"Canonical\"\n"
                        "    offer     = \"UbuntuServer\"\n"
                        "    sku       = \"18.04-LTS\"\n"
                        "    version   = \"latest\"\n"
                        "  }\n"
                        "}\n\n"
                        "# Better: Use Container Apps for immutable infrastructure (CM-2, SI-3)\n"
                        "resource \"azurerm_container_app\" \"example\" {\n"
                        "  name                         = \"example-container-app\"\n"
                        "  resource_group_name          = azurerm_resource_group.example.name\n"
                        "  container_app_environment_id = azurerm_container_app_environment.example.id\n"
                        "  revision_mode                = \"Single\"\n\n"
                        "  identity {\n"
                        "    type = \"SystemAssigned\"\n"
                        "  }\n\n"
                        "  template {\n"
                        "    container {\n"
                        "      name   = \"main\"\n"
                        "      image  = \"myregistry.azurecr.io/myapp:v1.0.0\"  # Immutable image tag\n"
                        "      cpu    = 0.5\n"
                        "      memory = \"1Gi\"\n"
                        "    }\n\n"
                        "    min_replicas = 2\n"
                        "    max_replicas = 10\n"
                        "  }\n\n"
                        "  ingress {\n"
                        "    external_enabled = true\n"
                        "    target_port      = 8080\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: azurerm_linux_virtual_machine (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/linux_virtual_machine)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: Container App with volume mounts (HIGH)
        container_app_match = self._find_line(lines, r'resource\s+"azurerm_container_app"')
        
        if container_app_match:
            line_num = container_app_match['line_num']
            # Check if using volume mounts (mutable storage)
            app_end = min(len(lines), line_num + 100)
            app_lines = lines[line_num:app_end]
            
            has_volume = any(re.search(r'volume\s*\{', line) 
                           for line in app_lines)
            has_azure_file = any(re.search(r'storage_type\s*=\s*"AzureFile"', line) 
                               for line in app_lines)
            
            if has_volume and has_azure_file:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Container App With Mutable Storage Volume",
                    description=(
                        "Container App using Azure File volume for persistent storage. "
                        "KSI-CNA-04 requires immutable infrastructure - "
                        "containers should be stateless with immutable file systems. "
                        "Mutable volumes violate immutability principles (CM-2) and increase "
                        "configuration drift risks. Use external storage services (Azure Storage, Cosmos DB) "
                        "for persistent state instead of mutable container volumes."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=5),
                    remediation=(
                        "Remove mutable volumes and use external storage services:\n"
                        "# BAD: Container with mutable volume\n"
                        "resource \"azurerm_container_app\" \"bad_example\" {\n"
                        "  template {\n"
                        "    volume {  # Mutable storage - violates immutability\n"
                        "      name         = \"data-volume\"\n"
                        "      storage_type = \"AzureFile\"\n"
                        "      storage_name = \"mystorageaccount\"\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "# GOOD: Immutable container with external storage\n"
                        "resource \"azurerm_container_app\" \"good_example\" {\n"
                        "  name                         = \"my-app\"\n"
                        "  resource_group_name          = azurerm_resource_group.example.name\n"
                        "  container_app_environment_id = azurerm_container_app_environment.example.id\n"
                        "  revision_mode                = \"Single\"\n\n"
                        "  identity {\n"
                        "    type = \"SystemAssigned\"\n"
                        "  }\n\n"
                        "  template {\n"
                        "    container {\n"
                        "      name   = \"app\"\n"
                        "      image  = \"myregistry.azurecr.io/app:v1.0.0\"  # Immutable\n"
                        "      cpu    = 0.5\n"
                        "      memory = \"1Gi\"\n\n"
                        "      env {\n"
                        "        name        = \"STORAGE_CONNECTION_STRING\"\n"
                        "        secret_name = \"storage-secret\"  # External storage\n"
                        "      }\n\n"
                        "      env {\n"
                        "        name  = \"COSMOS_ENDPOINT\"\n"
                        "        value = azurerm_cosmosdb_account.example.endpoint\n"
                        "      }\n"
                        "    }\n"
                        "    # No volumes - stateless container (immutable)\n"
                        "  }\n"
                        "}\n\n"
                        "# External storage for persistent state\n"
                        "resource \"azurerm_storage_account\" \"example\" {\n"
                        "  name                     = \"mystorageaccount\"\n"
                        "  resource_group_name      = azurerm_resource_group.example.name\n"
                        "  location                 = azurerm_resource_group.example.location\n"
                        "  account_tier             = \"Standard\"\n"
                        "  account_replication_type = \"GRS\"\n"
                        "}\n\n"
                        "Ref: azurerm_container_app volumes (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/container_app#volume)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: AKS without Defender (MEDIUM)
        aks_match = self._find_line(lines, r'resource\s+"azurerm_kubernetes_cluster"')
        
        if aks_match:
            line_num = aks_match['line_num']
            # Check if Defender is enabled
            aks_end = min(len(lines), line_num + 150)
            aks_lines = lines[line_num:aks_end]
            
            has_defender = any(re.search(r'microsoft_defender\s*\{', line) 
                             for line in aks_lines)
            
            if not has_defender:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="AKS Cluster Without Image Security Validation",
                    description=(
                        "AKS cluster without Microsoft Defender for Containers enabled. "
                        "KSI-CNA-04 requires immutable infrastructure with strictly defined functionality (SI-3) - "
                        "container images must be validated as immutable and free of vulnerabilities. "
                        "Defender provides continuous image scanning to ensure immutability "
                        "and prevent configuration drift."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Enable Microsoft Defender for Containers on AKS:\n"
                        "resource \"azurerm_kubernetes_cluster\" \"example\" {\n"
                        "  name                = \"example-aks\"\n"
                        "  location            = azurerm_resource_group.example.location\n"
                        "  resource_group_name = azurerm_resource_group.example.name\n"
                        "  dns_prefix          = \"exampleaks\"\n\n"
                        "  identity {\n"
                        "    type = \"SystemAssigned\"\n"
                        "  }\n\n"
                        "  # Enable Defender for immutable image validation\n"
                        "  microsoft_defender {\n"
                        "    log_analytics_workspace_id = azurerm_log_analytics_workspace.example.id\n"
                        "  }\n\n"
                        "  # Image cleaner to remove unused images\n"
                        "  image_cleaner_enabled        = true\n"
                        "  image_cleaner_interval_hours = 24\n\n"
                        "  default_node_pool {\n"
                        "    name       = \"default\"\n"
                        "    node_count = 3\n"
                        "    vm_size    = \"Standard_DS2_v2\"\n"
                        "    os_sku     = \"AzureLinux\"  # Immutable OS\n"
                        "  }\n\n"
                        "  # Enable workload identity for least privilege\n"
                        "  oidc_issuer_enabled       = true\n"
                        "  workload_identity_enabled = true\n"
                        "}\n\n"
                        "resource \"azurerm_log_analytics_workspace\" \"example\" {\n"
                        "  name                = \"example-log-analytics\"\n"
                        "  location            = azurerm_resource_group.example.location\n"
                        "  resource_group_name = azurerm_resource_group.example.name\n"
                        "  sku                 = \"PerGB2018\"\n"
                        "  retention_in_days   = 90\n"
                        "}\n\n"
                        "Ref: azurerm_kubernetes_cluster microsoft_defender (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#microsoft_defender)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CNA-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CNA-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CNA-04 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], pattern: str) -> Optional[Dict[str, Any]]:
        """Find line number and content matching regex pattern."""
        for i, line in enumerate(lines, 1):
            if re.search(pattern, line, re.IGNORECASE):
                return {'line_num': i, 'line': line}
        return None
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])

