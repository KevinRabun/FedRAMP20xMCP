"""
FRR-VDR-08: Evaluate Internet-Reachability

Providers MUST evaluate detected vulnerabilities, considering the context of the 
cloud service offering, to determine if they are internet-reachable vulnerabilities.

Official FedRAMP 20x Requirement
Source: FRR-VDR (Vulnerability Detection and Response) family
Primary Keyword: MUST
Impact Levels: Low, Moderate, High
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseFRRAnalyzer


class FRR_VDR_08_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-VDR-08: Evaluate Internet-Reachability
    
    **Official Statement:**
    Providers MUST evaluate detected vulnerabilities, considering the context of the 
    cloud service offering, to determine if they are internet-reachable vulnerabilities.
    
    **Family:** VDR - Vulnerability Detection and Response
    
    **Primary Keyword:** MUST
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes  
    - High: Yes
    
    **NIST Controls:**
    - RA-5: Vulnerability Monitoring and Scanning
    - SC-7: Boundary Protection
    - AC-4: Information Flow Enforcement
    
    **Related KSIs:**
    - KSI-CNA-01: Network Segmentation
    - KSI-CNA-02: Network Access Control
    - KSI-AFR-04: Vulnerability Detection and Response
    
    **Detectability:** Code-Detectable (IaC)
    
    **Detection Strategy:**
    Analyze infrastructure code for:
    - Public IP addresses assigned to resources
    - Internet-facing load balancers
    - VMs/containers without network security groups
    - Open firewall rules (0.0.0.0/0 ingress)
    - Resources in public subnets
    - Missing private endpoints
    """
    
    FRR_ID = "FRR-VDR-08"
    FRR_NAME = "Evaluate Internet-Reachability"
    FRR_STATEMENT = """Providers MUST evaluate detected vulnerabilities, considering the context of the cloud service offering, to determine if they are internet-reachable vulnerabilities."""
    FAMILY = "VDR"
    FAMILY_NAME = "Vulnerability Detection and Response"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("RA-5", "Vulnerability Monitoring and Scanning"),
        ("SC-7", "Boundary Protection"),
        ("AC-4", "Information Flow Enforcement")
    ]
    CODE_DETECTABLE = "Yes"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = ["KSI-CNA-01", "KSI-CNA-02", "KSI-AFR-04"]
    
    def __init__(self):
        """Initialize FRR-VDR-08 analyzer."""
        super().__init__(
            frr_id=self.FRR_ID,
            frr_name=self.FRR_NAME,
            frr_statement=self.FRR_STATEMENT
        )
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Primary detection for FRR-VDR-08)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for internet-reachable resources.
        
        Detects:
        - Public IP addresses
        - Internet-facing load balancers
        - VMs without NSGs
        - Open firewall rules (0.0.0.0/0)
        - Public subnet configurations
        """
        findings = []
        lines = code.split('\n')
        
        # Check for Public IP address resources
        public_ip_pattern = r"resource\s+\w+\s+'Microsoft\.Network/publicIPAddresses"
        for i, line in enumerate(lines, 1):
            if re.search(public_ip_pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Internet-reachable resource: Public IP address",
                    description="Public IP address detected. FRR-VDR-08 requires evaluation of internet-reachable vulnerabilities. Ensure this resource has vulnerability scanning enabled and findings are evaluated for internet exposure.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation="1. Enable vulnerability scanning for resources with public IPs\n2. Implement Network Security Groups with restrictive inbound rules\n3. Use Azure Firewall or Application Gateway for internet-facing services\n4. Document internet-reachability assessment in vulnerability reports"
                ))
        
        # Check for Load Balancers (potential internet-facing)
        lb_pattern = r"resource\s+\w+\s+'Microsoft\.Network/loadBalancers"
        for i, line in enumerate(lines, 1):
            if re.search(lb_pattern, line, re.IGNORECASE):
                # Check if it has public frontend IP
                snippet_start = max(1, i - 2)
                snippet_end = min(len(lines), i + 20)
                snippet = '\n'.join(lines[snippet_start-1:snippet_end])
                
                if 'publicIPAddress' in snippet or 'PublicIPAddress' in snippet:
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Internet-reachable resource: Public Load Balancer",
                        description="Load balancer with public frontend IP detected. Per FRR-VDR-08, internet-reachable resources require vulnerability assessment and evaluation.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 5),
                        recommendation="1. Enable Azure DDoS Protection Standard\n2. Implement WAF for HTTP/HTTPS load balancers\n3. Configure NSG on backend resources\n4. Enable vulnerability scanning on backend pool members\n5. Document internet-reachability in security assessments"
                    ))
        
        # Check for Network Security Groups with overly permissive rules
        nsg_pattern = r"resource\s+\w+\s+'Microsoft\.Network/networkSecurityGroups"
        for i, line in enumerate(lines, 1):
            if re.search(nsg_pattern, line, re.IGNORECASE):
                # Check for 0.0.0.0/0 or * in source address
                snippet_start = max(1, i - 2)
                snippet_end = min(len(lines), i + 30)
                snippet = '\n'.join(lines[snippet_start-1:snippet_end])
                
                if re.search(r"('0\.0\.0\.0/0'|'\*'|\"0\.0\.0\.0/0\"|\"\*\")", snippet):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Overly permissive NSG rule allows internet access",
                        description="Network Security Group allows inbound traffic from any source (0.0.0.0/0 or *). This creates internet-reachable resources that require vulnerability evaluation per FRR-VDR-08.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 10),
                        recommendation="1. Restrict source addresses to specific IP ranges or service tags\n2. Use Just-In-Time VM access for management ports\n3. Implement Azure Bastion for secure remote access\n4. Enable vulnerability scanning on exposed resources\n5. Document justification for internet-facing services"
                    ))
        
        # Check for Virtual Machines without explicit NSG reference
        vm_pattern = r"resource\s+\w+\s+'Microsoft\.Compute/virtualMachines"
        for i, line in enumerate(lines, 1):
            if re.search(vm_pattern, line, re.IGNORECASE):
                # Check if VM has NSG association in next 40 lines
                snippet_start = max(1, i - 2)
                snippet_end = min(len(lines), i + 40)
                snippet = '\n'.join(lines[snippet_start-1:snippet_end])
                
                has_nsg = 'networkSecurityGroup' in snippet or 'NetworkSecurityGroup' in snippet
                has_public_ip = 'publicIPAddress' in snippet or 'PublicIPAddress' in snippet
                
                if has_public_ip and not has_nsg:
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="VM with public IP lacks Network Security Group",
                        description="Virtual Machine has public IP but no Network Security Group reference. Internet-reachable VMs require NSG protection and vulnerability evaluation per FRR-VDR-08.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 8),
                        recommendation="1. Associate Network Security Group with VM's network interface\n2. Configure restrictive inbound rules (deny by default)\n3. Enable Microsoft Defender for Cloud\n4. Implement vulnerability scanning (Qualys/Defender)\n5. Use Azure Bastion instead of direct RDP/SSH"
                    ))
        
        # Check for Application Gateway (internet-facing by nature)
        appgw_pattern = r"resource\s+\w+\s+'Microsoft\.Network/applicationGateways"
        for i, line in enumerate(lines, 1):
            if re.search(appgw_pattern, line, re.IGNORECASE):
                findings.append(Finding(
                    ksi_id=self.FRR_ID,
                    requirement_id=self.FRR_ID,
                    title="Internet-facing Application Gateway requires vulnerability assessment",
                    description="Application Gateway detected - typically internet-facing. FRR-VDR-08 requires evaluation of vulnerabilities in internet-reachable services.",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=i,
                    code_snippet=self._get_snippet(lines, i, 3),
                    recommendation="1. Enable WAF on Application Gateway (Prevention mode)\n2. Configure OWASP rule sets\n3. Enable vulnerability scanning on backend pool members\n4. Implement SSL/TLS with strong ciphers\n5. Document internet-reachability assessment\n6. Enable Azure DDoS Protection"
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for internet-reachable resources.
        
        Detects:
        - AWS/Azure public resources
        - Security groups with 0.0.0.0/0
        - Public subnets
        - Internet gateways
        """
        findings = []
        lines = code.split('\n')
        
        # Azure Public IP
        if re.search(r'resource\s+"azurerm_public_ip"', code):
            for i, line in enumerate(lines, 1):
                if re.search(r'resource\s+"azurerm_public_ip"', line):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Internet-reachable: Azure Public IP",
                        description="Public IP resource detected. FRR-VDR-08 requires vulnerability evaluation for internet-reachable resources.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 3),
                        recommendation="1. Enable vulnerability scanning\n2. Implement NSG with restrictive rules\n3. Use Azure Firewall for centralized protection\n4. Document internet exposure justification"
                    ))
        
        # Azure NSG with overly permissive rules
        nsg_pattern = r'resource\s+"azurerm_network_security_group"'
        for i, line in enumerate(lines, 1):
            if re.search(nsg_pattern, line):
                snippet_end = min(len(lines), i + 30)
                snippet = '\n'.join(lines[i:snippet_end])
                
                if re.search(r'source_address_prefix\s*=\s*["\'](\*|0\.0\.0\.0/0)["\']', snippet):
                    findings.append(Finding(
                        ksi_id=self.FRR_ID,
                        requirement_id=self.FRR_ID,
                        title="Azure NSG allows internet inbound (0.0.0.0/0 or *)",
                        description="Network Security Group rule allows traffic from any source. Internet-reachable resources require vulnerability assessment per FRR-VDR-08.",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=i,
                        code_snippet=self._get_snippet(lines, i, 10),
                        recommendation="1. Use specific CIDR ranges or service tags\n2. Implement Azure Bastion for secure access\n3. Enable Microsoft Defender for Cloud\n4. Configure JIT VM access\n5. Document internet exposure requirements"
                    ))
        
        return findings
    
    # ============================================================================
    # APPLICATION CODE ANALYZERS (Not applicable for FRR-VDR-08)
    # ============================================================================
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-VDR-08 is IaC-focused. No application code detection."""
        return []
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-VDR-08 is IaC-focused. No application code detection."""
        return []
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-VDR-08 is IaC-focused. No application code detection."""
        return []
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-VDR-08 is IaC-focused. No application code detection."""
        return []
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Not applicable for FRR-VDR-08)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-VDR-08 is IaC-focused. No CI/CD detection."""
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-VDR-08 is IaC-focused. No CI/CD detection."""
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """FRR-VDR-08 is IaC-focused. No CI/CD detection."""
        return []

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for FRR-VDR-08.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "frr_id": self.frr_id,
            "frr_name": "Evaluate Internet-Reachability",
            "primary_keyword": "MUST",
            "impact_levels": ["Low", "Moderate", "High"],
            "evidence_type": "automated",
            "automation_feasibility": "high",
            "azure_services": [
                "Azure Resource Graph",
                "Microsoft Defender for Cloud",
                "Azure Network Watcher",
                "Azure Monitor",
                "Azure Policy"
            ],
            "collection_methods": [
                "Azure Resource Graph query to identify all resources with public IPs",
                "Azure Policy evaluation for NSG rules allowing 0.0.0.0/0",
                "Microsoft Defender for Cloud security recommendations for internet-exposed VMs",
                "Azure Network Watcher topology analysis for internet-facing resources",
                "Azure Monitor workbook aggregating vulnerability scan results for public resources"
            ],
            "implementation_steps": [
                "1. Deploy Azure Policy to audit resources with public IPs and overly permissive NSG rules",
                "2. Create Azure Resource Graph query to inventory internet-reachable resources",
                "3. Enable Microsoft Defender for Cloud vulnerability scanning on all internet-facing VMs",
                "4. Configure Azure Monitor workbook to display vulnerability assessment results filtered by internet-reachability",
                "5. Implement Azure Automation runbook to generate monthly report of internet-reachable resources and their vulnerability status",
                "6. Store evidence artifacts in Azure Storage with 7-year retention"
            ],
            "evidence_artifacts": [
                "Internet-Reachable Resources Inventory (JSON export from Azure Resource Graph)",
                "Vulnerability Assessment Results for Public-Facing Resources (CSV from Defender for Cloud)",
                "NSG Rules Audit Report (Excel showing all rules allowing 0.0.0.0/0)",
                "Network Topology Diagram with Internet-Facing Resources Highlighted (Azure Network Watcher)",
                "Monthly Internet-Reachability Assessment Report (PDF with vulnerability evaluation summary)"
            ],
            "update_frequency": "continuous (real-time for new resources), monthly reporting",
            "responsible_party": "Cloud Security Team / Network Security Team"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "Azure Resource Graph KQL",
                "query_name": "All resources with public IP addresses",
                "query": """Resources
| where type =~ 'Microsoft.Network/publicIPAddresses'
| project resourceId = id, resourceName = name, resourceGroup, location, subscriptionId, properties
| join kind=inner (
    Resources
    | where type in~ ('Microsoft.Compute/virtualMachines', 'Microsoft.Network/loadBalancers', 'Microsoft.Network/applicationGateways')
    | mv-expand ipConfig = properties.ipConfigurations
    | extend publicIpId = tostring(ipConfig.properties.publicIPAddress.id)
    | project resourceId = id, resourceName = name, resourceType = type, publicIpId
) on $left.resourceId == $right.publicIpId
| project resourceId, resourceName, resourceType, publicIpAddress = resourceId1, resourceGroup, location
| order by resourceType, resourceName""",
                "purpose": "Identify all Azure resources with public IP addresses for internet-reachability assessment"
            },
            {
                "query_type": "Azure Resource Graph KQL",
                "query_name": "NSG rules allowing internet inbound (0.0.0.0/0)",
                "query": """Resources
| where type == 'microsoft.network/networksecuritygroups'
| mv-expand rules = properties.securityRules
| where rules.properties.direction == 'Inbound' 
    and rules.properties.access == 'Allow'
    and (rules.properties.sourceAddressPrefix == '*' or rules.properties.sourceAddressPrefix == '0.0.0.0/0' or rules.properties.sourceAddressPrefix == 'Internet')
| project nsgName = name, resourceGroup, ruleName = rules.name, 
    priority = rules.properties.priority, 
    sourceAddress = rules.properties.sourceAddressPrefix,
    destinationPort = rules.properties.destinationPortRange,
    protocol = rules.properties.protocol
| order by nsgName, priority""",
                "purpose": "Identify overly permissive NSG rules that allow inbound traffic from the internet"
            },
            {
                "query_type": "Microsoft Defender for Cloud REST API",
                "query_name": "Vulnerability assessment results for internet-facing VMs",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01&$filter=properties/resourceDetails/Source eq 'Azure' and properties/status/code eq 'Unhealthy' and properties/metadata/assessmentType eq 'Vulnerability'",
                "purpose": "Retrieve vulnerability findings for all Azure VMs, to be filtered for internet-facing resources"
            },
            {
                "query_type": "Azure Monitor KQL",
                "query_name": "Public IP access logs (via Network Watcher NSG Flow Logs)",
                "query": """AzureNetworkAnalytics_CL
| where FlowType_s == 'ExternalPublic' and FlowDirection_s == 'I'
| summarize InboundFlows = count(), UniqueSourceIPs = dcount(SrcIP_s) by DestIP_s, DestPort_d, VM_s
| where InboundFlows > 100
| order by InboundFlows desc
| take 50""",
                "purpose": "Analyze inbound traffic patterns to public IPs to identify actively internet-exposed resources"
            },
            {
                "query_type": "Azure Policy Compliance REST API",
                "query_name": "Compliance status for internet-facing resources policy",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01&$filter=policyDefinitionName eq 'audit-public-ip-resources'",
                "purpose": "Track compliance with custom Azure Policy that audits internet-facing resources"
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
                "artifact_name": "Internet-Reachable Resources Inventory",
                "artifact_type": "JSON file",
                "description": "Complete list of all Azure resources with public IP addresses, including resource type, name, location, and associated NSG rules",
                "collection_method": "Azure Resource Graph query exported via Azure CLI or PowerShell",
                "storage_location": "Azure Storage Account /evidence/frr-vdr-08/inventory/{YYYY-MM}/"
            },
            {
                "artifact_name": "Vulnerability Assessment Results for Public Resources",
                "artifact_type": "CSV file",
                "description": "Vulnerability findings from Microsoft Defender for Cloud filtered to show only internet-facing VMs, including CVE IDs, severity, and remediation status",
                "collection_method": "Microsoft Defender for Cloud REST API query filtered by resource tags or public IP association",
                "storage_location": "Azure Storage Account /evidence/frr-vdr-08/vulnerabilities/{YYYY-MM}/"
            },
            {
                "artifact_name": "NSG Rules Audit Report",
                "artifact_type": "Excel workbook",
                "description": "Detailed audit of all Network Security Group rules allowing inbound traffic from 0.0.0.0/0, Internet, or *, with justification notes",
                "collection_method": "Azure Resource Graph query formatted into Excel via Azure Automation PowerShell runbook",
                "storage_location": "Azure Storage Account /evidence/frr-vdr-08/nsg-audit/{YYYY-MM}/"
            },
            {
                "artifact_name": "Network Topology with Internet-Facing Highlights",
                "artifact_type": "PNG/SVG diagram",
                "description": "Visual network topology diagram from Azure Network Watcher with internet-facing resources highlighted in red",
                "collection_method": "Azure Network Watcher topology export with post-processing script to highlight public IPs",
                "storage_location": "Azure Storage Account /evidence/frr-vdr-08/topology/{YYYY-MM}/"
            },
            {
                "artifact_name": "Monthly Internet-Reachability Assessment Report",
                "artifact_type": "PDF report",
                "description": "Executive summary showing count of internet-facing resources, vulnerability assessment completion rate, high/critical findings requiring remediation, and month-over-month trends",
                "collection_method": "Azure Logic App aggregating data from Resource Graph, Defender for Cloud, and Network Watcher, generating PDF via Power BI or custom reporting tool",
                "storage_location": "Azure Storage Account /evidence/frr-vdr-08/reports/{YYYY-MM}/ with email distribution to security team"
            }
        ]
