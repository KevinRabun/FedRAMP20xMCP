"""
KSI-CNA-05: Unwanted Activity

Protect against denial of service attacks and other unwanted activity.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Optional, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CNA_05_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-CNA-05: Unwanted Activity
    
    **Official Statement:**
    Protect against denial of service attacks and other unwanted activity.
    
    **Family:** CNA - Cloud Native Architecture
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - sc-5
    - si-8
    - si-8.2
    
    **Detectability:** Process/Documentation (Limited code detection)
    
    **Detection Strategy:**
    This KSI primarily involves processes, policies, or documentation. Code analysis may have limited applicability.
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-CNA-05"
    KSI_NAME = "Unwanted Activity"
    KSI_STATEMENT = """Protect against denial of service attacks and other unwanted activity."""
    FAMILY = "CNA"
    FAMILY_NAME = "Cloud Native Architecture"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = ["sc-5", "si-8", "si-8.2"]
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
        Analyze Python code for KSI-CNA-05 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        TODO: Implement detection logic for:
        - Protect against denial of service attacks and other unwanted activity....
        """
        findings = []
        
        # TODO: Implement Python-specific detection logic
        # Example patterns to detect:
        # - Configuration issues
        # - Missing security controls
        # - Framework-specific vulnerabilities
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-CNA-05 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        TODO: Implement detection logic for:
        - Protect against denial of service attacks and other unwanted activity....
        """
        findings = []
        
        # TODO: Implement C#-specific detection logic
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-CNA-05 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        TODO: Implement detection logic for:
        - Protect against denial of service attacks and other unwanted activity....
        """
        findings = []
        
        # TODO: Implement Java-specific detection logic
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-CNA-05 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        TODO: Implement detection logic for:
        - Protect against denial of service attacks and other unwanted activity....
        """
        findings = []
        
        # TODO: Implement TypeScript-specific detection logic
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-CNA-05 compliance.
        
        Detects:
        - Web apps without Azure Front Door/DDoS protection
        - API Management without rate limiting policies
        - Application Gateway without WAF
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: Web App/App Service without DDoS protection (HIGH)
        webapp_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Web/sites")
        
        if webapp_match:
            line_num = webapp_match['line_num']
            # Check if protected by Front Door or DDoS plan
            has_frontdoor = any(re.search(r"Microsoft\.Network/(frontDoors|FrontDoorWebApplicationFirewallPolicies)", line) 
                              for line in lines)
            has_ddos = any(re.search(r"Microsoft\.Network/ddosProtectionPlans", line) 
                         for line in lines)
            
            if not (has_frontdoor or has_ddos):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Web App Without DDoS Protection",
                    description=(
                        "Web App deployed without DDoS protection or Azure Front Door. "
                        "KSI-CNA-05 requires protecting against DoS attacks (SC-5) - "
                        "public-facing web applications must be protected by Azure Front Door, "
                        "Azure DDoS Protection, or equivalent service to mitigate volumetric attacks, "
                        "protocol attacks, and resource-layer attacks."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Add Azure Front Door with WAF for DDoS protection:\n"
                        "// Azure Front Door with DDoS protection and rate limiting\n"
                        "param wafPolicyId string\n\n"
                        "resource frontDoor 'Microsoft.Network/frontDoors@2021-06-01' = {\n"
                        "  name: 'myFrontDoor'\n"
                        "  location: 'Global'\n"
                        "  properties: {\n"
                        "    enabledState: 'Enabled'\n"
                        "    frontendEndpoints: [\n"
                        "      {\n"
                        "        name: 'frontendEndpoint1'\n"
                        "        properties: {\n"
                        "          hostName: '${frontDoorName}.azurefd.net'\n"
                        "          sessionAffinityEnabledState: 'Disabled'\n"
                        "          // WAF policy for DDoS protection\n"
                        "          webApplicationFirewallPolicyLink: {\n"
                        "            id: wafPolicyId\n"
                        "          }\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "    backendPools: [\n"
                        "      {\n"
                        "        name: 'backendPool1'\n"
                        "        properties: {\n"
                        "          backends: [\n"
                        "            {\n"
                        "              address: webApp.properties.defaultHostName\n"
                        "              backendHostHeader: webApp.properties.defaultHostName\n"
                        "              httpPort: 80\n"
                        "              httpsPort: 443\n"
                        "              weight: 50\n"
                        "              priority: 1\n"
                        "              enabledState: 'Enabled'\n"
                        "            }\n"
                        "          ]\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "    routingRules: [\n"
                        "      {\n"
                        "        name: 'routingRule1'\n"
                        "        properties: {\n"
                        "          frontendEndpoints: [\n"
                        "            { id: resourceId('Microsoft.Network/frontDoors/frontendEndpoints', frontDoorName, 'frontendEndpoint1') }\n"
                        "          ]\n"
                        "          acceptedProtocols: ['Https']\n"
                        "          patternsToMatch: ['/*']\n"
                        "          routeConfiguration: {\n"
                        "            '@odata.type': '#Microsoft.Azure.FrontDoor.Models.FrontdoorForwardingConfiguration'\n"
                        "            forwardingProtocol: 'HttpsOnly'\n"
                        "            backendPool: { id: resourceId('Microsoft.Network/frontDoors/backendPools', frontDoorName, 'backendPool1') }\n"
                        "          }\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "  }\n"
                        "}\n\n"
                        "// WAF Policy with DDoS protection rules\n"
                        "resource wafPolicy 'Microsoft.Network/FrontDoorWebApplicationFirewallPolicies@2022-05-01' = {\n"
                        "  name: 'myWafPolicy'\n"
                        "  location: 'Global'\n"
                        "  sku: {\n"
                        "    name: 'Premium_AzureFrontDoor'  // Required for advanced DDoS\n"
                        "  }\n"
                        "  properties: {\n"
                        "    policySettings: {\n"
                        "      enabledState: 'Enabled'\n"
                        "      mode: 'Prevention'\n"
                        "      // Rate limiting for DoS protection (SC-5)\n"
                        "      requestBodyCheck: 'Enabled'\n"
                        "      maxRequestBodySizeInKb: 128\n"
                        "    }\n"
                        "    customRules: {\n"
                        "      rules: [\n"
                        "        {\n"
                        "          name: 'RateLimitRule'\n"
                        "          priority: 1\n"
                        "          ruleType: 'RateLimitRule'\n"
                        "          rateLimitThreshold: 100  // Max requests per minute\n"
                        "          rateLimitDurationInMinutes: 1\n"
                        "          matchConditions: [\n"
                        "            {\n"
                        "              matchVariable: 'RequestUri'\n"
                        "              operator: 'Contains'\n"
                        "              matchValue: ['/api/']\n"
                        "            }\n"
                        "          ]\n"
                        "          action: 'Block'\n"
                        "        }\n"
                        "      ]\n"
                        "    }\n"
                        "    managedRules: {\n"
                        "      managedRuleSets: [\n"
                        "        {\n"
                        "          ruleSetType: 'Microsoft_DefaultRuleSet'\n"
                        "          ruleSetVersion: '2.1'\n"
                        "        }\n"
                        "        {\n"
                        "          ruleSetType: 'Microsoft_BotManagerRuleSet'\n"
                        "          ruleSetVersion: '1.0'\n"
                        "        }\n"
                        "      ]\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Azure Front Door DDoS Protection (https://learn.microsoft.com/azure/frontdoor/front-door-ddos)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 2: API Management without rate limiting (HIGH)
        apim_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.ApiManagement/service")
        
        if apim_match:
            line_num = apim_match['line_num']
            # Check if rate limit policy exists
            has_rate_limit = any(re.search(r"rate-limit|quota|throttle", line, re.IGNORECASE) 
                               for line in lines)
            
            if not has_rate_limit:
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="API Management Without Rate Limiting",
                    description=(
                        "API Management service without rate limiting policies. "
                        "KSI-CNA-05 requires protecting against DoS attacks and unwanted activity (SC-5, SI-8) - "
                        "APIs must implement rate limiting, quota policies, and throttling "
                        "to prevent abuse and resource exhaustion attacks."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Add rate limiting policies to API Management:\n"
                        "// API Management with rate limiting\n"
                        "resource apiManagement 'Microsoft.ApiManagement/service@2023-03-01-preview' = {\n"
                        "  name: 'myApiManagement'\n"
                        "  location: resourceGroup().location\n"
                        "  sku: {\n"
                        "    name: 'Standard'\n"
                        "    capacity: 1\n"
                        "  }\n"
                        "  properties: {\n"
                        "    publisherEmail: 'admin@example.com'\n"
                        "    publisherName: 'My Company'\n"
                        "  }\n"
                        "}\n\n"
                        "// Global rate limit policy (DoS protection)\n"
                        "resource rateLimitPolicy 'Microsoft.ApiManagement/service/policies@2023-03-01-preview' = {\n"
                        "  parent: apiManagement\n"
                        "  name: 'policy'\n"
                        "  properties: {\n"
                        "    value: '''\n"
                        "      <policies>\n"
                        "        <inbound>\n"
                        "          <!-- Rate limit by IP address (SC-5) -->\n"
                        "          <rate-limit-by-key calls=\"100\" renewal-period=\"60\" \n"
                        "                            counter-key=\"@(context.Request.IpAddress)\" />\n"
                        "          \n"
                        "          <!-- Quota limit per subscription -->\n"
                        "          <quota-by-key calls=\"10000\" renewal-period=\"86400\" \n"
                        "                        counter-key=\"@(context.Subscription.Id)\" />\n"
                        "          \n"
                        "          <!-- Throttle concurrent requests -->\n"
                        "          <limit-concurrency key=\"@(context.Request.IpAddress)\" max-count=\"10\" />\n"
                        "          \n"
                        "          <!-- Block suspicious user agents (SI-8) -->\n"
                        "          <choose>\n"
                        "            <when condition=\"@(context.Request.Headers.GetValueOrDefault('User-Agent','').Contains('bot'))\">\n"
                        "              <return-response>\n"
                        "                <set-status code=\"403\" reason=\"Forbidden\" />\n"
                        "              </return-response>\n"
                        "            </when>\n"
                        "          </choose>\n"
                        "          \n"
                        "          <!-- Check request size limits -->\n"
                        "          <check-header name=\"Content-Length\" failed-check-httpcode=\"413\" \n"
                        "                        failed-check-error-message=\"Request too large\">\n"
                        "            <value>1048576</value> <!-- 1 MB max -->\n"
                        "          </check-header>\n"
                        "        </inbound>\n"
                        "      </policies>\n"
                        "    '''\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: API Management Rate Limiting (https://learn.microsoft.com/azure/api-management/api-management-howto-rate-limit)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        # Pattern 3: Application Gateway without WAF (MEDIUM)
        appgw_match = self._find_line(lines, r"resource\s+\w+\s+'Microsoft\.Network/applicationGateways")
        
        if appgw_match:
            line_num = appgw_match['line_num']
            # Check if WAF is enabled
            appgw_end = min(len(lines), line_num + 100)
            appgw_lines = lines[line_num:appgw_end]
            
            has_waf = any(re.search(r"sku.*WAF|firewallPolicy", line, re.IGNORECASE) 
                        for line in appgw_lines)
            
            if not has_waf:
                findings.append(Finding(
                    severity=Severity.MEDIUM,
                    title="Application Gateway Without WAF",
                    description=(
                        "Application Gateway deployed without Web Application Firewall (WAF). "
                        "KSI-CNA-05 requires protecting against unwanted activity (SC-5, SI-8.2) - "
                        "Application Gateway should use WAF SKU or WAF policy "
                        "to protect against common web exploits, bot traffic, and application-layer DDoS attacks."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Use Application Gateway with WAF:\n"
                        "// Application Gateway with WAF for DoS protection\n"
                        "resource applicationGateway 'Microsoft.Network/applicationGateways@2023-06-01' = {\n"
                        "  name: 'myAppGateway'\n"
                        "  location: resourceGroup().location\n"
                        "  properties: {\n"
                        "    sku: {\n"
                        "      name: 'WAF_v2'  // WAF-enabled SKU\n"
                        "      tier: 'WAF_v2'\n"
                        "      capacity: 2\n"
                        "    }\n"
                        "    // WAF configuration for DDoS protection\n"
                        "    webApplicationFirewallConfiguration: {\n"
                        "      enabled: true\n"
                        "      firewallMode: 'Prevention'  // Block malicious traffic\n"
                        "      ruleSetType: 'OWASP'\n"
                        "      ruleSetVersion: '3.2'\n"
                        "      // Rate limiting and request limits\n"
                        "      requestBodyCheck: true\n"
                        "      maxRequestBodySizeInKb: 128\n"
                        "      fileUploadLimitInMb: 100\n"
                        "    }\n"
                        "    gatewayIPConfigurations: [\n"
                        "      {\n"
                        "        name: 'appGatewayIpConfig'\n"
                        "        properties: {\n"
                        "          subnet: { id: subnet.id }\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "    frontendIPConfigurations: [\n"
                        "      {\n"
                        "        name: 'appGatewayFrontendIP'\n"
                        "        properties: {\n"
                        "          publicIPAddress: { id: publicIP.id }\n"
                        "        }\n"
                        "      }\n"
                        "    ]\n"
                        "    frontendPorts: [\n"
                        "      {\n"
                        "        name: 'port_443'\n"
                        "        properties: { port: 443 }\n"
                        "      }\n"
                        "    ]\n"
                        "    // Additional configuration...\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: Application Gateway WAF (https://learn.microsoft.com/azure/web-application-firewall/ag/ag-overview)"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-CNA-05 compliance.
        
        Detects:
        - Web apps without Azure Front Door/DDoS protection
        - API Management without rate limiting policies
        - Application Gateway without WAF
        """
        findings = []
        lines = code.split('\n')
        
        # Pattern 1: App Service without DDoS protection (HIGH)
        webapp_match = self._find_line(lines, r'resource\s+"azurerm_(linux|windows)_web_app"')
        
        if webapp_match:
            line_num = webapp_match['line_num']
            # Check if protected by Front Door
            has_frontdoor = any(re.search(r'resource\s+"azurerm_cdn_frontdoor', line) 
                              for line in lines)
            has_ddos = any(re.search(r'resource\s+"azurerm_network_ddos_protection_plan"', line) 
                         for line in lines)
            
            if not (has_frontdoor or has_ddos):
                findings.append(Finding(
                    severity=Severity.HIGH,
                    title="Web App Without DDoS Protection",
                    description=(
                        "Web App deployed without DDoS protection or Azure Front Door. "
                        "KSI-CNA-05 requires protecting against DoS attacks (SC-5) - "
                        "public-facing web applications must be protected by Azure Front Door, "
                        "Azure DDoS Protection, or equivalent service to mitigate volumetric attacks, "
                        "protocol attacks, and resource-layer attacks."
                    ),
                    file_path=file_path,
                    line_number=line_num,
                    snippet=self._get_snippet(lines, line_num, context=3),
                    remediation=(
                        "Add Azure Front Door with WAF for DDoS protection:\n"
                        "# Azure Front Door with DDoS protection\n"
                        "resource \"azurerm_cdn_frontdoor_profile\" \"example\" {\n"
                        "  name                = \"my-frontdoor\"\n"
                        "  resource_group_name = azurerm_resource_group.example.name\n"
                        "  sku_name            = \"Premium_AzureFrontDoor\"  # Required for advanced DDoS\n"
                        "}\n\n"
                        "resource \"azurerm_cdn_frontdoor_endpoint\" \"example\" {\n"
                        "  name                     = \"my-endpoint\"\n"
                        "  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.example.id\n"
                        "}\n\n"
                        "# WAF Policy with DDoS protection rules\n"
                        "resource \"azurerm_cdn_frontdoor_firewall_policy\" \"example\" {\n"
                        "  name                              = \"mywafpolicy\"\n"
                        "  resource_group_name               = azurerm_resource_group.example.name\n"
                        "  sku_name                          = azurerm_cdn_frontdoor_profile.example.sku_name\n"
                        "  enabled                           = true\n"
                        "  mode                              = \"Prevention\"\n"
                        "  request_body_check_enabled        = true\n"
                        "  # Rate limiting for DoS protection (SC-5)\n"
                        "  custom_rule {\n"
                        "    name                           = \"RateLimitRule\"\n"
                        "    enabled                        = true\n"
                        "    priority                       = 1\n"
                        "    rate_limit_duration_in_minutes = 1\n"
                        "    rate_limit_threshold           = 100  # Max requests per minute\n"
                        "    type                           = \"RateLimitRule\"\n"
                        "    action                         = \"Block\"\n\n"
                        "    match_condition {\n"
                        "      match_variable     = \"RequestUri\"\n"
                        "      operator           = \"Contains\"\n"
                        "      match_values       = [\"/api/\"]\n"
                        "    }\n"
                        "  }\n\n"
                        "  # Managed rules for OWASP and bot protection\n"
                        "  managed_rule {\n"
                        "    type    = \"Microsoft_DefaultRuleSet\"\n"
                        "    version = \"2.1\"\n"
                        "    action  = \"Block\"\n"
                        "  }\n\n"
                        "  managed_rule {\n"
                        "    type    = \"Microsoft_BotManagerRuleSet\"\n"
                        "    version = \"1.0\"\n"
                        "    action  = \"Block\"\n"
                        "  }\n"
                        "}\n\n"
                        "# Associate WAF with endpoint\n"
                        "resource \"azurerm_cdn_frontdoor_security_policy\" \"example\" {\n"
                        "  name                     = \"my-security-policy\"\n"
                        "  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.example.id\n\n"
                        "  security_policies {\n"
                        "    firewall {\n"
                        "      cdn_frontdoor_firewall_policy_id = azurerm_cdn_frontdoor_firewall_policy.example.id\n\n"
                        "      association {\n"
                        "        domain {\n"
                        "          cdn_frontdoor_domain_id = azurerm_cdn_frontdoor_endpoint.example.id\n"
                        "        }\n"
                        "      }\n"
                        "    }\n"
                        "  }\n"
                        "}\n\n"
                        "Ref: azurerm_cdn_frontdoor_firewall_policy (https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/cdn_frontdoor_firewall_policy)\n"
                    ),
                    ksi_id=self.KSI_ID
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-CNA-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-CNA-05 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-CNA-05 compliance.
        
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
