"""
FRR-ADS-04: Uninterrupted Sharing

Providers MUST share _authorization data_ with all necessary parties without interruption, including at least FedRAMP, CISA, and agency customers. 

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


class FRR_ADS_04_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-04: Uninterrupted Sharing
    
    **Official Statement:**
    Providers MUST share _authorization data_ with all necessary parties without interruption, including at least FedRAMP, CISA, and agency customers. 
    
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
    
    FRR_ID = "FRR-ADS-04"
    FRR_NAME = "Uninterrupted Sharing"
    FRR_STATEMENT = """Providers MUST share _authorization data_ with all necessary parties without interruption, including at least FedRAMP, CISA, and agency customers. """
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "MUST"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CP-2", "Contingency Plan"),
        ("CP-6", "Alternate Storage Site"),
        ("CP-9", "System Backup"),
        ("SC-5", "Denial of Service Protection"),
    ]
    CODE_DETECTABLE = "Yes"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
        "KSI-ICP-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-04 analyzer."""
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
        Analyze Python code for FRR-ADS-04 compliance using AST.
        
        Detects uninterrupted sharing mechanisms:
        - High availability configurations
        - Redundancy/failover systems
        - Health checks and monitoring
        - Retry mechanisms
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis first
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for health check endpoints
                function_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func in function_defs:
                    func_text = parser.get_node_text(func, code_bytes).lower()
                    if any(pattern in func_text for pattern in ['health', 'liveness', 'readiness', 'heartbeat']):
                        line_num = func.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Health check endpoint detected",
                            description="Found health/liveness check for uninterrupted service",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else "",
                            recommendation="Ensure health checks monitor authorization data sharing availability."
                        ))
                
                # Look for retry/circuit breaker patterns
                decorators = parser.find_nodes_by_type(tree.root_node, 'decorator')
                for dec in decorators:
                    dec_text = parser.get_node_text(dec, code_bytes).lower()
                    if any(pattern in dec_text for pattern in ['retry', 'backoff', 'circuit_breaker', 'resilient']):
                        line_num = dec.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Resilience pattern detected",
                            description="Found retry/circuit breaker for uninterrupted sharing",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else "",
                            recommendation="Ensure resilience patterns protect authorization data sharing."
                        ))
                
                if findings:
                    return findings
        except Exception:
            pass
        
        # Regex fallback
        ha_patterns = [
            r'high.*availab',
            r'failover',
            r'redundan',
            r'load.*balanc',
            r'health.*check',
            r'retry',
            r'backoff',
            r'circuit.*breaker',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in ha_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Uninterrupted sharing mechanism detected",
                        description=f"Found HA/resilience pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure authorization data sharing is uninterrupted."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-04 compliance using AST.
        
        Detects uninterrupted sharing mechanisms in C#:
        - Health check endpoints
        - Retry policies (Polly library)
        - Circuit breaker patterns
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for health check methods
                methods = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in methods:
                    method_text = parser.get_node_text(method, code_bytes).decode('utf8').lower()
                    if any(pattern in method_text for pattern in ['health', 'liveness', 'readiness']):
                        line_num = method.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Health check endpoint detected (C#)",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else ""
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        for i, line in enumerate(lines, 1):
            if re.search(r'(health|retry|polly|circuit.*breaker)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Resilience pattern detected (C#)",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip()
                ))
                break
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-04 compliance using AST.
        
        Detects uninterrupted sharing mechanisms in Java:
        - Health check endpoints
        - Resilience4j patterns
        - Spring Boot actuator health checks
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for health check methods
                methods = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in methods:
                    method_text = parser.get_node_text(method, code_bytes).decode('utf8').lower()
                    if any(pattern in method_text for pattern in ['health', 'liveness', 'readiness']):
                        line_num = method.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Health check endpoint detected (Java)",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else ""
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        for i, line in enumerate(lines, 1):
            if re.search(r'(health|retry|resilience4j|actuator)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Resilience pattern detected (Java)",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip()
                ))
                break
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-04 compliance using AST.
        
        Detects uninterrupted sharing mechanisms in TypeScript:
        - Health check endpoints
        - Retry logic
        - Circuit breaker implementations
        """
        findings = []
        lines = code.split('\n')
        
        # Try AST-based analysis
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Look for health check routes/functions
                functions = parser.find_nodes_by_type(tree.root_node, 'function_declaration')
                functions.extend(parser.find_nodes_by_type(tree.root_node, 'method_definition'))
                
                for func in functions:
                    func_text = parser.get_node_text(func, code_bytes).decode('utf8').lower()
                    if any(pattern in func_text for pattern in ['health', 'liveness', 'readiness']):
                        line_num = func.start_point[0] + 1
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Health check endpoint detected (TypeScript)",
                            severity=Severity.INFO,
                            line_number=line_num,
                            code_snippet=lines[line_num-1] if line_num <= len(lines) else ""
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        for i, line in enumerate(lines, 1):
            if re.search(r'(health|retry|circuit.*breaker)', line, re.IGNORECASE):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Resilience pattern detected (TypeScript)",
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
        Analyze Bicep infrastructure code for FRR-ADS-04 compliance.
        
        Detects high availability and redundancy configurations:
        - Multi-region deployments
        - Availability zones
        - Load balancers
        - Traffic Manager/Front Door
        """
        findings = []
        lines = code.split('\n')
        
        # High availability patterns
        ha_resources = [
            r"resource\s+\w+\s+'Microsoft\.Network/trafficManagerProfiles",  # Traffic Manager
            r"resource\s+\w+\s+'Microsoft\.Cdn/profiles",  # Front Door
            r"resource\s+\w+\s+'Microsoft\.Network/loadBalancers",  # Load Balancer
            r"resource\s+\w+\s+'Microsoft\.Network/applicationGateways",  # App Gateway
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in ha_resources:
                if re.search(pattern, line):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="High availability resource detected",
                        description="Found HA resource for uninterrupted sharing",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure HA configuration protects authorization data sharing."
                    ))
                    break
        
        # Check for availability zones
        if re.search(r"zones\s*:\s*\[", code, re.IGNORECASE):
            for i, line in enumerate(lines, 1):
                if re.search(r"zones\s*:\s*\[", line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Availability zones configured",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip()
                    ))
                    break
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-04 compliance.
        
        Detects high availability and redundancy configurations:
        - Multi-region deployments
        - Load balancers
        - Auto-scaling groups
        """
        findings = []
        lines = code.split('\n')
        
        # HA resources
        ha_resources = [
            r'resource\s+"azurerm_traffic_manager_profile"',
            r'resource\s+"azurerm_frontdoor"',
            r'resource\s+"azurerm_lb"',  # Load Balancer
            r'resource\s+"azurerm_application_gateway"',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in ha_resources:
                if re.search(pattern, line):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="High availability resource detected",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure HA protects authorization data sharing."
                    ))
                    break
        
        # Check for zones configuration
        if re.search(r'zones\s*=\s*\[', code):
            for i, line in enumerate(lines, 1):
                if re.search(r'zones\s*=\s*\[', line):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Availability zones configured",
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
        Analyze GitHub Actions workflow for FRR-ADS-04 compliance.
        
        Detects deployment automation that ensures uninterrupted service:
        - Multi-region deployments
        - Blue-green deployments
        - Rolling updates
        - Health check verification
        """
        findings = []
        lines = code.split('\n')
        
        # Deployment patterns for uninterrupted service
        ha_patterns = [
            r'blue.*green',
            r'rolling.*update',
            r'canary.*deploy',
            r'multi.*region',
            r'health.*check',
            r'zero.*downtime',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in ha_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="HA deployment automation detected",
                        description="Found deployment pattern for uninterrupted service",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify deployment ensures uninterrupted authorization data sharing."
                    ))
                    break
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-04 compliance.
        
        Detects deployment strategies for uninterrupted service.
        """
        findings = []
        lines = code.split('\n')
        
        # HA deployment patterns
        ha_patterns = [
            r'blue.*green',
            r'rolling.*deploy',
            r'canary',
            r'multi.*region',
            r'health.*check',
            r'zero.*downtime',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in ha_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="HA deployment automation detected",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify deployment ensures uninterrupted sharing."
                    ))
                    break
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-04 compliance.
        
        Detects deployment strategies for uninterrupted service.
        """
        findings = []
        lines = code.split('\n')
        
        # HA deployment patterns
        ha_patterns = [
            r'blue.*green',
            r'rolling',
            r'canary',
            r'multi.*region',
            r'health.*check',
            r'zero.*downtime',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in ha_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="HA deployment automation detected",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Verify deployment ensures uninterrupted sharing."
                    ))
                    break
        
        return findings
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-04.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Yes',
            'automation_feasibility': 'High - Can automate detection of high availability configurations, uptime monitoring, redundancy systems, and service health checks',
            'automation_approach': 'Automated detection of uninterrupted sharing mechanisms through code analysis (health checks, retry logic, circuit breakers), infrastructure scanning (multi-region deployments, load balancers), and monitoring configuration validation',
            'evidence_artifacts': [
                'High availability architecture diagrams',
                'Uptime monitoring reports (99.9%+ availability)',
                'Load balancer and redundancy configurations',
                'Service health check implementations',
                'Disaster recovery and business continuity plans',
                'Incident response logs showing no authorization data interruptions'
            ],
            'collection_queries': [
                'Azure Monitor: Availability metrics for authorization data endpoints',
                'Load balancer logs: Traffic distribution across redundant instances',
                'Application Insights: Health check endpoint response times',
                'Resource configuration: Multi-region deployment verification',
                'Incident logs: Downtime events affecting authorization data sharing'
            ],
            'manual_validation_steps': [
                '1. Review high availability architecture for authorization data sharing endpoints',
                '2. Verify multi-region or multi-zone deployment for redundancy',
                '3. Confirm load balancers distribute traffic to prevent single points of failure',
                '4. Test failover mechanisms to ensure uninterrupted access',
                '5. Review uptime reports showing 99.9%+ availability',
                '6. Validate incident response procedures for authorization data outages'
            ],
            'recommended_services': [
                'Azure Front Door - global load balancing and failover',
                'Azure Traffic Manager - DNS-based load balancing for multi-region redundancy',
                'Azure Load Balancer - distribute traffic across availability zones',
                'Azure Monitor - uptime monitoring and availability tracking',
                'Azure Site Recovery - disaster recovery for authorization data systems'
            ],
            'azure_services': [
                'Azure Front Door (global load balancing with automatic failover)',
                'Azure Traffic Manager (DNS-based multi-region redundancy)',
                'Azure Load Balancer (zone-redundant traffic distribution)',
                'Azure Monitor (uptime monitoring and availability metrics)',
                'Azure Site Recovery (disaster recovery and business continuity)'
            ],
            'collection_methods': [
                'Automated uptime monitoring with Azure Monitor availability tests',
                'Infrastructure scanning for multi-region deployment validation',
                'Load balancer configuration analysis for redundancy verification',
                'Health check endpoint testing and response time measurement',
                'Incident log analysis to identify authorization data interruptions',
                'Disaster recovery plan review and testing validation'
            ],
            'implementation_steps': [
                '1. Deploy authorization data sharing endpoints in multiple Azure regions (East US, West US minimum)',
                '2. Configure Azure Front Door or Traffic Manager for global load balancing',
                '3. Implement health check endpoints (/health, /ready) in application code',
                '4. Set up Azure Monitor availability tests with alerts for <99.9% uptime',
                '5. Configure automatic failover to standby region if primary fails',
                '6. Test disaster recovery procedures quarterly (failover drills)',
                '7. Document RTO (Recovery Time Objective) and RPO (Recovery Point Objective) for authorization data'
            ],
            'integration_points': [
                'Azure Monitor alerts integrated with incident management system',
                'Uptime metrics exported to OSCAL SSP for FedRAMP reporting',
                'Health check endpoints monitored by external services (Pingdom, StatusPage)',
                'Disaster recovery procedures integrated with business continuity planning'
            ]
        }
    
    def get_evidence_collection_queries(self) -> List[dict]:
        """
        Get specific queries for collecting FRR-ADS-04 evidence.
        
        Returns:
            List of evidence collection queries specific to uninterrupted sharing verification
        """
        return [
            {
                'method_type': 'Uptime Monitoring',
                'name': 'Authorization Data Endpoint Availability Metrics',
                'description': 'Query Azure Monitor for uptime and availability metrics of authorization data sharing endpoints',
                'command': '''az monitor metrics list --resource "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Web/sites/{siteName}" --metric "Http2xx" --aggregation Average --interval PT1H --start-time "2024-01-01" --end-time "2024-12-31" | jq ".value[] | {timestamp: .timeseries[0].data[].timeStamp, availability: .timeseries[0].data[].average}"''',
                'purpose': 'Verify authorization data sharing endpoints maintain 99.9%+ uptime as required by FRR-ADS-04 uninterrupted sharing',
                'evidence_type': 'Uptime and availability metrics report',
                'validation_checks': [
                    'Availability metrics show >=99.9% uptime over past 12 months',
                    'No sustained outages exceeding 5 minutes',
                    'HTTP 2xx success rate >=99.9%',
                    'Mean time to recovery (MTTR) <5 minutes for incidents'
                ],
                'storage_location': 'Evidence/ADS-04/uptime-reports/'
            },
            {
                'method_type': 'Infrastructure Scan',
                'name': 'Multi-Region Redundancy Verification',
                'description': 'Scan Azure infrastructure to verify authorization data endpoints are deployed across multiple regions for redundancy',
                'command': '''az resource list --resource-type "Microsoft.Web/sites" --query "[?tags.purpose=='authorization-data'].{name:name, location:location}" | jq "group_by(.location) | length"''',
                'purpose': 'Confirm multi-region deployment to prevent single points of failure and ensure uninterrupted sharing per FRR-ADS-04',
                'evidence_type': 'Multi-region deployment configuration report',
                'validation_checks': [
                    'Authorization data endpoints deployed in at least 2 Azure regions',
                    'Regions are geographically separated (e.g., East US + West US)',
                    'Each region has redundant instances (minimum 2 per region)',
                    'Load balancer configured to distribute traffic across all regions'
                ],
                'storage_location': 'Evidence/ADS-04/infrastructure-scans/'
            },
            {
                'method_type': 'Load Balancer Analysis',
                'name': 'Traffic Distribution and Failover Configuration',
                'description': 'Analyze Azure Front Door or Traffic Manager configuration to verify automatic failover and traffic distribution',
                'command': '''az network front-door show --name {frontDoorName} --resource-group {resourceGroup} | jq ".backendPools[] | {name: .name, backends: .backends | length, healthProbeSettings: .healthProbeSettings}"''',
                'purpose': 'Validate load balancing and automatic failover ensure uninterrupted authorization data sharing per FRR-ADS-04',
                'evidence_type': 'Load balancer configuration and health probe settings',
                'validation_checks': [
                    'Load balancer distributes traffic across multiple backend instances',
                    'Health probes configured with <30 second intervals',
                    'Automatic failover enabled (unhealthy backends removed from rotation)',
                    'Minimum 2 healthy backends required at all times'
                ],
                'storage_location': 'Evidence/ADS-04/load-balancer-configs/'
            },
            {
                'method_type': 'Health Check Validation',
                'name': 'Application Health Endpoint Testing',
                'description': 'Test application health check endpoints to verify they report accurate availability status',
                'command': '''curl -s -o /dev/null -w "%{http_code}\\t%{time_total}s\\n" https://{authorizationDataEndpoint}/health | awk "{if ($1 == 200 && $2 < 1.0) print \\"PASS\\"; else print \\"FAIL\\"}"''',
                'purpose': 'Confirm health check endpoints enable load balancers to detect and route around failures, ensuring uninterrupted sharing',
                'evidence_type': 'Health check endpoint test results',
                'validation_checks': [
                    'Health endpoint returns HTTP 200 when service is healthy',
                    'Response time <1 second',
                    'Health check validates critical dependencies (database, external APIs)',
                    'Unhealthy status correctly reported when dependencies fail'
                ],
                'storage_location': 'Evidence/ADS-04/health-check-tests/'
            },
            {
                'method_type': 'Incident Log Analysis',
                'name': 'Authorization Data Interruption Incident Review',
                'description': 'Query incident management system for outages or interruptions affecting authorization data sharing',
                'command': '''az monitor activity-log list --resource-group {resourceGroup} --start-time "2024-01-01" --end-time "2024-12-31" --query "[?contains(operationName.value, \'Microsoft.Web/sites\') && (status.value==\'Failed\' || status.value==\'Degraded\')]" | jq "length"''',
                'purpose': 'Identify any interruptions to authorization data sharing and verify they were resolved within acceptable RTO',
                'evidence_type': 'Incident log and resolution report',
                'validation_checks': [
                    'Zero incidents causing >5 minutes of authorization data unavailability',
                    'All incidents have documented root cause analysis',
                    'Mean time to recovery (MTTR) <5 minutes',
                    'Corrective actions implemented to prevent recurrence'
                ],
                'storage_location': 'Evidence/ADS-04/incident-logs/'
            },
            {
                'method_type': 'Disaster Recovery Test',
                'name': 'Failover Drill and RTO Verification',
                'description': 'Execute disaster recovery failover drill to validate RTO (Recovery Time Objective) meets uninterrupted sharing requirements',
                'command': '''# Manual test procedure: 1. Simulate primary region outage, 2. Measure time to failover, 3. Verify authorization data accessible from secondary region''',
                'purpose': 'Validate disaster recovery procedures ensure authorization data sharing resumes within acceptable RTO per FRR-ADS-04',
                'evidence_type': 'Disaster recovery test report with RTO measurements',
                'validation_checks': [
                    'Failover to secondary region completes within RTO (target: <5 minutes)',
                    'Authorization data accessible from secondary region after failover',
                    'No data loss (RPO = 0 for authorization data)',
                    'Automatic failover triggers without manual intervention',
                    'Test conducted quarterly with documented results'
                ],
                'storage_location': 'Evidence/ADS-04/dr-test-reports/'
            }
        ]
    
    def get_evidence_artifacts(self) -> List[dict]:
        """
        Get list of evidence artifacts for FRR-ADS-04 compliance.
        
        Returns:
            List of evidence artifacts specific to uninterrupted sharing verification
        """
        return [
            {
                'artifact_name': 'Uptime and Availability Report',
                'artifact_type': 'Azure Monitor Metrics',
                'description': 'Report showing 99.9%+ uptime for authorization data sharing endpoints over past 12 months',
                'collection_method': 'Export Azure Monitor availability metrics, calculate uptime percentage, generate monthly report',
                'validation_checks': [
                    'Uptime >=99.9% (maximum 8.76 hours downtime per year)',
                    'Report covers all authorization data endpoints',
                    'Monthly breakdown shows consistent availability',
                    'Incidents documented with root cause and resolution time'
                ],
                'storage_location': 'Evidence/ADS-04/uptime-reports/annual-availability-report.pdf',
                'retention_period': '7 years per FedRAMP requirements'
            },
            {
                'artifact_name': 'Multi-Region Architecture Diagram',
                'artifact_type': 'Technical Architecture Documentation',
                'description': 'Diagram showing authorization data sharing infrastructure deployed across multiple Azure regions with load balancing',
                'collection_method': 'Export infrastructure configuration, generate architecture diagram using Azure Resource Visualizer or draw.io',
                'validation_checks': [
                    'Minimum 2 geographically separated Azure regions',
                    'Load balancer (Azure Front Door or Traffic Manager) distributes traffic',
                    'Each region has redundant instances (minimum 2)',
                    'Health probes monitor backend availability',
                    'Automatic failover configured between regions'
                ],
                'storage_location': 'Evidence/ADS-04/architecture/multi-region-diagram.pdf',
                'retention_period': '7 years'
            },
            {
                'artifact_name': 'Load Balancer Configuration Export',
                'artifact_type': 'Azure Resource Configuration',
                'description': 'JSON export of Azure Front Door or Traffic Manager configuration showing redundancy and failover settings',
                'collection_method': 'Use Azure CLI to export load balancer configuration: az network front-door show --name {name} --resource-group {rg} > front-door-config.json',
                'validation_checks': [
                    'Multiple backend pools configured (one per region)',
                    'Health probe settings: interval <=30 seconds, timeout <=10 seconds',
                    'Automatic failover enabled (unhealthy backends removed)',
                    'Minimum 1 healthy backend required at all times'
                ],
                'storage_location': 'Evidence/ADS-04/configurations/load-balancer-config.json',
                'retention_period': '7 years'
            },
            {
                'artifact_name': 'Health Check Endpoint Test Results',
                'artifact_type': 'Application Testing Report',
                'description': 'Results from automated testing of application health check endpoints (/health, /ready, /liveness)',
                'collection_method': 'Run automated curl tests against health endpoints, measure response times and status codes, generate pass/fail report',
                'validation_checks': [
                    'All health endpoints return HTTP 200 when healthy',
                    'Response time <1 second (target: <500ms)',
                    'Health checks validate critical dependencies (database, APIs)',
                    'Unhealthy status correctly reported during simulated failures'
                ],
                'storage_location': 'Evidence/ADS-04/testing/health-check-results.json',
                'retention_period': '7 years (monthly snapshots)'
            },
            {
                'artifact_name': 'Incident Log - Authorization Data Interruptions',
                'artifact_type': 'Incident Management Report',
                'description': 'Log of all incidents affecting authorization data sharing availability, including root cause and resolution details',
                'collection_method': 'Export incidents from Azure Monitor Activity Log and incident management system, filter for authorization data outages',
                'validation_checks': [
                    'All incidents documented with timestamp, duration, root cause',
                    'Mean time to recovery (MTTR) <5 minutes',
                    'Zero incidents causing >5 minutes of unavailability',
                    'Corrective actions documented to prevent recurrence'
                ],
                'storage_location': 'Evidence/ADS-04/incidents/interruption-log.xlsx',
                'retention_period': '7 years'
            },
            {
                'artifact_name': 'Disaster Recovery Test Report',
                'artifact_type': 'DR Testing Documentation',
                'description': 'Quarterly disaster recovery test report showing failover drill results, RTO measurements, and lessons learned',
                'collection_method': 'Execute disaster recovery failover drill, measure time to recovery, document results in structured report template',
                'validation_checks': [
                    'Failover completed within RTO (target: <5 minutes)',
                    'Authorization data accessible from secondary region after failover',
                    'No data loss during failover (RPO = 0)',
                    'Automatic failover triggered without manual intervention',
                    'Test conducted quarterly with documented results and improvements'
                ],
                'storage_location': 'Evidence/ADS-04/dr-tests/quarterly-dr-test-{YYYY-QQ}.pdf',
                'retention_period': '7 years'
            }
        ]
