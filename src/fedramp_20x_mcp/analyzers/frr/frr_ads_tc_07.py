"""
FRR-ADS-TC-07: Responsive Performance

_Trust centers_ SHOULD deliver responsive performance during normal operating conditions and minimize service disruptions.

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


class FRR_ADS_TC_07_Analyzer(BaseFRRAnalyzer):
    """
    Analyzer for FRR-ADS-TC-07: Responsive Performance
    
    **Official Statement:**
    _Trust centers_ SHOULD deliver responsive performance during normal operating conditions and minimize service disruptions.
    
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
    
    FRR_ID = "FRR-ADS-TC-07"
    FRR_NAME = "Responsive Performance"
    FRR_STATEMENT = """_Trust centers_ SHOULD deliver responsive performance during normal operating conditions and minimize service disruptions."""
    FAMILY = "ADS"
    FAMILY_NAME = "Authorization Data Sharing"
    PRIMARY_KEYWORD = "SHOULD"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    IMPACT_HIGH = True
    NIST_CONTROLS = [
        ("CP-2", "Contingency Plan"),
        ("SC-5", "Denial-of-Service Protection"),
        ("SI-10", "Information Input Validation"),
    ]
    CODE_DETECTABLE = "Yes"
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    RELATED_KSIS = [
        "KSI-AFR-01",
        "KSI-ICP-01",
    ]
    
    def __init__(self):
        """Initialize FRR-ADS-TC-07 analyzer."""
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
        Analyze Python code for FRR-ADS-TC-07 compliance using AST.
        
        Detects performance and availability mechanisms:
        - Performance monitoring
        - Service disruption minimization
        - Response time optimization
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.PYTHON)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check for performance-related functions
                func_defs = parser.find_nodes_by_type(tree.root_node, 'function_definition')
                for func_def in func_defs:
                    func_text = parser.get_node_text(func_def, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['monitor_performance', 'health_check', 'response_time', 'latency', 'availability', 'uptime']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Performance monitoring function detected",
                            description="Found function for monitoring performance or availability",
                            severity=Severity.INFO,
                            line_number=func_def.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure responsive performance and minimal service disruptions."
                        ))
                
                # Check for timeout/retry configurations
                assignments = parser.find_nodes_by_type(tree.root_node, 'assignment')
                for assignment in assignments:
                    assign_text = parser.get_node_text(assignment, code_bytes).lower()
                    if any(keyword in assign_text for keyword in ['timeout', 'retry', 'backoff', 'circuit_breaker']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Resilience configuration detected",
                            description="Found timeout/retry configuration for service disruption minimization",
                            severity=Severity.INFO,
                            line_number=assignment.start_point[0] + 1,
                            code_snippet=assign_text.split('\n')[0],
                            recommendation="Verify configuration supports responsive performance."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        performance_patterns = [
            r'performance.*monitor',
            r'response.*time',
            r'minimize.*disruption',
            r'service.*availability',
            r'health.*check',
            r'timeout',
            r'retry.*policy',
        ]
        
        for i, line in enumerate(lines, 1):
            for pattern in performance_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        frr_id=self.FRR_ID,
                        title="Performance mechanism detected",
                        description=f"Found pattern: {pattern}",
                        severity=Severity.INFO,
                        line_number=i,
                        code_snippet=line.strip(),
                        recommendation="Ensure responsive performance with minimal disruptions."
                    ))
                    break
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for FRR-ADS-TC-07 compliance using AST.
        
        Detects performance and availability mechanisms in C#.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.CSHARP)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check method declarations
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_lower = method_text.lower()
                    
                    if any(keyword in method_lower for keyword in ['monitorperformance', 'healthcheck', 'responsetime', 'latency', 'availability']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Performance monitoring method detected",
                            description="Found method for monitoring performance or availability",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure responsive performance with minimal disruptions."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:MonitorPerformance|HealthCheck|ResponseTime|Timeout|RetryPolicy)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Performance mechanism detected",
                    description="Found performance or resilience code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify responsive performance configuration."
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for FRR-ADS-TC-07 compliance using AST.
        
        Detects performance and availability mechanisms in Java.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.JAVA)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check method declarations
                method_declarations = parser.find_nodes_by_type(tree.root_node, 'method_declaration')
                for method in method_declarations:
                    method_text = parser.get_node_text(method, code_bytes)
                    method_lower = method_text.lower()
                    
                    if any(keyword in method_lower for keyword in ['monitorperformance', 'healthcheck', 'responsetime', 'latency', 'availability']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Performance monitoring method detected",
                            description="Found method for monitoring performance or availability",
                            severity=Severity.INFO,
                            line_number=method.start_point[0] + 1,
                            code_snippet=method_text.split('\n')[0],
                            recommendation="Ensure responsive performance with minimal disruptions."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:monitorPerformance|healthCheck|responseTime|timeout|retryPolicy)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Performance mechanism detected",
                    description="Found performance or resilience code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify responsive performance configuration."
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for FRR-ADS-TC-07 compliance using AST.
        
        Detects performance and availability mechanisms in TypeScript/JavaScript.
        """
        findings = []
        
        try:
            parser = ASTParser(CodeLanguage.TYPESCRIPT)
            tree = parser.parse(code)
            code_bytes = code.encode('utf8')
            
            if tree and tree.root_node:
                # Check function declarations
                function_declarations = parser.find_nodes_by_type(tree.root_node, 'function_declaration')
                for func_decl in function_declarations:
                    func_text = parser.get_node_text(func_decl, code_bytes)
                    func_lower = func_text.lower()
                    
                    if any(keyword in func_lower for keyword in ['monitorperformance', 'healthcheck', 'responsetime', 'latency', 'availability']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Performance monitoring function detected",
                            description="Found function for monitoring performance or availability",
                            severity=Severity.INFO,
                            line_number=func_decl.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Ensure responsive performance with minimal disruptions."
                        ))
                
                # Check arrow functions
                arrow_functions = parser.find_nodes_by_type(tree.root_node, 'arrow_function')
                for arrow_func in arrow_functions:
                    func_text = parser.get_node_text(arrow_func, code_bytes)
                    if any(keyword in func_text.lower() for keyword in ['performance', 'health', 'timeout', 'retry']):
                        findings.append(Finding(
                            frr_id=self.FRR_ID,
                            title="Performance handler detected",
                            description="Found handler for performance monitoring",
                            severity=Severity.INFO,
                            line_number=arrow_func.start_point[0] + 1,
                            code_snippet=func_text.split('\n')[0],
                            recommendation="Verify performance optimization."
                        ))
                
                return findings
        except Exception:
            pass
        
        # Regex fallback
        lines = code.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'(?:monitorPerformance|healthCheck|responseTime|timeout|retryPolicy)', line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Performance mechanism detected",
                    description="Found performance or resilience code",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Verify responsive performance configuration."
                ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep infrastructure code for FRR-ADS-TC-07 compliance.
        
        Detects high-availability and performance configurations.
        """
        findings = []
        lines = code.split('\n')
        
        # Check for availability zones
        availability_zones_pattern = r"zones\s*:\s*\["
        # Check for autoscaling
        autoscale_pattern = r"resource\s+\w+\s+'Microsoft\.Insights/autoscaleSettings@"
        # Check for Application Gateway with WAF
        app_gateway_pattern = r"resource\s+\w+\s+'Microsoft\.Network/applicationGateways@"
        
        for i, line in enumerate(lines, 1):
            if re.search(availability_zones_pattern, line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Availability zones configuration detected",
                    description="Found availability zones for high availability",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Availability zones help minimize service disruptions."
                ))
            
            if re.search(autoscale_pattern, line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Autoscaling configuration detected",
                    description="Found autoscale settings for responsive performance",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Autoscaling helps maintain responsive performance under load."
                ))
            
            if re.search(app_gateway_pattern, line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Application Gateway detected",
                    description="Found Application Gateway for load balancing and performance",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Application Gateway helps ensure responsive performance."
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform infrastructure code for FRR-ADS-TC-07 compliance.
        
        Detects high-availability and performance configurations.
        """
        findings = []
        lines = code.split('\n')
        
        # Check for availability zones
        availability_zones_pattern = r'availability_zones\s*='
        # Check for autoscaling
        autoscale_pattern = r'resource\s+"azurerm_monitor_autoscale_setting"'
        # Check for load balancing
        load_balancer_pattern = r'resource\s+"(?:azurerm_lb|aws_lb|google_compute_forwarding_rule)"'
        
        for i, line in enumerate(lines, 1):
            if re.search(availability_zones_pattern, line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Availability zones configuration detected",
                    description="Found availability zones for high availability",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Availability zones help minimize service disruptions."
                ))
            
            if re.search(autoscale_pattern, line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Autoscaling configuration detected",
                    description="Found autoscale settings for responsive performance",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Autoscaling helps maintain responsive performance under load."
                ))
            
            if re.search(load_balancer_pattern, line):
                findings.append(Finding(
                    frr_id=self.FRR_ID,
                    title="Load balancer detected",
                    description="Found load balancer for performance and availability",
                    severity=Severity.INFO,
                    line_number=i,
                    code_snippet=line.strip(),
                    recommendation="Load balancing helps ensure responsive performance."
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS (Regex-based)
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for FRR-ADS-TC-07 compliance.
        
        NOT APPLICABLE: Responsive performance and service disruption minimization are
        runtime application and infrastructure concerns, not CI/CD pipeline concerns.
        The requirement mandates that trust centers deliver responsive performance during
        operations, which is implemented through application architecture, infrastructure
        design (load balancing, autoscaling, availability zones), and monitoring, not
        through build or deployment automation.
        """
        return []
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for FRR-ADS-TC-07 compliance.
        
        NOT APPLICABLE: Responsive performance and service disruption minimization are
        runtime application and infrastructure concerns, not CI/CD pipeline concerns.
        The requirement mandates operational performance characteristics, which are
        implemented through application code and infrastructure configuration, not
        build or deployment automation.
        """
        return []
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for FRR-ADS-TC-07 compliance.
        
        NOT APPLICABLE: Responsive performance and service disruption minimization are
        runtime application and infrastructure concerns, not CI/CD pipeline concerns.
        The requirement mandates operational performance characteristics, which are
        implemented through application code and infrastructure configuration, not
        build or deployment automation.
        """
        return []
    
    # ============================================================================
    # EVIDENCE COLLECTION SUPPORT
    # ============================================================================
    
    def get_evidence_automation_recommendations(self) -> dict:
        """
        Get recommendations for automating evidence collection for FRR-ADS-TC-07.
        """
        return {
            'frr_id': self.FRR_ID,
            'frr_name': self.FRR_NAME,
            'code_detectable': 'Yes',
            'automation_approach': 'Automated detection through application code, infrastructure configuration analysis',
            'evidence_artifacts': [
                "performance_metrics_report.json",
                "availability_report.json",
                "health_check_logs.json",
                "autoscaling_configurations.json",
                "load_balancer_configs.json",
                "service_disruption_logs.json",
                "infrastructure_availability_zones.json",
                "performance_slo_definitions.md",
                "performance_baseline_report.pdf",
                "mttr_analysis_report.json",
            ],
            'collection_queries': [
                "AzureMetrics | where MetricName in ('ResponseTime', 'Availability') | summarize avg(Average), max(Maximum) by bin(TimeGenerated, 1h)",
                "requests | summarize avg(duration), percentile(duration, 95), percentile(duration, 99) by bin(timestamp, 1h)",
                "availabilityResults | where name == 'HealthCheck' | summarize SuccessRate=100.0*countif(success == true)/count() by bin(timestamp, 1h)",
                "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Insights/autoscalesettings",
                "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Network/loadBalancers",
                "traces | where severityLevel >= 3 and (message contains 'disruption' or message contains 'outage')",
            ],
            'manual_validation_steps': [
                "1. Review documented performance SLOs and compare to actual metrics",
                "2. Verify availability targets meet operational requirements (e.g., 99.9% uptime)",
                "3. Validate health check endpoints respond within acceptable timeframes",
                "4. Review autoscaling policies align with performance requirements",
                "5. Confirm high-availability configurations (availability zones, load balancing)",
                "6. Analyze service disruption logs and MTTR metrics",
            ],
            'recommended_services': [
                "Azure Application Insights - Detailed performance telemetry and monitoring",
                "Azure Monitor - Availability tracking and health checks",
                "Azure Load Balancer / Application Gateway - Responsive performance and high availability",
                "Azure Autoscale - Dynamic scaling for responsive performance",
                "Azure Availability Zones - Minimize service disruptions",
            ],
            'integration_points': [
                "Export performance metrics to OSCAL format for automated reporting",
                "Integrate with incident management systems for disruption tracking",
                "Connect to capacity planning tools for performance optimization",
            ]
        }
    
    def get_evidence_collection_queries(self) -> Dict[str, str]:
        """
        Get queries for collecting evidence of FRR-ADS-TC-07 compliance.
        
        Returns dict mapping query names to query strings.
        """
        return {
            "performance_metrics": "SELECT avg(duration), percentile(duration, 95) FROM requests WHERE timestamp > ago(7d)",
            "availability_percentage": "SELECT count(*) as total, countif(success == true) as successful FROM requests WHERE timestamp > ago(30d)",
            "health_check_status": "SELECT timestamp, resultCode, duration FROM availabilityResults WHERE name == 'HealthCheck' ORDER BY timestamp DESC",
            "autoscaling_config": "az monitor autoscale show --resource-group <rg> --name <autoscale-name>",
            "load_balancer_health": "az network lb probe list --resource-group <rg> --lb-name <lb-name>",
            "service_disruptions": "SELECT timestamp, message FROM traces WHERE severityLevel >= 3 AND message contains 'disruption' OR message contains 'outage'",
        }
    
    def get_evidence_artifacts(self) -> List[str]:
        """
        Get list of evidence artifacts for FRR-ADS-TC-07 compliance.
        
        Returns list of artifact filenames.
        """
        return [
            "performance_metrics_report.json",
            "availability_report.json",
            "health_check_logs.json",
            "autoscaling_configurations.json",
            "load_balancer_configs.json",
            "service_disruption_logs.json",
            "infrastructure_availability_zones.json",
            "performance_slo_definitions.md",
            "performance_baseline_report.pdf",
            "mttr_analysis_report.json",
        ]
