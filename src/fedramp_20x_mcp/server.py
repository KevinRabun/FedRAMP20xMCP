"""
FedRAMP 20x MCP Server

This module implements an MCP server that provides access to FedRAMP 20x
security requirements and controls.
"""

import asyncio
import json
import logging
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

from .data_loader import get_data_loader

# Configure logging to stderr only (MCP requirement)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)

logger = logging.getLogger(__name__)

# Initialize FastMCP server
mcp = FastMCP("FedRAMP 20x Requirements Server")

# Initialize data loader
data_loader = get_data_loader()


# Add prompts for common compliance workflows
@mcp.prompt()
async def gap_analysis() -> str:
    """
    Guide a FedRAMP gap analysis by helping identify which requirements apply 
    to your system and what evidence you need to provide.
    
    Use this prompt to:
    - Understand which FedRAMP requirements are relevant to your authorization level
    - Identify Key Security Indicators (KSI) you need to track
    - Determine what evidence and documentation is needed
    """
    return """I'll help you conduct a FedRAMP 20x gap analysis. Let's start by understanding your system:

1. **Authorization Level**: What FedRAMP authorization level are you targeting?
   - Low Impact
   - Moderate Impact
   - High Impact

2. **Service Type**: What type of cloud service are you offering?
   - SaaS (Software as a Service)
   - PaaS (Platform as a Service)
   - IaaS (Infrastructure as a Service)

3. **Current State**: Are you:
   - Starting a new FedRAMP authorization
   - Maintaining an existing authorization
   - Addressing a significant change

Based on your answers, I'll help you:
- Identify applicable requirements from all FedRAMP 20x documents
- Review Key Security Indicators (KSI) you need to track
- Understand Minimum Assessment Scope (MAS) requirements
- Check Vulnerability Detection and Response (VDR) obligations
- Review Significant Change Notification (SCN) requirements

**Next Steps**: Please share your authorization level and service type, and I'll provide tailored guidance."""


@mcp.prompt()
async def ato_package_checklist() -> str:
    """
    Generate a comprehensive checklist for preparing your FedRAMP Authorization 
    to Operate (ATO) package based on FedRAMP 20x requirements.
    
    Use this prompt to:
    - Ensure all required documentation is included
    - Verify compliance with all applicable standards
    - Prepare for assessment and authorization
    """
    return """I'll help you prepare a complete FedRAMP Authorization to Operate (ATO) package checklist.

**FedRAMP 20x Documentation Requirements**:

**1. Minimum Assessment Scope (MAS)**
   - System boundary definition
   - Information resources inventory
   - Federal customer data handling documentation
   - Third-party service dependencies

**2. Authorization Data Sharing (ADS)**
   - Access control matrix
   - Trust center documentation
   - Authorization sharing agreements

**3. FedRAMP Definitions (FRD)**
   - Verify all terminology usage aligns with official definitions
   - Document any service-specific interpretations

**4. Key Security Indicators (KSI) - 72 total indicators across:**
   - Authorization & Accreditation (AFR)
   - Cybersecurity Education (CED)
   - Commitment (CMT)
   - Change Management & Notifications (CNA)
   - Identity & Access Management (IAM)
   - Information Resources (INR)
   - Monitoring, Logging & Analysis (MLA)
   - Privacy (PIY)
   - Reporting (RPL)
   - Service Offerings (SVC)
   - Third Party Resources (TPR)

**5. Vulnerability Detection & Response (VDR)**
   - Vulnerability scanning procedures
   - Remediation timeframes by severity
   - Exception documentation
   - Agency-specific requirements

**6. Incident Communications Procedures (ICP)**
   - Incident response plan
   - Communication protocols
   - Escalation procedures

**7. Collaborative Continuous Monitoring (CCM)**
   - Quarterly review procedures
   - Continuous monitoring documentation
   - Agency collaboration processes

**8. Persistent Validation & Assessment (PVA)**
   - Assessment schedules by impact level
   - Validation procedures
   - Remediation tracking

**9. Recommended Secure Configuration (RSC)**
   - Baseline configurations
   - Configuration management procedures

**10. Significant Change Notifications (SCN)**
    - Change classification procedures
    - Notification protocols
    - Impact assessment process

**11. Using Cryptographic Modules (UCM)**
    - FIPS 140 compliance documentation
    - Cryptographic module inventory

**12. FedRAMP Security Inbox (FSI)**
    - Security inbox setup
    - Response procedures
    - Communication protocols

**What to do next**: 
1. Use the search_requirements tool to find specific details for each area
2. Use get_definition to clarify any terminology
3. Use list_ksi to review all Key Security Indicators you need to address"""


@mcp.prompt()
async def significant_change_assessment() -> str:
    """
    Assess whether a planned change to your cloud service offering requires 
    FedRAMP notification and help determine the change classification.
    
    Use this prompt to:
    - Determine if your change is routine, adaptive, or transformative
    - Understand notification requirements
    - Prepare change documentation
    """
    return """I'll help you assess your planned change and determine FedRAMP notification requirements.

**Significant Change Classification (SCN)**:

**1. Change Description**
Please describe the change you're planning:
- What systems/components are affected?
- What functionality is changing?
- When is the change scheduled?

**2. Change Categories (per FedRAMP SCN requirements)**:

**Routine/Recurring Changes**:
- Regularly scheduled updates following documented procedures
- Changes within normal operational parameters
- No substantial impact to security posture
- Examples: Patch updates, regular maintenance

**Adaptive Changes**:
- Modifications to existing functionality
- Changes in response to operational needs
- May affect some security controls
- Examples: Configuration changes, minor feature updates

**Transformative Changes**:
- Major architectural changes
- New technologies or services
- Significant impact to authorization boundary
- Examples: Major version upgrades, infrastructure changes, adding new services

**3. Impact Assessment**:
Does your change affect:
- [ ] Authorization boundary?
- [ ] Federal customer data handling?
- [ ] Security controls implementation?
- [ ] Third-party service dependencies?
- [ ] Cryptographic modules?
- [ ] Information resources in assessment scope?

**4. Notification Requirements**:
Based on your classification:
- **Routine**: Covered by continuous monitoring, no special notification
- **Adaptive**: May require notification depending on impact
- **Transformative**: Requires notification and may require re-assessment

**Next Steps**:
1. Use get_control with "FRR-SCN-*" IDs to review detailed change requirements
2. Use search_requirements with "significant change" to find related guidance
3. Document your change classification and justification
4. Prepare notification if required"""


@mcp.prompt()
async def vulnerability_remediation_timeline() -> str:
    """
    Determine the required remediation timeframes for vulnerabilities based on 
    severity and FedRAMP impact level.
    
    Use this prompt to:
    - Understand VDR timeframe requirements
    - Plan vulnerability remediation
    - Ensure compliance with FedRAMP deadlines
    """
    return """I'll help you understand FedRAMP vulnerability remediation timeframes.

**Vulnerability Detection & Response (VDR) Timeframes**:

**Question 1**: What is your FedRAMP authorization impact level?
- Low Impact
- Moderate Impact
- High Impact

**Question 2**: What is the vulnerability severity?
- Critical
- High
- Moderate
- Low

**FedRAMP VDR Timeframe Requirements**:

The remediation timeline depends on both your authorization impact level and the vulnerability severity.

**For Low Impact Systems**:
- Critical vulnerabilities: [Review FRR-VDR requirements]
- High vulnerabilities: [Review FRR-VDR requirements]
- Moderate/Low vulnerabilities: [Review FRR-VDR requirements]

**For Moderate Impact Systems**:
- Critical vulnerabilities: [Stricter timeframes]
- High vulnerabilities: [Review FRR-VDR requirements]
- Moderate/Low vulnerabilities: [Review FRR-VDR requirements]

**For High Impact Systems**:
- Critical vulnerabilities: [Strictest timeframes]
- High vulnerabilities: [Stricter requirements]
- Moderate/Low vulnerabilities: [Review FRR-VDR requirements]

**Important Considerations**:
1. **Exceptions**: Limited exceptions may apply (documented in VDR)
2. **Reporting**: Vulnerabilities must be reported through proper channels
3. **Agency Requirements**: Specific agencies may have stricter requirements
4. **Compensating Controls**: May be required while remediation is in progress

**Next Steps**:
1. Use search_requirements with "vulnerability" to find all VDR requirements
2. Use list_family_controls with "FRR" to see all VDR-related requirements
3. Review timeframe-specific requirements for your impact level
4. Document your vulnerability management and remediation procedures"""


@mcp.prompt()
async def continuous_monitoring_setup() -> str:
    """
    Set up a FedRAMP-compliant continuous monitoring program with proper 
    reporting and assessment schedules.
    
    Use this prompt to:
    - Understand continuous monitoring requirements
    - Set up reporting schedules
    - Plan assessments and reviews
    """
    return """I'll help you establish a FedRAMP-compliant continuous monitoring program.

**Continuous Monitoring Components**:

**1. Collaborative Continuous Monitoring (CCM)**
- Quarterly reviews with agencies
- Continuous authorization maintenance
- Agency-specific monitoring requirements

**2. Persistent Validation & Assessment (PVA)**
- Regular assessment schedules based on impact level
- Validation procedures
- Evidence collection and documentation

**3. Key Security Indicators (KSI) Tracking**
Track 72 indicators across 11 categories:
- Authorization & Accreditation metrics
- Cybersecurity Education completion
- Commitment to security practices
- Change Management effectiveness
- Identity & Access Management
- Information Resources management
- Monitoring, Logging & Analysis
- Privacy protection
- Reporting compliance
- Service Offerings documentation
- Third Party Resources management

**4. Monitoring Schedule**:

**Monthly Activities**:
- [ ] Vulnerability scanning
- [ ] Log review and analysis
- [ ] Incident tracking and reporting
- [ ] KSI metrics collection

**Quarterly Activities**:
- [ ] CCM reviews with agencies
- [ ] Security posture assessment
- [ ] Control effectiveness evaluation
- [ ] Significant change review

**Annual Activities**:
- [ ] Full security assessment (based on impact level)
- [ ] Authorization package update
- [ ] Third-party assessment coordination

**5. Reporting Requirements**:
- Monthly vulnerability reports
- Quarterly CCM deliverables
- Incident notifications (as they occur)
- Annual assessment reports

**Setup Steps**:
1. Use list_ksi to review all 72 Key Security Indicators
2. Use search_requirements with "monitoring" to find related requirements
3. Use get_control for specific CCM and PVA requirements
4. Document your monitoring procedures and schedules
5. Establish automated collection where possible

**Next Steps**: Would you like detailed requirements for a specific monitoring component?"""


@mcp.prompt()
async def authorization_boundary_review() -> str:
    """
    Review and validate your FedRAMP authorization boundary to ensure all 
    required information resources are included.
    
    Use this prompt to:
    - Verify authorization boundary completeness
    - Identify missing components
    - Ensure MAS compliance
    """
    return """I'll help you review your FedRAMP authorization boundary for completeness.

**Minimum Assessment Scope (MAS) Boundary Review**:

**1. Information Resources Inventory**

Must include ALL information resources that are **likely to handle federal customer data** or **likely to impact information handling**:

**Machine-Based Information Resources**:
- [ ] Application servers
- [ ] Database servers
- [ ] Web servers
- [ ] Load balancers
- [ ] Storage systems
- [ ] Network devices
- [ ] Security appliances
- [ ] Monitoring systems
- [ ] Backup systems
- [ ] Development/staging environments (if they handle customer data)

**Non-Machine-Based Information Resources**:
- [ ] Organizational policies
- [ ] Security procedures
- [ ] Employees with system access
- [ ] Training programs
- [ ] Incident response processes
- [ ] Change management procedures

**2. Third-Party Information Resources**

Document ALL third-party services:
- [ ] Cloud infrastructure providers
- [ ] SaaS tools and services
- [ ] Development tools
- [ ] Monitoring/logging services
- [ ] Identity providers
- [ ] Payment processors
- [ ] CDN providers

**3. Federal Customer Data Flow**

Trace data flow through your system:
- Where does federal customer data enter?
- What systems process or store it?
- How is it transmitted?
- Where is it backed up?
- How is it deleted/archived?

**4. Boundary Exclusions**

FedRAMP explicitly excludes certain categories (per OMB direction):
- Identify any excluded services
- Document why they're out of scope
- Verify exclusions are valid

**5. Assessment Scope Validation**

For each component, verify:
- [ ] Is it documented in the system inventory?
- [ ] Is its function clearly described?
- [ ] Are security controls identified?
- [ ] Is it included in the assessment scope?
- [ ] Are interconnections documented?

**Common Boundary Gaps**:
❌ Missing development/staging environments that process customer data
❌ Undocumented third-party services
❌ Forgotten monitoring or logging systems
❌ Backup systems not included
❌ Non-machine resources (policies, procedures, people) omitted

**Next Steps**:
1. Use search_requirements with "minimum assessment scope" or "information resource"
2. Use list_family_controls with "MAS" for detailed requirements
3. Review get_definition for "Information Resource" and "Cloud Service Offering"
4. Document any boundary additions or clarifications needed"""


@mcp.prompt()
async def initial_assessment_roadmap() -> str:
    """
    Step-by-step guide for organizations starting FedRAMP 20x authorization from scratch.
    
    Use this prompt to:
    - Understand the complete FedRAMP 20x authorization process
    - Get a phased implementation roadmap
    - Identify key milestones and dependencies
    """
    return """I'll provide a comprehensive roadmap for starting your FedRAMP 20x authorization from scratch.

# FedRAMP 20x Initial Assessment Roadmap

## Phase 1: Foundation (Weeks 1-4)

**Week 1-2: Understanding & Planning**
- [ ] Review all FedRAMP 20x standards (use list_family_controls for each)
- [ ] Identify your authorization level (Low, Moderate, High)
- [ ] Determine service categorization (SaaS, PaaS, IaaS)
- [ ] Assemble core team (CISO, compliance PM, engineering lead)
- [ ] Budget for 3PAO, tools, and staff time

**Week 3-4: Initial Scoping**
- [ ] Define authorization boundary (FRR-MAS)
- [ ] Inventory all information resources
- [ ] Document Federal Customer Data flows
- [ ] Identify third-party dependencies
- [ ] Review FRD definitions for terminology

**Deliverables**: Authorization boundary diagram, resource inventory, project charter

## Phase 2: Infrastructure & Tools (Weeks 5-12)

**Security Monitoring (Weeks 5-8)**
- [ ] Select and deploy SIEM solution (KSI-MLA-01)
- [ ] Configure log forwarding from all systems
- [ ] Set up vulnerability scanning (FRR-VDR-01)
- [ ] Implement container/code scanning
- [ ] Configure alerting and dashboards

**Identity & Access (Weeks 7-10)**
- [ ] Implement phishing-resistant MFA (KSI-IAM-01)
- [ ] Configure least-privilege IAM (KSI-IAM-05)
- [ ] Set up identity provider integration
- [ ] Document access procedures

**Automation Foundation (Weeks 9-12)**
- [ ] Implement Infrastructure as Code (KSI-MLA-05)
- [ ] Set up CI/CD pipelines (KSI-CMT-03)
- [ ] Configure automated testing
- [ ] Implement secret management (KSI-SVC-06)

**Deliverables**: Operational SIEM, vulnerability scanning, MFA, IaC

## Phase 3: Compliance Infrastructure (Weeks 13-20)

**KSI Tracking (Weeks 13-16)**
- [ ] Review all 72 KSIs (use list_ksi)
- [ ] Map KSIs to your monitoring systems
- [ ] Implement automated KSI collection
- [ ] Create KSI dashboards
- [ ] Document collection procedures

**Authorization Data Sharing API (Weeks 15-20)**
- [ ] Design API endpoints (FRR-ADS)
- [ ] Implement OSCAL format support
- [ ] Configure authentication (OAuth 2.0 or mTLS)
- [ ] Integrate with data sources
- [ ] Test with sample queries

**Continuous Monitoring Setup (Weeks 17-20)**
- [ ] Document quarterly review process (FRR-CCM-QR)
- [ ] Set up continuous vulnerability scanning
- [ ] Configure persistent validation (FRR-PVA)
- [ ] Establish agency collaboration procedures

**Deliverables**: KSI collection system, Data Sharing API, ConMon procedures

## Phase 4: Documentation (Weeks 21-28)

**Core Documentation (Weeks 21-24)**
- [ ] System Security Plan (OSCAL format)
- [ ] Vulnerability Detection & Response procedures (FRR-VDR)
- [ ] Incident Communications Procedures (FRR-ICP)
- [ ] Significant Change Notification procedures (FRR-SCN)
- [ ] All 72 KSI implementation descriptions

**Policies & Procedures (Weeks 23-26)**
- [ ] Security policies aligned to FedRAMP 20x
- [ ] Change management procedures (KSI-CMT-04)
- [ ] Incident response plan (KSI-INR-01)
- [ ] Backup and recovery plan (KSI-RPL-02)
- [ ] Training programs (KSI-CED)

**Evidence Collection (Weeks 25-28)**
- [ ] Configure automated evidence collection
- [ ] Validate all KSI metrics are being tracked
- [ ] Test Authorization Data Sharing API
- [ ] Generate sample quarterly reports
- [ ] Document evidence collection procedures

**Deliverables**: Complete SSP, all policies/procedures, evidence collection system

## Phase 5: Assessment Preparation (Weeks 29-36)

**Internal Readiness (Weeks 29-32)**
- [ ] Internal security assessment
- [ ] Gap remediation
- [ ] Evidence validation
- [ ] Practice runs with team
- [ ] Documentation review

**3PAO Selection & Engagement (Weeks 31-34)**
- [ ] Select 3PAO assessor
- [ ] Kickoff meeting
- [ ] Provide documentation
- [ ] Schedule assessment

**Assessment (Weeks 35-36)**
- [ ] 3PAO conducts assessment
- [ ] Daily standups with assessor
- [ ] Address findings in real-time
- [ ] Document any deviations

**Deliverables**: Security Assessment Report (SAR)

## Phase 6: Authorization (Weeks 37-44)

**POA&M Development (Weeks 37-38)**
- [ ] Document all findings
- [ ] Create remediation plans
- [ ] Assign ownership and timelines
- [ ] Get executive approval

**Package Submission (Weeks 39-40)**
- [ ] Compile complete ATO package
- [ ] Submit to agency/FedRAMP
- [ ] Respond to initial questions

**Authorization Review (Weeks 41-44)**
- [ ] Agency/FedRAMP reviews package
- [ ] Respond to questions
- [ ] Provide additional evidence
- [ ] Receive Authorization decision

**Deliverables**: Authorization to Operate (ATO)

## Ongoing: Continuous Monitoring (Post-Authorization)

**Daily/Automated**
- Vulnerability scanning
- Log collection and analysis
- KSI metric collection
- Change tracking

**Monthly**
- Review vulnerability findings
- Update POA&Ms
- Security control validation

**Quarterly (FRR-CCM-QR)**
- Formal quarterly review
- Update authorization package
- Share data via API
- Agency coordination

**Annual**
- Update authorization boundary
- Review significant changes
- Update risk assessment
- Plan for re-assessment

## Critical Success Factors

**1. Executive Support** (KSI-PIY-08)
- Secure budget and resources
- Get organizational buy-in
- Ensure priority status

**2. Automation First** (FRD-ALL-07: "automatically if possible")
- Automate evidence collection
- Use IaC for all infrastructure
- Implement CI/CD pipelines
- Automated compliance checking

**3. Team Skills**
- FedRAMP 20x knowledge
- Cloud-native expertise
- Security automation skills
- OSCAL format understanding

**4. Vendor Selection**
- Choose FedRAMP-ready tools
- Ensure API integration capabilities
- Verify OSCAL support
- Check for KSI alignment

## Estimated Totals

**Timeline**: 9-11 months from start to ATO
**Team Size**: 5-8 FTE during peak periods
**Budget**: $300K-800K (tools, 3PAO, staff)

## Next Steps

1. Use get_implementation_examples for specific requirements
2. Use estimate_implementation_effort to refine timeline
3. Use check_requirement_dependencies to understand relationships
4. Use search_requirements to find specific guidance

Ready to start? Let me know which phase you'd like to focus on first!"""


@mcp.prompt()
async def quarterly_review_checklist() -> str:
    """
    Structured checklist for FedRAMP 20x Collaborative Continuous Monitoring quarterly reviews.
    
    Use this prompt to:
    - Conduct quarterly reviews per FRR-CCM-QR requirements
    - Ensure all required activities are completed
    - Prepare quarterly deliverables
    """
    return """I'll guide you through the FedRAMP 20x quarterly review process.

# Quarterly Review Checklist (FRR-CCM-QR)

## Pre-Review Preparation (Week Before)

**Data Collection (FRR-CCM-QR-01 through QR-11)**
- [ ] Pull KSI metrics for the quarter (all 72 indicators)
- [ ] Generate vulnerability scan reports
- [ ] Compile incident logs
- [ ] Gather change notifications
- [ ] Review POA&M status
- [ ] Collect evidence from Authorization Data Sharing API

**Team Coordination**
- [ ] Schedule review meeting with stakeholders
- [ ] Notify authorizing agencies
- [ ] Prepare agenda
- [ ] Assign action items from last quarter

## Quarterly Review Activities

### 1. Key Security Indicators Review

**Authorization Framework (KSI-AFR-01 through AFR-11)**
- [ ] Review assessment scope for changes
- [ ] Validate KSI tracking is current
- [ ] Check authorization data sharing functionality
- [ ] Review vulnerability response metrics
- [ ] Verify change notification compliance
- [ ] Check continuous monitoring effectiveness
- [ ] Validate secure configuration baselines
- [ ] Review security inbox activity
- [ ] Check persistent validation results
- [ ] Review incident communications
- [ ] Validate cryptographic module usage

**Cybersecurity Education (KSI-CED-01 through CED-04)**
- [ ] General education completion rates
- [ ] Role-specific training completion
- [ ] Development/engineering security training
- [ ] Incident response training status

**Change Management (KSI-CMT-01 through CMT-05)**
- [ ] Review all changes logged this quarter
- [ ] Verify redeployment procedures followed
- [ ] Check automated testing coverage
- [ ] Validate change management procedures
- [ ] Review change impacts

**Cloud Native Architecture (KSI-CNA-01 through CNA-08)**
- [ ] Network traffic restrictions effective
- [ ] Attack surface minimization progress
- [ ] Traffic flow enforcement working
- [ ] Immutable infrastructure compliance
- [ ] Unwanted activity detection
- [ ] High availability metrics
- [ ] Best practices adherence
- [ ] Persistent assessment results

**Identity & Access Management (KSI-IAM-01 through IAM-07)**
- [ ] MFA usage (phishing-resistant)
- [ ] Passwordless authentication adoption
- [ ] Non-user account management
- [ ] Just-in-time authorization usage
- [ ] Least privilege validation
- [ ] Suspicious activity detections
- [ ] Automated account management effectiveness

**Incident Response (KSI-INR-01 through INR-03)**
- [ ] Review incident response procedures
- [ ] Check incident logging completeness
- [ ] Review after-action reports

**Monitoring, Logging & Analysis (KSI-MLA-01 through MLA-08)**
- [ ] SIEM operational status
- [ ] Audit logging coverage
- [ ] Infrastructure as Code usage
- [ ] Event type coverage
- [ ] Log data access controls

**Proactive Investment (KSI-PIY-01 through PIY-08)**
- [ ] Automated inventory accuracy
- [ ] Security objectives progress
- [ ] Vulnerability disclosure program status
- [ ] CISA Secure by Design alignment
- [ ] Implementation evaluation results
- [ ] Security investment effectiveness
- [ ] Supply chain risk management
- [ ] Executive support validation

**Recovery & Planning (KSI-RPL-01 through RPL-04)**
- [ ] Recovery objectives current
- [ ] Recovery plan tested this quarter
- [ ] System backups validated
- [ ] Recovery testing results

**Services (KSI-SVC-01 through SVC-10)**
- [ ] Continuous improvement activities
- [ ] Network encryption status
- [ ] Configuration automation effectiveness
- [ ] Resource integrity validation
- [ ] Secret management review
- [ ] Patching compliance rates
- [ ] Shared resource security
- [ ] Communication integrity
- [ ] Data destruction procedures

**Third-Party Risk (KSI-TPR-01 through TPR-04)**
- [ ] Supply chain risk management activities
- [ ] Supply chain risk monitoring results

### 2. Vulnerability Management Review (FRR-VDR)

**Vulnerability Scanning**
- [ ] Scan frequency maintained (continuous)
- [ ] All systems/containers/code scanned
- [ ] Scan coverage verification

**Remediation Timeframes**
- [ ] Critical/High within timeframes (7-15 days)
- [ ] Medium within timeframes (30-90 days)
- [ ] Low within timeframes (180 days)
- [ ] Exceptions properly documented (FRR-VDR-EX)

**Reporting**
- [ ] Agency-specific vulnerabilities reported
- [ ] Reporting timeframes met
- [ ] Follow-up communications documented

### 3. Significant Changes Review (FRR-SCN)

**Change Categories**
- [ ] Routine/recurring changes documented
- [ ] Administrative changes tracked
- [ ] Transformative changes assessed
- [ ] Impact changes reported
- [ ] Notifications sent to appropriate parties

### 4. Authorization Boundary Review (FRR-MAS)

- [ ] No unauthorized changes to boundary
- [ ] New components added properly
- [ ] Removed components documented
- [ ] Third-party services reviewed
- [ ] Inventory accuracy validated

### 5. Incident Review (FRR-ICP, FRR-FSI)

**Incidents This Quarter**
- [ ] All incidents logged
- [ ] Communications followed procedures
- [ ] Security Inbox used appropriately
- [ ] Agency notifications completed
- [ ] Lessons learned documented

### 6. Persistent Validation (FRR-PVA)

- [ ] Continuous validation operational
- [ ] Results reviewed and analyzed
- [ ] Issues addressed
- [ ] Validation coverage adequate

### 7. Authorization Data Sharing (FRR-ADS)

**API Functionality**
- [ ] API operational and accessible
- [ ] Authentication working properly
- [ ] Data current and accurate
- [ ] Agencies able to query successfully
- [ ] OSCAL format compliance

**Data Shared**
- [ ] System boundary information
- [ ] Vulnerability data
- [ ] KSI metrics
- [ ] Incident data
- [ ] Change notifications
- [ ] POA&M status

## Post-Review Actions

**Documentation**
- [ ] Complete quarterly review report
- [ ] Update POA&Ms with new findings
- [ ] Document any exceptions or deviations
- [ ] Record decisions and action items

**Communication**
- [ ] Share results with authorizing agencies
- [ ] Update Authorization Data Sharing API
- [ ] Notify stakeholders of significant findings
- [ ] Schedule follow-up meetings if needed

**Continuous Improvement**
- [ ] Identify process improvements
- [ ] Update procedures based on lessons learned
- [ ] Address any gaps found
- [ ] Plan next quarter's activities

## Deliverables Checklist

- [ ] Quarterly Review Report
- [ ] Updated KSI metrics dashboard
- [ ] Vulnerability scan results summary
- [ ] Incident summary report
- [ ] POA&M updates
- [ ] Change log for the quarter
- [ ] Evidence package (via Authorization Data Sharing API)
- [ ] Agency coordination notes

## Red Flags to Escalate

⚠ **Immediate escalation required if:**
- Critical/High vulnerabilities past remediation deadline
- Unauthorized boundary changes
- Security incidents not properly reported
- KSI metrics showing degradation
- Authorization Data Sharing API unavailable
- Required training completion below threshold
- Significant changes not properly notified

## Next Quarter Planning

- [ ] Review upcoming system changes
- [ ] Plan security improvements
- [ ] Schedule next quarterly review
- [ ] Assign preparatory tasks
- [ ] Update calendar reminders

Use search_requirements to find specific requirement details for any area needing deeper investigation."""


@mcp.prompt()
async def api_design_guide() -> str:
    """
    Guide for designing your Authorization Data Sharing API per FRR-ADS requirements.
    
    Use this prompt to:
    - Design compliant data sharing APIs
    - Implement OSCAL format support
    - Set up proper authentication and authorization
    """
    return """I'll help you design your FedRAMP 20x Authorization Data Sharing API.

# Authorization Data Sharing API Design Guide (FRR-ADS)

## Overview

FedRAMP 20x requires CSPs to share authorization data via API rather than document uploads. This API must provide machine-readable access to your security posture.

## Required Endpoints

### 1. System Information
```
GET /api/v1/system
GET /api/v1/authorization-boundary
GET /api/v1/system-characteristics
```

**Response Format (OSCAL SSP):**
```json
{
  "system-security-plan": {
    "uuid": "12345678-1234-1234-1234-123456789abc",
    "metadata": {
      "title": "My Cloud Service SSP",
      "last-modified": "2025-11-26T10:00:00Z",
      "version": "1.2.0",
      "oscal-version": "1.1.2"
    },
    "system-characteristics": {
      "system-ids": [...],
      "system-name": "My Cloud Service",
      "description": "...",
      "security-sensitivity-level": "moderate",
      "authorization-boundary": {
        "description": "...",
        "diagrams": [...],
        "remarks": "..."
      }
    },
    "system-implementation": {
      "users": [...],
      "components": [...],
      "leveraged-authorizations": [...]
    }
  }
}
```

### 2. Vulnerability Data
```
GET /api/v1/vulnerabilities
GET /api/v1/vulnerabilities?status=open
GET /api/v1/vulnerabilities?severity=high
GET /api/v1/vulnerabilities/{vuln-id}
```

**Response Format:**
```json
{
  "vulnerabilities": [
    {
      "id": "vuln-2025-001",
      "cve_id": "CVE-2025-12345",
      "severity": "HIGH",
      "cvss_score": 8.5,
      "discovered_date": "2025-11-20",
      "status": "remediation_in_progress",
      "remediation_deadline": "2025-11-27",
      "affected_components": ["web-server-prod-01"],
      "description": "...",
      "remediation_plan": "..."
    }
  ],
  "metadata": {
    "total_count": 45,
    "open_count": 12,
    "last_scan": "2025-11-26T08:00:00Z"
  }
}
```

### 3. Key Security Indicators
```
GET /api/v1/ksi
GET /api/v1/ksi/{category}
GET /api/v1/ksi/{ksi-id}
GET /api/v1/ksi/metrics?start_date=2025-10-01&end_date=2025-12-31
```

**Response Format:**
```json
{
  "ksi_metrics": [
    {
      "id": "KSI-IAM-01",
      "name": "Phishing-Resistant MFA",
      "status": "compliant",
      "metric_value": "100%",
      "measurement_date": "2025-11-26",
      "details": {
        "total_users": 150,
        "users_with_mfa": 150,
        "mfa_type": "FIDO2"
      },
      "evidence": {
        "type": "automated_report",
        "location": "https://evidencestorage.blob.core.windows.net/reports/iam-mfa-report-2025-11.pdf"
      }
    }
  ]
}
```

### 4. Incidents
```
GET /api/v1/incidents
GET /api/v1/incidents?start_date=2025-10-01
GET /api/v1/incidents/{incident-id}
```

**Response Format:**
```json
{
  "incidents": [
    {
      "id": "INC-2025-003",
      "type": "security_event",
      "severity": "medium",
      "detected_date": "2025-11-15T14:30:00Z",
      "resolved_date": "2025-11-15T18:45:00Z",
      "affected_agencies": [],
      "description": "Suspicious login attempts detected",
      "response_actions": "Account locked, investigation completed",
      "status": "closed"
    }
  ]
}
```

### 5. Changes
```
GET /api/v1/changes
GET /api/v1/changes?type=significant
GET /api/v1/changes/{change-id}
```

**Response Format:**
```json
{
  "changes": [
    {
      "id": "CHG-2025-042",
      "type": "transformative",
      "date": "2025-11-20",
      "description": "Added new microservice for analytics",
      "impact_assessment": "New component added to boundary",
      "notification_sent": true,
      "notification_date": "2025-11-20",
      "approvals": [...]
    }
  ]
}
```

### 6. POA&M
```
GET /api/v1/poam
GET /api/v1/poam?status=open
GET /api/v1/poam/{poam-id}
```

**Response Format (OSCAL POA&M):**
```json
{
  "plan-of-action-and-milestones": {
    "uuid": "...",
    "metadata": {...},
    "poam-items": [
      {
        "uuid": "...",
        "title": "Implement automated log forwarding",
        "description": "...",
        "risk-statement": "...",
        "remediation-tracking": {
          "tracking-entry": [
            {
              "date-time-stamp": "2025-11-26T10:00:00Z",
              "title": "Initial identification",
              "description": "..."
            }
          ]
        }
      }
    ]
  }
}
```

## Authentication & Authorization

### Option 1: OAuth 2.0 (Recommended for Multiple Consumers)

**Flow:**
```
1. Agency registers as OAuth client with FedRAMP
2. FedRAMP provides client_id and client_secret
3. Agency requests token:
   POST /oauth/token
   {
     "grant_type": "client_credentials",
     "client_id": "agency-xyz",
     "client_secret": "..."
   }
4. Use token in requests:
   GET /api/v1/system
   Authorization: Bearer {token}
```

**Implementation:**
```python
# Using FastAPI + OAuth2
from fastapi import FastAPI, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/api/v1/system")
async def get_system(token: str = Depends(oauth2_scheme)):
    # Validate token
    client = validate_token(token)
    if not client:
        raise HTTPException(status_code=401)
    
    # Return system data
    return get_system_data()
```

### Option 2: Mutual TLS (mTLS) (Recommended for High Security)

**Configuration:**
```
1. FedRAMP/Agency provides client certificate
2. Configure API to require client certificates
3. Validate certificate on each request
```

**Nginx Configuration:**
```nginx
server {
    listen 443 ssl;
    server_name api.myservice.com;
    
    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;
    
    # Require client certificate
    ssl_client_certificate /etc/nginx/ssl/ca.crt;
    ssl_verify_client on;
    
    location /api/ {
        proxy_pass http://backend;
        proxy_set_header X-SSL-Client-Cert $ssl_client_cert;
    }
}
```

## Access Control

**Principle: Least Privilege**

Different consumers should have different access levels:

```json
{
  "client_id": "fedramp-pmo",
  "permissions": [
    "read:system",
    "read:vulnerabilities", 
    "read:ksi",
    "read:incidents",
    "read:changes",
    "read:poam"
  ]
},
{
  "client_id": "agency-xyz",
  "permissions": [
    "read:system",
    "read:vulnerabilities",
    "read:incidents:agency-xyz",  // Only their incidents
    "read:ksi"
  ]
}
```

## API Versioning

**Use URL versioning:**
```
/api/v1/system  (current)
/api/v2/system  (future)
```

**Include version in responses:**
```json
{
  "api_version": "1.0.0",
  "data": {...}
}
```

## Rate Limiting

**Recommended limits:**
```
- Per client: 1000 requests/hour
- Per endpoint: 100 requests/minute
- Burst: Allow 10 requests/second
```

**Headers:**
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 850
X-RateLimit-Reset: 1701014400
```

## Error Handling

**Standard error format:**
```json
{
  "error": {
    "code": "unauthorized",
    "message": "Invalid or expired token",
    "details": "Token expired at 2025-11-26T10:00:00Z",
    "timestamp": "2025-11-26T12:30:00Z",
    "request_id": "req-abc-123"
  }
}
```

## Monitoring & Logging

**Log all API access:**
```json
{
  "timestamp": "2025-11-26T10:00:00Z",
  "client_id": "fedramp-pmo",
  "endpoint": "/api/v1/vulnerabilities",
  "method": "GET",
  "status_code": 200,
  "response_time_ms": 145,
  "user_agent": "FedRAMP-Client/1.0"
}
```

**Alert on:**
- Repeated authentication failures
- Unusual access patterns
- High error rates
- Slow response times

## Testing

**Provide test credentials:**
```
Test API endpoint: https://api-test.myservice.com
Client ID: test-client
Client Secret: (provided securely)
```

**Sample queries:**
```bash
# Test authentication
curl -X POST https://api-test.myservice.com/oauth/token \
  -d "grant_type=client_credentials&client_id=test-client&client_secret=..."

# Test system endpoint
curl https://api-test.myservice.com/api/v1/system \
  -H "Authorization: Bearer {token}"

# Test vulnerabilities
curl https://api-test.myservice.com/api/v1/vulnerabilities?status=open \
  -H "Authorization: Bearer {token}"
```

## Documentation

**Provide OpenAPI/Swagger spec:**
```yaml
openapi: 3.0.0
info:
  title: Authorization Data Sharing API
  version: 1.0.0
  description: FedRAMP 20x compliant API for sharing authorization data

servers:
  - url: https://api.myservice.com
    description: Production API

paths:
  /api/v1/system:
    get:
      summary: Get system information
      security:
        - oauth2: [read:system]
      responses:
        '200':
          description: System information in OSCAL format
```

## Implementation Checklist

- [ ] Choose authentication method (OAuth 2.0 or mTLS)
- [ ] Implement all required endpoints
- [ ] Use OSCAL format where applicable
- [ ] Add proper error handling
- [ ] Implement rate limiting
- [ ] Add comprehensive logging
- [ ] Write API documentation (OpenAPI)
- [ ] Create test credentials
- [ ] Test with FedRAMP/agency
- [ ] Monitor API usage and performance

Use get_implementation_examples('FRR-ADS-01') for more detailed implementation guidance."""


@mcp.prompt()
async def ksi_implementation_priorities() -> str:
    """
    Help prioritize which Key Security Indicators to implement first based on impact and dependencies.
    
    Use this prompt to:
    - Understand KSI implementation order
    - Identify quick wins vs. long-term investments
    - Plan phased KSI rollout
    """
    return """I'll help you prioritize the implementation of FedRAMP 20x's 72 Key Security Indicators.

# KSI Implementation Priority Guide

## Priority 1: Foundation (Weeks 1-8)
**Must be completed first - other KSIs depend on these**

### Critical Infrastructure
1. **KSI-MLA-01: SIEM** ⭐ HIGHEST PRIORITY
   - Why: Required for logging all other KSIs
   - Impact: Blocks 15+ other KSIs
   - Effort: 6-12 weeks
   - Dependencies: None

2. **KSI-IAM-01: Phishing-Resistant MFA** ⭐ HIGH PRIORITY
   - Why: Security foundation, quick win
   - Impact: Protects all access
   - Effort: 2-4 weeks
   - Dependencies: None

3. **KSI-PIY-01: Automated Inventory**
   - Why: Needed to track what you're securing
   - Impact: Required for boundary management
   - Effort: 3-4 weeks
   - Dependencies: None

4. **KSI-MLA-02: Audit Logging**
   - Why: Foundation for compliance evidence
   - Impact: Enables incident investigation
   - Effort: 2-3 weeks
   - Dependencies: KSI-MLA-01 (SIEM)

## Priority 2: Security Controls (Weeks 4-12)
**Core security capabilities**

### Vulnerability Management
5. **KSI-AFR-04: Vulnerability Detection and Response** (ties to FRR-VDR)
   - Why: Required for continuous scanning
   - Impact: Critical for compliance
   - Effort: 4-8 weeks
   - Dependencies: None

6. **KSI-SVC-07: Patching**
   - Why: Vulnerability remediation
   - Impact: Keeps systems secure
   - Effort: 3-6 weeks
   - Dependencies: KSI-AFR-04, automated deployment

### Access Management
7. **KSI-IAM-05: Least Privilege**
   - Why: Limits blast radius
   - Impact: Reduces risk across all systems
   - Effort: 4-6 weeks
   - Dependencies: KSI-IAM-01, KSI-PIY-01

8. **KSI-IAM-06: Suspicious Activity Detection**
   - Why: Threat detection
   - Impact: Early incident detection
   - Effort: 3-4 weeks
   - Dependencies: KSI-MLA-01 (SIEM)

### Secret Management
9. **KSI-SVC-06: Secret Management**
   - Why: Prevents credential exposure
   - Impact: Critical security control
   - Effort: 4-6 weeks
   - Dependencies: None

## Priority 3: Automation & Operations (Weeks 8-16)
**Improve efficiency and reduce manual work**

### Infrastructure as Code
10. **KSI-MLA-05: Infrastructure as Code**
    - Why: Enables repeatability and audit
    - Impact: Foundation for automation
    - Effort: 6-10 weeks
    - Dependencies: None

11. **KSI-SVC-04: Configuration Automation**
    - Why: Consistent, auditable configs
    - Impact: Reduces drift, improves security
    - Effort: 4-6 weeks
    - Dependencies: KSI-MLA-05

### CI/CD Integration
12. **KSI-CMT-03: Automated Testing and Validation**
    - Why: Quality and security gates
    - Impact: Prevents bad deployments
    - Effort: 4-8 weeks
    - Dependencies: CI/CD pipeline

13. **KSI-CMT-01: Log and Monitor Changes**
    - Why: Change tracking and audit
    - Impact: Required for FRR-SCN compliance
    - Effort: 2-4 weeks
    - Dependencies: KSI-MLA-01 (SIEM)

## Priority 4: Cloud-Native Security (Weeks 10-18)
**For containerized/Kubernetes environments**

### Network Security
14. **KSI-CNA-01: Restrict Network Traffic**
    - Why: Defense in depth
    - Impact: Limits lateral movement
    - Effort: 3-5 weeks
    - Dependencies: Network mapping

15. **KSI-CNA-03: Enforce Traffic Flow**
    - Why: Network segmentation
    - Impact: Contains breaches
    - Effort: 4-6 weeks
    - Dependencies: KSI-CNA-01

16. **KSI-CNA-04: Immutable Infrastructure**
    - Why: Prevents tampering
    - Impact: Improves security posture
    - Effort: 6-10 weeks
    - Dependencies: KSI-MLA-05 (IaC)

### Continuous Assessment
17. **KSI-CNA-08: Persistent Assessment and Automated Enforcement**
    - Why: Real-time compliance checking
    - Impact: Continuous validation
    - Effort: 6-8 weeks
    - Dependencies: Policy engine (OPA/Kyverno)

## Priority 5: Incident Response (Weeks 12-20)
**Detection and response capabilities**

### Incident Management
18. **KSI-INR-01: Incident Response Procedure**
    - Why: Required for compliance
    - Impact: Effective incident handling
    - Effort: 3-4 weeks
    - Dependencies: None

19. **KSI-INR-02: Incident Logging**
    - Why: Evidence and investigation
    - Impact: Post-incident analysis
    - Effort: 2-3 weeks
    - Dependencies: KSI-MLA-01 (SIEM)

20. **KSI-INR-03: Incident After Action Reports**
    - Why: Continuous improvement
    - Impact: Learn from incidents
    - Effort: 1-2 weeks
    - Dependencies: KSI-INR-01, KSI-INR-02

## Priority 6: Business Continuity (Weeks 14-22)
**Resilience and recovery**

### Backup & Recovery
21. **KSI-RPL-01: Recovery Objectives**
    - Why: Define RTO/RPO
    - Impact: Business continuity planning
    - Effort: 2-3 weeks
    - Dependencies: Business analysis

22. **KSI-RPL-03: System Backups**
    - Why: Data protection
    - Impact: Recovery capability
    - Effort: 3-5 weeks
    - Dependencies: KSI-RPL-01

23. **KSI-RPL-02: Recovery Plan**
    - Why: Documented procedures
    - Impact: Faster recovery
    - Effort: 3-4 weeks
    - Dependencies: KSI-RPL-01, KSI-RPL-03

24. **KSI-RPL-04: Recovery Testing**
    - Why: Validate backup/recovery works
    - Impact: Confidence in recovery
    - Effort: 2-4 weeks (quarterly)
    - Dependencies: KSI-RPL-02, KSI-RPL-03

## Priority 7: Governance & Culture (Weeks 16-28)
**Organizational capabilities**

### Education
25. **KSI-CED-01: General Education**
    - Why: Security awareness baseline
    - Impact: Reduces human error
    - Effort: 4-6 weeks (initial setup)
    - Dependencies: Training platform

26. **KSI-CED-02: Role-Specific Education**
    - Why: Targeted training
    - Impact: Better security practices
    - Effort: 4-8 weeks
    - Dependencies: KSI-CED-01

27. **KSI-CED-03: Development and Engineering Education**
    - Why: Secure coding practices
    - Impact: Fewer vulnerabilities
    - Effort: 3-6 weeks
    - Dependencies: KSI-CED-01

### Supply Chain
28. **KSI-PIY-07: Supply Chain Risk Management**
    - Why: Third-party risk
    - Impact: Vendor security
    - Effort: 6-10 weeks
    - Dependencies: Vendor assessment process

29. **KSI-TPR-04: Supply Chain Risk Monitoring**
    - Why: Ongoing vendor oversight
    - Impact: Continuous third-party risk
    - Effort: 4-6 weeks
    - Dependencies: KSI-PIY-07

### Executive Support
30. **KSI-PIY-08: Executive Support**
    - Why: Resources and priority
    - Impact: Project success
    - Effort: Ongoing
    - Dependencies: Business case

## Priority 8: Advanced Capabilities (Weeks 20-32)
**Nice-to-have and advanced features**

### Additional Security
31. **KSI-IAM-02: Passwordless Authentication**
    - Why: Better UX and security
    - Impact: Reduces password attacks
    - Effort: 6-10 weeks
    - Dependencies: KSI-IAM-01

32. **KSI-IAM-04: Just-in-Time Authorization**
    - Why: Temporary elevated access
    - Impact: Reduces standing privileges
    - Effort: 8-12 weeks
    - Dependencies: KSI-IAM-05

33. **KSI-SVC-02: Network Encryption**
    - Why: Data in transit protection
    - Impact: Confidentiality
    - Effort: 2-4 weeks
    - Dependencies: TLS/mTLS implementation

## Quick Wins (Can be done anytime)
**Low effort, high visibility**

- **KSI-AFR-08: FedRAMP Security Inbox** (1-2 days)
  - Set up email forwarding to security inbox

- **KSI-PIY-03: Vulnerability Disclosure Program** (1-2 weeks)
  - Create security.txt, disclosure policy

- **KSI-SVC-10: Data Destruction** (2-3 weeks)
  - Document and implement data deletion procedures

- **KSI-CMT-04: Change Management Procedure** (2-3 weeks)
  - Document existing change process

## Implementation Strategy

### Phase 1 (Months 1-3): Foundation
Focus on Priority 1-2 KSIs
- SIEM (KSI-MLA-01) ← Start immediately
- MFA (KSI-IAM-01) ← Parallel track
- Vulnerability scanning (KSI-AFR-04) ← Week 4
- Basic logging (KSI-MLA-02) ← Week 6

### Phase 2 (Months 4-6): Core Security
Priority 3-4 KSIs
- IaC (KSI-MLA-05)
- Secret management (KSI-SVC-06)
- Network controls (KSI-CNA-01, CNA-03)
- Automated testing (KSI-CMT-03)

### Phase 3 (Months 7-9): Operations
Priority 5-6 KSIs
- Incident response (KSI-INR-01, INR-02, INR-03)
- Backup/recovery (KSI-RPL-01 through RPL-04)
- Change tracking (KSI-CMT-01)

### Phase 4 (Months 10-12): Maturity
Priority 7-8 KSIs
- Training programs (KSI-CED)
- Supply chain management (KSI-PIY-07, TPR-04)
- Advanced IAM (KSI-IAM-02, IAM-04)

## Dependencies to Watch

**Blockers:**
- No SIEM = Can't implement 15+ other KSIs
- No IaC = Can't implement immutable infrastructure
- No CI/CD = Can't implement automated testing

**Common Mistakes:**
❌ Starting with advanced KSIs before foundation
❌ Trying to implement all 72 simultaneously
❌ Ignoring dependencies between KSIs
❌ Not allocating enough time for SIEM

**Success Patterns:**
✓ Start with SIEM and MFA in parallel
✓ Build automation early (IaC, CI/CD)
✓ Focus on one category at a time
✓ Collect evidence as you go

## Resource Allocation

**Minimum Team:**
- 1 Security Engineer (SIEM, vulnerability management)
- 1 DevOps/SRE (automation, IaC)
- 1 IAM Specialist (MFA, access controls)
- 1 Compliance PM (coordination, documentation)

**Peak Team (Months 4-8):**
Add 2-3 more engineers for parallel workstreams

Use list_ksi to see all 72 indicators, and get_ksi(ksi_id) for detailed requirements."""


@mcp.prompt()
async def vendor_evaluation() -> str:
    """
    Questions to ask vendors and tools to ensure FedRAMP 20x compatibility.
    
    Use this prompt to:
    - Evaluate security tools for FedRAMP 20x compliance
    - Assess third-party service providers
    - Identify gaps in vendor capabilities
    """
    return """I'll help you evaluate vendors and tools for FedRAMP 20x compatibility.

# Vendor/Tool Evaluation Guide for FedRAMP 20x

## General Vendor Questions

### FedRAMP Awareness
1. Is your product/service FedRAMP authorized?
   - If yes, at what impact level? (Low/Moderate/High)
   - What's your FedRAMP authorization date?
   - Are you familiar with FedRAMP 20x changes from Rev 5?

2. Do you have customers who use your product for FedRAMP compliance?
   - Can you provide references?
   - What FedRAMP 20x standards do they use your product for?

### Data Handling
3. Does your service handle Federal Customer Data?
   - Where is data stored geographically?
   - Is data encrypted at rest and in transit?
   - Can you provide data residency guarantees?

4. What is your data retention and deletion policy?
   - Can you delete data on demand? (KSI-SVC-10)
   - Do you provide certificates of destruction?

## Category-Specific Questions

### SIEM / Security Monitoring Tools (KSI-MLA-01)

**Required Capabilities:**
- [ ] Can ingest logs from all our sources (cloud, on-prem, containers)?
- [ ] Supports structured logging (JSON)?
- [ ] Can retain logs for 1+ years?
- [ ] Provides API access to log data?
- [ ] Supports automated alerting?
- [ ] Can generate compliance reports?
- [ ] OSCAL format support or export capability?

**FedRAMP 20x Specific:**
- [ ] Can track all 72 KSI metrics?
- [ ] Can provide data for Authorization Data Sharing API (FRR-ADS)?
- [ ] Supports continuous monitoring (FRR-CCM)?
- [ ] Can generate quarterly review reports?

**Questions to Ask:**
- What's your typical log ingestion rate capability?
- Do you offer government regions/dedicated instances?
- Can you integrate with our Authorization Data Sharing API?
- What's your SLA for log availability?

**Top Vendors:**
- Microsoft Sentinel (FedRAMP authorized, Azure-native)
- Splunk Cloud (FedRAMP authorized)
- Datadog (FedRAMP authorized)
- Sumo Logic (FedRAMP authorized)

### Vulnerability Scanning Tools (FRR-VDR, KSI-AFR-04)

**Required Capabilities:**
- [ ] Continuous/automated scanning?
- [ ] Covers infrastructure, containers, and code?
- [ ] Provides CVSS scores and remediation guidance?
- [ ] Can scan on-demand and scheduled?
- [ ] API access to vulnerability data?
- [ ] Integrates with ticketing systems?
- [ ] Supports exception management (FRR-VDR-EX)?

**FedRAMP 20x Specific:**
- [ ] Can track remediation timeframes by severity (FRR-VDR-TF)?
- [ ] Provides data for Authorization Data Sharing API?
- [ ] Supports agency-specific vulnerability reporting (FRR-VDR-RP)?

**Questions to Ask:**
- How often can we scan without impacting performance?
- Do you support scanning ephemeral containers?
- Can you scan during CI/CD pipeline?
- What's the false positive rate?
- How do you handle zero-day vulnerabilities?

**Top Vendors:**
- Microsoft Defender for Cloud (FedRAMP authorized, Azure-native)
- Tenable.io (FedRAMP authorized)
- Qualys (FedRAMP authorized)
- Snyk (code and container scanning)
- Trivy (open source, container scanning)

### Identity & Access Management (KSI-IAM)

**Required Capabilities:**
- [ ] Phishing-resistant MFA (FIDO2/WebAuthn)? (KSI-IAM-01)
- [ ] Supports passwordless authentication? (KSI-IAM-02)
- [ ] Provides detailed audit logs? (KSI-MLA-02)
- [ ] Supports conditional access policies?
- [ ] Can integrate with all your applications?
- [ ] API access for user management?

**FedRAMP 20x Specific:**
- [ ] Can enforce least privilege? (KSI-IAM-05)
- [ ] Detects suspicious activity? (KSI-IAM-06)
- [ ] Supports just-in-time access? (KSI-IAM-04)
- [ ] Can provide MFA compliance data for KSI tracking?

**Questions to Ask:**
- What MFA methods do you support? (must include FIDO2)
- Can you disable SMS/TOTP for privileged accounts?
- How do you handle service account authentication?
- What's your session timeout capability?
- Can you export IAM events to our SIEM?

**Top Vendors:**
- Microsoft Entra ID (formerly Azure AD, FedRAMP authorized, Azure-native)
- Okta (FedRAMP authorized)
- Ping Identity (FedRAMP authorized)

### Secret Management (KSI-SVC-06)

**Required Capabilities:**
- [ ] Encrypted storage of secrets?
- [ ] Automatic secret rotation?
- [ ] Access audit logs?
- [ ] API access for applications?
- [ ] Integration with CI/CD pipelines?
- [ ] Emergency access procedures?

**FedRAMP 20x Specific:**
- [ ] Can provide secret access logs to SIEM?
- [ ] Supports automated secret rotation?
- [ ] Can track secret usage for KSI metrics?

**Questions to Ask:**
- How are secrets encrypted (algorithm, key management)?
- Do you support dynamic secrets?
- Can you integrate with our cloud provider's KMS?
- What happens if your service is unavailable?
- Can secrets be backed up securely?

**Top Vendors:**
- Azure Key Vault (FedRAMP authorized, Azure-native)
- HashiCorp Vault (FedRAMP authorized)
- CyberArk (FedRAMP authorized)

### Cloud Infrastructure (KSI-CNA, KSI-SVC)

**Required Capabilities:**
- [ ] Network isolation/segmentation?
- [ ] Encryption at rest and in transit?
- [ ] Immutable infrastructure support?
- [ ] API-driven management?
- [ ] Compliance certifications?
- [ ] Logging and monitoring built-in?

**FedRAMP 20x Specific:**
- [ ] Supports Infrastructure as Code? (KSI-MLA-05)
- [ ] Can restrict network traffic programmatically? (KSI-CNA-01)
- [ ] Provides high availability options? (KSI-CNA-06)
- [ ] Supports immutable deployments? (KSI-CNA-04)

**Questions to Ask:**
- What FedRAMP impact levels are authorized?
- Do you offer government-only regions?
- Can you provide dedicated infrastructure?
- What's your SLA and how is it measured?
- How do you handle data sovereignty?

**Top Vendors:**
- Azure Government (FedRAMP High, recommended for Azure workloads)
- Azure Commercial (FedRAMP High for many services)
- AWS GovCloud (FedRAMP High)
- Google Cloud (FedRAMP High)

### Backup & Disaster Recovery (KSI-RPL)

**Required Capabilities:**
- [ ] Automated backups?
- [ ] Point-in-time recovery?
- [ ] Encrypted backups?
- [ ] Off-site/geo-redundant storage?
- [ ] Regular restore testing?
- [ ] Documented RTO/RPO?

**FedRAMP 20x Specific:**
- [ ] Can meet your recovery objectives? (KSI-RPL-01)
- [ ] Supports automated recovery testing? (KSI-RPL-04)
- [ ] Provides backup success metrics for KSI tracking?

**Questions to Ask:**
- What's your guaranteed RTO and RPO?
- How often are backups tested?
- Can we perform test restores on-demand?
- Where are backups stored geographically?
- What's the retention period?

**Top Vendors:**
- Azure Backup (FedRAMP authorized, Azure-native)
- Azure Site Recovery (FedRAMP authorized, for DR)
- Veeam (FedRAMP authorized)
- Druva (FedRAMP authorized)

### CI/CD & DevOps Tools (KSI-CMT)

**Required Capabilities:**
- [ ] Security scanning in pipeline?
- [ ] Automated testing support?
- [ ] Audit logs of all deployments?
- [ ] Rollback capabilities?
- [ ] Integration with secrets management?
- [ ] Infrastructure as Code support?

**FedRAMP 20x Specific:**
- [ ] Can log all changes for tracking? (KSI-CMT-01)
- [ ] Supports automated testing? (KSI-CMT-03)
- [ ] Can provide deployment metrics for KSI tracking?
- [ ] Integrates with change notification system (FRR-SCN)?

**Questions to Ask:**
- Can you block deployments based on security findings?
- How do you handle secrets in CI/CD?
- What's your audit log retention?
- Can you integrate with our SIEM?
- Do you support deployment approvals?

**Top Vendors:**
- Azure DevOps (FedRAMP authorized, Azure-native)
- GitHub Actions (with FedRAMP-authorized runners, Microsoft-owned)
- GitLab (FedRAMP authorized)
- Jenkins (self-hosted)

## Third-Party Service Provider Evaluation

### Supply Chain Risk (KSI-PIY-07, KSI-TPR-04)

**Due Diligence Questions:**
1. Security Posture
   - [ ] Do you have SOC 2 Type II certification?
   - [ ] Are you FedRAMP authorized?
   - [ ] Do you have ISO 27001 certification?
   - [ ] When was your last security assessment?

2. Incident Response
   - [ ] What's your incident notification timeframe?
   - [ ] Have you had breaches in the last 3 years?
   - [ ] Can you provide incident response reports?

3. Data Protection
   - [ ] How do you protect Federal Customer Data?
   - [ ] What encryption do you use?
   - [ ] Who has access to our data?
   - [ ] Can you segregate our data from other customers?

4. Monitoring & Logging
   - [ ] Can you provide logs of access to our data?
   - [ ] How long do you retain logs?
   - [ ] Can we access logs via API?

5. Business Continuity
   - [ ] What's your uptime SLA?
   - [ ] What's your disaster recovery plan?
   - [ ] Have you tested recovery procedures?

6. Vendor Management
   - [ ] Do you use fourth-party vendors?
   - [ ] How do you manage supply chain risk?
   - [ ] Can you provide a list of subprocessors?

## Evaluation Scorecard Template

```
Vendor Name: __________________
Product/Service: __________________
Date: __________________

Category: [SIEM | Vulnerability | IAM | Secrets | Cloud | Backup | CI/CD | Other]

Scoring: 0=No, 1=Partial, 2=Yes, N/A=Not Applicable

FedRAMP Readiness:
[ ] FedRAMP authorized (2)
[ ] FedRAMP ready (1)
[ ] In process (1)
[ ] No plans (0)

Technical Capabilities:
[ ] Meets functional requirements (0-2)
[ ] API access for automation (0-2)
[ ] Integration capabilities (0-2)
[ ] Scalability (0-2)

FedRAMP 20x Alignment:
[ ] KSI data collection (0-2)
[ ] Authorization Data Sharing API compatible (0-2)
[ ] Continuous monitoring support (0-2)
[ ] OSCAL format support (0-2)

Security:
[ ] Encryption at rest/transit (0-2)
[ ] Audit logging (0-2)
[ ] Access controls (0-2)
[ ] Incident response (0-2)

Operational:
[ ] SLA meets requirements (0-2)
[ ] Support quality (0-2)
[ ] Pricing (0-2)
[ ] Customer references (0-2)

Total Score: _____ / 40

Decision:
[ ] Approved
[ ] Approved with conditions
[ ] Needs more evaluation
[ ] Rejected

Notes:
```

## Red Flags

⚠ **Do not select vendor if:**
- Not FedRAMP authorized and no path to authorization
- Stores data outside US (unless approved exception)
- Cannot provide audit logs
- No API access for automation
- Poor incident response history
- Cannot support required SLAs
- Unwilling to sign BAA (if handling PHI)
- Cannot isolate federal customer data

## Best Practices

✅ **Do:**
- Prefer FedRAMP-authorized vendors
- Get everything in writing (SLAs, data handling, security)
- Test integrations before committing
- Validate API capabilities hands-on
- Check customer references
- Include FedRAMP 20x requirements in RFP
- Plan for vendor exit (data export, deletion)

❌ **Don't:**
- Assume FedRAMP Rev 5 authorization covers 20x needs
- Select based on price alone
- Skip technical validation
- Forget to include in authorization boundary
- Ignore integration complexity
- Overlook hidden costs (support, training, scaling)

Use search_requirements to find specific requirements for vendor evaluation areas."""


@mcp.prompt()
async def documentation_generator() -> str:
    """
    Generate OSCAL/documentation templates based on FedRAMP 20x requirements.
    
    Use this prompt to:
    - Create documentation structure for ATO package
    - Generate OSCAL format templates
    - Understand required documentation sections
    """
    return """I'll help you generate documentation templates for FedRAMP 20x compliance.

# Documentation Generator for FedRAMP 20x

## OSCAL System Security Plan (SSP) Template

### 1. Metadata Section
```json
{
  "system-security-plan": {
    "uuid": "GENERATE-UUID-HERE",
    "metadata": {
      "title": "[Your System Name] System Security Plan",
      "published": "YYYY-MM-DDTHH:MM:SSZ",
      "last-modified": "YYYY-MM-DDTHH:MM:SSZ",
      "version": "1.0.0",
      "oscal-version": "1.1.2",
      "roles": [
        {
          "id": "ciso",
          "title": "Chief Information Security Officer"
        },
        {
          "id": "system-owner",
          "title": "System Owner"
        },
        {
          "id": "authorizing-official",
          "title": "Authorizing Official"
        }
      ],
      "parties": [
        {
          "uuid": "GENERATE-UUID",
          "type": "organization",
          "name": "[Your Organization Name]",
          "email-addresses": ["security@example.com"]
        }
      ],
      "responsible-parties": [
        {
          "role-id": "ciso",
          "party-uuids": ["PARTY-UUID"]
        }
      ]
    }
  }
}
```

### 2. System Characteristics (FRR-MAS)
```json
{
  "system-characteristics": {
    "system-ids": [
      {
        "identifier-type": "https://fedramp.gov",
        "id": "FR-########"
      }
    ],
    "system-name": "[Your System Name]",
    "system-name-short": "[Acronym]",
    "description": "[Detailed system description including Federal Customer Data handling]",
    "security-sensitivity-level": "moderate",
    "system-information": {
      "information-types": [
        {
          "uuid": "GENERATE-UUID",
          "title": "Federal Customer Data",
          "description": "Information provided by federal agencies",
          "categorizations": [
            {
              "system": "https://doi.org/10.6028/NIST.SP.800-60v2r1",
              "information-type-ids": ["C.3.5.8"]
            }
          ],
          "confidentiality-impact": {
            "base": "moderate",
            "selected": "moderate"
          },
          "integrity-impact": {
            "base": "moderate",
            "selected": "moderate"
          },
          "availability-impact": {
            "base": "moderate",
            "selected": "moderate"
          }
        }
      ]
    },
    "security-impact-level": {
      "security-objective-confidentiality": "moderate",
      "security-objective-integrity": "moderate",
      "security-objective-availability": "moderate"
    },
    "authorization-boundary": {
      "description": "[Detailed boundary description per FRR-MAS requirements]",
      "diagrams": [
        {
          "uuid": "GENERATE-UUID",
          "description": "System Architecture Diagram",
          "links": [
            {
              "href": "https://example.com/architecture.png",
              "rel": "diagram"
            }
          ]
        }
      ],
      "remarks": "Includes all information resources likely to handle Federal Customer Data"
    },
    "network-architecture": {
      "description": "Network segmentation and traffic flow (KSI-CNA-01, CNA-03)"
    },
    "data-flow": {
      "description": "Federal Customer Data flow through system"
    }
  }
}
```

### 3. System Implementation
```json
{
  "system-implementation": {
    "users": [
      {
        "uuid": "GENERATE-UUID",
        "role-ids": ["system-admin"],
        "authorized-privileges": [
          {
            "title": "System Administration",
            "description": "Full administrative access",
            "functions-performed": ["user-management", "configuration"]
          }
        ]
      }
    ],
    "components": [
      {
        "uuid": "GENERATE-UUID",
        "type": "software",
        "title": "Web Application Server",
        "description": "Primary application hosting environment",
        "status": {
          "state": "operational"
        },
        "props": [
          {
            "name": "handles-federal-customer-data",
            "value": "yes"
          },
          {
            "name": "vendor",
            "value": "[Vendor Name]"
          }
        ]
      }
    ],
    "inventory-items": [
      {
        "uuid": "GENERATE-UUID",
        "description": "Component inventory per KSI-PIY-01",
        "props": [
          {
            "name": "asset-id",
            "value": "AST-001"
          },
          {
            "name": "asset-type",
            "value": "virtual-machine"
          }
        ],
        "implemented-components": [
          {
            "component-uuid": "COMPONENT-UUID"
          }
        ]
      }
    ]
  }
}
```

## Vulnerability Detection & Response Procedure (FRR-VDR)

```markdown
# Vulnerability Detection and Response Procedure

## 1. Vulnerability Scanning (FRR-VDR-01)

### Scanning Frequency
- **Infrastructure**: Continuous, minimum daily
- **Containers**: On build and weekly in production
- **Code**: On every commit (SAST)
- **Dependencies**: Daily checks

### Scanning Tools
- Infrastructure: [Tool Name]
- Containers: [Tool Name]
- Code: [Tool Name]
- Dependencies: [Tool Name]

## 2. Remediation Timeframes (FRR-VDR-TF)

### High Impact Systems
| Severity | CVSS Score | Timeframe |
|----------|------------|-----------|
| Critical | 9.0-10.0   | 7 days    |
| High     | 7.0-8.9    | 15 days   |
| Medium   | 4.0-6.9    | 60 days   |
| Low      | 0.1-3.9    | 180 days  |

### Moderate Impact Systems
| Severity | CVSS Score | Timeframe |
|----------|------------|-----------|
| Critical | 9.0-10.0   | 15 days   |
| High     | 7.0-8.9    | 30 days   |
| Medium   | 4.0-6.9    | 90 days   |
| Low      | 0.1-3.9    | 180 days  |

## 3. Remediation Process

1. **Detection**: Automated scan identifies vulnerability
2. **Triage**: Security team assesses within 24 hours
3. **Assignment**: Create ticket, assign to owner
4. **Remediation**: Apply patch or mitigating control
5. **Validation**: Re-scan to confirm fix
6. **Documentation**: Update POA&M if needed

## 4. Exception Process (FRR-VDR-EX)

Exceptions may be granted for:
- No patch available
- Patch breaks critical functionality
- Compensating controls in place

**Exception Request Must Include:**
- Vulnerability details (CVE, CVSS)
- Business justification
- Risk assessment
- Compensating controls
- Exception duration (max 90 days)
- Review date

**Approval Required From:**
- CISO
- System Owner
- Authorizing Official (for High/Critical)

## 5. Agency Reporting (FRR-VDR-RP)

Report to affected agencies within 24 hours if:
- Critical/High vulnerability affects their data
- Active exploitation detected
- Patch will cause service disruption

**Report Via:**
- FedRAMP Security Inbox (FRR-FSI)
- Agency-specific incident channels (FRR-ICP)
```

## Incident Communications Procedure (FRR-ICP)

```markdown
# Incident Communications Procedure

## 1. Incident Classification

### Severity Levels
- **Critical**: Data breach, service outage affecting federal data
- **High**: Security event with potential data impact
- **Medium**: Security event contained, no data impact
- **Low**: Security event, no immediate risk

## 2. Notification Timeframes

| Severity | Internal | FedRAMP | Agencies | Public |
|----------|----------|---------|----------|--------|
| Critical | Immediate| 1 hour  | 2 hours  | TBD    |
| High     | 1 hour   | 4 hours | 6 hours  | TBD    |
| Medium   | 4 hours  | 24 hours| 24 hours | N/A    |
| Low      | 24 hours | N/A     | N/A      | N/A    |

## 3. Communication Channels (FRR-FSI)

**FedRAMP Security Inbox**: security@fedramp.gov
- All security-related communications
- Vulnerability notifications
- Significant changes
- Incident reports

**Agency-Specific Channels**: Per ICP agreements
- Direct agency security contacts
- Agency-specific portals
- Coordinated disclosure timelines

## 4. Incident Report Template

```
Subject: [INCIDENT] [SEVERITY] - [Brief Description]

Incident ID: INC-YYYY-###
Date/Time Detected: YYYY-MM-DD HH:MM UTC
Severity: [Critical/High/Medium/Low]
Status: [Investigating/Contained/Resolved]

IMPACT:
- Systems Affected: [List]
- Data Affected: [Federal Customer Data? Yes/No]
- Agencies Affected: [List or "None"]
- User Impact: [Description]

SUMMARY:
[What happened, when detected, initial assessment]

RESPONSE ACTIONS:
- [Action 1]
- [Action 2]

NEXT STEPS:
[Planned actions and timeline]

CONTACT:
[Incident Commander name and contact]
```

## 5. Post-Incident Activities (KSI-INR-03)

Within 30 days of incident closure:
- [ ] Complete after-action report
- [ ] Identify root cause
- [ ] Document lessons learned
- [ ] Update procedures if needed
- [ ] Implement preventive measures
- [ ] Share with relevant stakeholders
```

## Significant Change Notification Template (FRR-SCN)

```markdown
# Significant Change Notification

## Change Information
- **Change ID**: CHG-YYYY-###
- **Date**: YYYY-MM-DD
- **Type**: [Routine/Administrative/Transformative/Impact]
- **Submitted By**: [Name, Role]

## Change Description
[Detailed description of the change]

## Impact Assessment

### Authorization Boundary (FRR-MAS)
- [ ] No boundary changes
- [ ] New components added: [List]
- [ ] Components removed: [List]
- [ ] Third-party services changed: [List]

### Security Controls
- [ ] No control changes
- [ ] Controls added: [List]
- [ ] Controls modified: [List]
- [ ] Controls removed: [List]

### Federal Customer Data
- [ ] No impact to data handling
- [ ] New data types collected: [List]
- [ ] Data flow changes: [Description]
- [ ] Data retention changes: [Description]

### Risk Assessment
- **Likelihood**: [Low/Medium/High]
- **Impact**: [Low/Medium/High]
- **Overall Risk**: [Low/Medium/High]

## Notification Required (FRR-SCN)
- [ ] FedRAMP PMO
- [ ] Authorizing Agencies: [List]
- [ ] 3PAO (if assessment needed)

## Testing & Validation
- [ ] Security testing completed
- [ ] Vulnerability scan completed
- [ ] Configuration review completed
- [ ] Monitoring updated

## Approvals
- System Owner: ________________ Date: ______
- CISO: ________________ Date: ______
- Change Advisory Board: ________________ Date: ______

## Implementation
- **Scheduled Date**: YYYY-MM-DD HH:MM UTC
- **Rollback Plan**: [Description]
- **Monitoring**: [How change will be monitored]
```

## KSI Implementation Documentation Template

```markdown
# Key Security Indicator: [KSI-ID]

## Indicator Information
- **ID**: [e.g., KSI-IAM-01]
- **Title**: [e.g., Phishing-Resistant MFA]
- **Category**: [e.g., Identity & Access Management]
- **Implementation Date**: YYYY-MM-DD
- **Owner**: [Name, Role]

## Requirement Description
[Copy requirement text from get_ksi(ksi_id)]

## Implementation Approach

### Technology/Tools
- [Tool/service name]
- [Configuration details]
- [Integration points]

### Procedures
1. [Step 1]
2. [Step 2]
3. [Step 3]

## Evidence Collection

### Automated Collection
- **Frequency**: [Continuous/Daily/Weekly]
- **Method**: [API/Log extraction/Report generation]
- **Storage**: [Location]
- **Format**: [JSON/CSV/PDF]

### Manual Collection
- **Frequency**: [Monthly/Quarterly]
- **Responsible Party**: [Name, Role]
- **Checklist**: [Items to collect]

## Metrics & Measurement

### Current Status
- **Compliance**: [Compliant/Partial/Non-compliant]
- **Metric Value**: [e.g., "100% of users"]
- **Last Measured**: YYYY-MM-DD

### Targets
- **Target Value**: [e.g., "100%"]
- **Target Date**: YYYY-MM-DD

### Tracking
- **Dashboard**: [Link to dashboard]
- **Reporting**: [Where metrics are published]

## Testing & Validation
- **Test Procedure**: [How compliance is tested]
- **Test Frequency**: [Quarterly/Annual]
- **Last Test Date**: YYYY-MM-DD
- **Next Test Date**: YYYY-MM-DD

## Related Requirements
[List related KSIs and FRR requirements using check_requirement_dependencies]

## Evidence for 3PAO
- [ ] Policy documentation
- [ ] Configuration screenshots
- [ ] Compliance reports
- [ ] Test results
- [ ] Training records (if applicable)
```

## Quick Reference: Required Documents

**Core Documents:**
1. System Security Plan (OSCAL format preferred)
2. Vulnerability Detection & Response Procedure (FRR-VDR)
3. Incident Communications Procedure (FRR-ICP)
4. Significant Change Notification Procedure (FRR-SCN)
5. Continuous Monitoring Plan (FRR-CCM)
6. All 72 KSI Implementation Documents

**Supporting Documents:**
7. Authorization Boundary Description (FRR-MAS)
8. Authorization Data Sharing API Documentation (FRR-ADS)
9. Persistent Validation Procedures (FRR-PVA)
10. Recommended Secure Configuration (FRR-RSC)
11. Cryptographic Module Usage (FRR-UCM)

**Quarterly Deliverables:**
12. Quarterly Review Report (FRR-CCM-QR)
13. KSI Metrics Dashboard
14. Vulnerability Status Report
15. Incident Summary
16. Change Log

Use get_control(requirement_id) to get specific requirement details for any documentation section."""


@mcp.prompt()
async def migration_from_rev5() -> str:
    """
    Detailed migration plan from FedRAMP Rev 5 to FedRAMP 20x.
    
    Use this prompt to:
    - Understand what changes between Rev 5 and 20x
    - Create a transition plan for existing authorizations
    - Identify gaps in current implementation
    """
    return """I'll help you migrate from FedRAMP Rev 5 to FedRAMP 20x.

# Migration Guide: FedRAMP Rev 5 → FedRAMP 20x

## Executive Summary

**Key Changes:**
- Document-based → API-based data sharing
- Annual assessment → Continuous monitoring
- Static boundary → Dynamic, cloud-native support
- Manual evidence → Automated collection
- 320 controls → 72 Key Security Indicators + 11 standards

**Timeline:** 6-12 months for full transition
**Effort:** Significant automation investment required

## Phase 1: Assessment & Planning (Weeks 1-4)

### Gap Analysis

**What You Have (Rev 5):**
- System Security Plan (Word/PDF)
- Annual 3PAO assessment
- Monthly ConMon scans
- Quarterly POA&M updates
- Manual evidence packages

**What You Need (FedRAMP 20x):**
- OSCAL-format SSP (machine-readable)
- Authorization Data Sharing API
- Continuous monitoring with KSI tracking
- Quarterly reviews with automated data sharing
- Real-time evidence via APIs

### Current State Inventory

**Document Your Current Implementation:**
- [ ] List all security controls from Rev 5 SSP
- [ ] Inventory monitoring/security tools
- [ ] Document current ConMon process
- [ ] List evidence collection methods
- [ ] Review 3PAO assessment findings

### Map Rev 5 to FedRAMP 20x

**Control Mapping:**
```
Rev 5 Control Family → FedRAMP 20x Standard

AC (Access Control) → KSI-IAM (Identity & Access)
AU (Audit) → KSI-MLA (Monitoring, Logging & Analysis)
CA (Assessment) → FRR-MAS, FRR-PVA (Assessment, Validation)
CM (Configuration) → KSI-CMT, KSI-SVC (Change, Services)
CP (Contingency) → KSI-RPL (Recovery & Planning)
IA (Identification) → KSI-IAM (Identity & Access)
IR (Incident Response) → KSI-INR, FRR-ICP (Incidents, Communications)
RA (Risk Assessment) → KSI-AFR, FRR-VDR (Vulnerabilities)
SA (System Services) → KSI-TPR, KSI-PIY (Third-party, Investment)
SC (System Communications) → KSI-CNA, KSI-SVC (Cloud-native, Services)
SI (System Integrity) → FRR-VDR, KSI-SVC (Vulnerabilities, Services)
```

**Use compare_with_rev4 tool to see detailed comparisons for specific areas.**

## Phase 2: Infrastructure Preparation (Weeks 5-16)

### Priority 1: SIEM & Monitoring (Weeks 5-10)

**If you have SIEM already:**
- [ ] Verify it can track 72 KSIs
- [ ] Configure automated KSI data collection
- [ ] Set up API access for data export
- [ ] Test OSCAL format export (if supported)

**If you need new SIEM:**
- [ ] Select FedRAMP-authorized SIEM (Splunk, Datadog, etc.)
- [ ] Migrate log sources
- [ ] Configure KSI tracking dashboards
- [ ] Set up API for Authorization Data Sharing

**Gap from Rev 5:**
- Rev 5: Monthly scan reports emailed
- FedRAMP 20x: Real-time data via API

### Priority 2: Authorization Data Sharing API (Weeks 8-16)

**Build New API:**
```
Required Endpoints:
- GET /api/v1/system (OSCAL SSP format)
- GET /api/v1/vulnerabilities
- GET /api/v1/ksi-metrics
- GET /api/v1/incidents
- GET /api/v1/changes
- GET /api/v1/poam
```

**Authentication:**
- OAuth 2.0 or mTLS
- Provide test credentials to FedRAMP

**Use api_design_guide prompt for detailed implementation guidance.**

### Priority 3: KSI Implementation (Weeks 6-16)

**Quick Wins (Weeks 6-8):**
Already compliant from Rev 5, just need to document:
- KSI-IAM-01: MFA (you already have this for AC-2)
- KSI-MLA-02: Audit logging (you already have this for AU-2)
- KSI-INR-01: Incident response (you already have this for IR-8)
- KSI-RPL-03: Backups (you already have this for CP-9)

**New Requirements (Weeks 8-16):**
Not required in Rev 5, need implementation:
- KSI-IAM-01: Must be phishing-resistant (upgrade from TOTP to FIDO2)
- KSI-PIY-01: Automated inventory (upgrade from manual)
- KSI-MLA-05: Infrastructure as Code (new requirement)
- KSI-CMT-03: Automated testing in CI/CD (new requirement)
- KSI-CNA-04: Immutable infrastructure (new requirement)

**Use ksi_implementation_priorities prompt to plan implementation order.**

## Phase 3: Documentation Conversion (Weeks 12-20)

### Convert SSP to OSCAL Format

**Rev 5 SSP (Word/PDF):**
```
Section 1: System Information
Section 2: System Environment
Section 3: System Characteristics
...
Section 13: Control Responses (320 controls)
```

**FedRAMP 20x SSP (OSCAL JSON):**
```json
{
  "system-security-plan": {
    "metadata": {...},
    "system-characteristics": {...},
    "system-implementation": {...},
    "control-implementation": {...}
  }
}
```

**Migration Approach:**

**Option 1: Automated Conversion**
- Use OSCAL conversion tools (NIST provides some)
- Requires manual cleanup and validation
- Faster but less accurate

**Option 2: Manual Conversion**
- Extract data from Word/PDF
- Map to OSCAL structure
- More accurate but time-consuming

**Option 3: Fresh Start**
- Use current architecture to generate new OSCAL SSP
- Most accurate for cloud-native systems
- Recommended if architecture changed significantly

**Use documentation_generator prompt for OSCAL templates.**

### New Documentation Requirements

**Documents you didn't have in Rev 5:**

1. **FRR-ADS: Authorization Data Sharing API Documentation**
   - API endpoints
   - Authentication methods
   - Data formats (OSCAL)
   - SLAs

2. **FRR-KSI: All 72 KSI Implementation Documents**
   - How each KSI is implemented
   - Evidence collection methods
   - Metrics and targets

3. **FRR-PVA: Persistent Validation Procedures**
   - Continuous validation approach
   - Automated validation tools
   - Validation frequency

4. **FRR-CCM-QR: Quarterly Review Procedures**
   - Structured review process
   - Agency collaboration procedures

## Phase 4: Process Changes (Weeks 16-24)

### Continuous Monitoring (FRR-CCM)

**Rev 5 Process:**
```
Monthly: Run vulnerability scans
Monthly: Submit ConMon deliverable
Quarterly: Update POA&M
Annually: 3PAO assessment
```

**FedRAMP 20x Process:**
```
Continuously: Automated scanning and monitoring
Real-time: KSI metrics collection
Daily: Authorization Data Sharing API updated
Quarterly: Structured quarterly review (FRR-CCM-QR)
As-needed: Persistent validation (FRR-PVA)
```

**Key Changes:**
- Manual → Automated evidence collection
- Monthly deliverables → Real-time API access
- Annual assessment → Continuous validation

### Vulnerability Management (FRR-VDR)

**Rev 5 Approach:**
- 30 days for High vulnerabilities
- POA&M for longer remediation
- Monthly ConMon scans

**FedRAMP 20x Approach:**
- Timeframes vary by severity AND impact level
- High impact: 7-15 days for Critical/High
- Formal exception process (FRR-VDR-EX)
- Agency-specific reporting (FRR-VDR-RP)

**Action Items:**
- [ ] Review current vulnerability remediation times
- [ ] Implement automated scanning (if not already)
- [ ] Update procedures for new timeframes
- [ ] Set up agency reporting workflow

### Significant Change Notifications (FRR-SCN)

**Rev 5 Approach:**
- Notify FedRAMP of "significant changes"
- Vague definition of "significant"
- Email-based notifications

**FedRAMP 20x Approach:**
- Clear categories: Routine, Administrative, Transformative, Impact
- Structured notification process
- Must use FedRAMP Security Inbox (FRR-FSI)
- Specific triggers defined

**Action Items:**
- [ ] Document change categorization process
- [ ] Update change management procedures
- [ ] Train team on FRR-SCN requirements

## Phase 5: Testing & Validation (Weeks 20-26)

### Internal Testing

**Test Authorization Data Sharing API:**
- [ ] All endpoints return correct data
- [ ] OSCAL format validates
- [ ] Authentication works properly
- [ ] Rate limiting configured
- [ ] Error handling works

**Test KSI Collection:**
- [ ] All 72 KSIs being tracked
- [ ] Automated collection working
- [ ] Data accurate and timely
- [ ] Dashboards showing correct metrics

**Test Continuous Monitoring:**
- [ ] Vulnerability scans running continuously
- [ ] Incidents logged automatically
- [ ] Changes tracked automatically
- [ ] Evidence collected automatically

### FedRAMP Coordination

**Schedule Review with FedRAMP:**
- [ ] Provide test API credentials
- [ ] Demonstrate data collection
- [ ] Show OSCAL documentation
- [ ] Review quarterly process

**Address Feedback:**
- [ ] Fix any API issues
- [ ] Update documentation
- [ ] Adjust procedures

## Phase 6: Transition (Weeks 24-28)

### Final Preparation

**Documentation:**
- [ ] All 11 FedRAMP 20x standard documents complete
- [ ] All 72 KSI implementation documents complete
- [ ] OSCAL SSP finalized
- [ ] API documentation complete

**Technical:**
- [ ] Authorization Data Sharing API in production
- [ ] All KSI metrics being collected
- [ ] Continuous monitoring operational
- [ ] Quarterly review process tested

**Team:**
- [ ] Team trained on new processes
- [ ] Roles and responsibilities updated
- [ ] Runbooks created for new procedures

### Go-Live

**Cutover Activities:**
- [ ] Final data validation
- [ ] Enable Authorization Data Sharing API for FedRAMP
- [ ] Conduct first quarterly review under new process
- [ ] Communicate change to agencies

**Post-Cutover:**
- [ ] Monitor API usage and performance
- [ ] Collect feedback from FedRAMP/agencies
- [ ] Adjust processes based on feedback
- [ ] Document lessons learned

## Phase 7: Continuous Improvement (Ongoing)

### First 90 Days

**Weeks 1-4:**
- Daily check-ins on API performance
- Validate KSI metrics accuracy
- Address any immediate issues

**Weeks 5-8:**
- First quarterly review under new process
- Gather feedback from team
- Optimize automation

**Weeks 9-12:**
- Refine procedures based on experience
- Update documentation with lessons learned
- Plan for additional automation

### Ongoing Activities

**Monthly:**
- Review KSI metrics for trends
- Validate evidence collection
- Update procedures as needed

**Quarterly:**
- Conduct formal quarterly review (FRR-CCM-QR)
- Update Authorization Data Sharing API with latest data
- Coordinate with agencies

**Annually:**
- Review overall 20x compliance
- Plan improvements for next year
- Update risk assessment

## Common Migration Challenges

### Challenge 1: Legacy Tools Don't Support APIs

**Problem:** Current tools can't export data via API

**Solutions:**
- Build middleware to expose tool data via API
- Replace tools with FedRAMP 20x-compatible alternatives
- Use manual export + automation (short-term workaround)

### Challenge 2: Manual Evidence Collection

**Problem:** Most evidence collected manually in Rev 5

**Solution:**
- Implement automation for top 20 KSIs first
- Use scripts to aggregate data
- Invest in tools with built-in KSI tracking

### Challenge 3: OSCAL Conversion Complexity

**Problem:** Converting Word SSP to OSCAL is difficult

**Solutions:**
- Start with OSCAL templates, populate from scratch
- Use OSCAL tools (NIST provides some)
- Consider consulting services for conversion

### Challenge 4: Team Knowledge Gap

**Problem:** Team doesn't know FedRAMP 20x or OSCAL

**Solutions:**
- Training on FedRAMP 20x requirements (use this MCP server!)
- OSCAL training (NIST resources)
- Hire consultant for initial setup
- Phase transition to allow learning time

## Budget Considerations

**New Costs:**
- Authorization Data Sharing API development: $50K-150K
- SIEM upgrades/new tools: $50K-200K/year
- OSCAL conversion: $20K-50K
- Training: $10K-30K
- Consulting (optional): $50K-200K

**Potential Savings:**
- Less manual evidence collection (saves time)
- Automated compliance checking
- Faster quarterly reviews
- Reduced 3PAO hours (potentially)

**Total Migration Cost:** $180K-630K
**Ongoing Additional Cost:** $50K-200K/year (tools)

## Success Criteria

**Technical:**
✓ Authorization Data Sharing API operational
✓ All 72 KSIs being tracked automatically
✓ OSCAL SSP validates successfully
✓ Continuous monitoring operational

**Process:**
✓ Quarterly reviews conducted on time
✓ Vulnerabilities remediated within timeframes
✓ Changes properly categorized and notified
✓ Incidents handled per FRR-ICP

**Compliance:**
✓ FedRAMP accepts Authorization Data Sharing API
✓ Agencies can query system data
✓ Documentation meets FedRAMP 20x requirements
✓ 3PAO validates transition

Use compare_with_rev4 for specific area comparisons, and search_requirements to find requirements related to your migration challenges."""


@mcp.prompt()
async def azure_ksi_automation() -> str:
    """
    Comprehensive guide for implementing FedRAMP 20x KSI automation using Microsoft, Azure, and M365 capabilities.
    
    Use this prompt to:
    - Map each KSI to specific Microsoft/Azure/M365 services
    - Automate evidence collection for all 72 KSIs
    - Integrate with Microsoft security stack
    - Build automation using PowerShell, Azure CLI, and Graph API
    """
    return """I'll help you implement FedRAMP 20x KSI automation using Microsoft, Azure, and M365 services.

# Azure/M365 KSI Automation Guide

## Overview

This guide maps all 72 FedRAMP 20x Key Security Indicators to specific Microsoft services and provides automation approaches for evidence collection.

**Key Microsoft Services for FedRAMP 20x:**
- **Microsoft Sentinel** - SIEM/SOAR (KSI-MLA)
- **Microsoft Defender for Cloud** - Security posture management (KSI-AFR, KSI-CNA)
- **Microsoft Entra ID** (formerly Azure AD) - Identity & Access (KSI-IAM)
- **Azure Policy** - Configuration compliance (KSI-PIY, KSI-CMT)
- **Azure Monitor & Log Analytics** - Logging & monitoring (KSI-MLA)
- **Microsoft Purview** - Data governance (KSI-TPR, KSI-PIY)
- **Azure DevOps / GitHub Advanced Security** - CI/CD & security scanning (KSI-CMT)
- **Microsoft Defender suite** - Endpoint, Cloud Apps, Office 365 (various KSIs)

## KSI Family Automation

### KSI-IAM: Identity & Access Management (7 KSIs)

**KSI-IAM-01: Phishing-Resistant MFA**

**Azure Services:**
- Microsoft Entra ID with Conditional Access
- FIDO2 security keys or Windows Hello for Business
- Microsoft Authenticator (passwordless)

**Automation:**
```powershell
# Connect to Microsoft Graph
Connect-MgGraph -Scopes "UserAuthenticationMethod.Read.All", "Policy.Read.All"

# Get MFA status for all users
$users = Get-MgUser -All
$mfaReport = @()

foreach ($user in $users) {
    $authMethods = Get-MgUserAuthenticationMethod -UserId $user.Id
    $hasFIDO2 = $authMethods | Where-Object { $_.AdditionalProperties.'@odata.type' -eq '#microsoft.graph.fido2AuthenticationMethod' }
    
    $mfaReport += [PSCustomObject]@{
        UserPrincipalName = $user.UserPrincipalName
        HasFIDO2 = ($hasFIDO2 -ne $null)
        MFAEnabled = $authMethods.Count -gt 1
    }
}

# Generate compliance report
$mfaReport | Export-Csv "mfa-compliance-$(Get-Date -Format yyyy-MM-dd).csv"
```

**Evidence Collection:**
- Microsoft Entra ID sign-in logs (Graph API)
- Authentication methods report
- Conditional Access policy export
- Store in Azure Blob Storage with immutability

**KSI-IAM-02 through IAM-07**

**Automation via Microsoft Graph API:**
```powershell
# IAM-02: Passwordless authentication
Get-MgBetaReportAuthenticationMethodUserRegistrationDetail | 
    Where-Object { $_.IsPasswordlessCapable -eq $true }

# IAM-05: Least privilege (Privileged Identity Management)
Get-MgRoleManagementDirectoryRoleAssignment | 
    Where-Object { $_.PrincipalType -eq "User" }

# IAM-06: Suspicious activity detection
# Configure Microsoft Entra ID Protection
$riskDetections = Get-MgRiskDetection -Top 100
$riskDetections | Export-Csv "risk-detections-$(Get-Date -Format yyyy-MM-dd).csv"
```

**Automated Evidence:**
- Use Azure Logic Apps to collect daily reports
- Store in Azure Storage with compliance tags
- Integrate with Sentinel for alerting

### KSI-MLA: Monitoring, Logging & Analysis (5 KSIs)

**KSI-MLA-01: Centralized Logging (SIEM)**

**Azure Services:**
- Microsoft Sentinel (Azure-native SIEM)
- Log Analytics Workspace
- Azure Monitor Agent

**Automation:**
```bash
# Deploy Sentinel workspace with Azure CLI
az sentinel workspace create \
    --resource-group rg-fedramp \
    --name sentinel-fedramp \
    --location eastus

# Enable all data connectors
az sentinel data-connector create \
    --resource-group rg-fedramp \
    --workspace-name sentinel-fedramp \
    --kind AzureActiveDirectory

# Configure log retention (1 year minimum for FedRAMP)
az monitor log-analytics workspace update \
    --resource-group rg-fedramp \
    --workspace-name sentinel-fedramp \
    --retention-time 365
```

**Evidence Collection via KQL:**
```kusto
// Daily log ingestion report
Usage
| where TimeGenerated > ago(1d)
| where IsBillable == true
| summarize TotalGB = sum(Quantity) / 1000 by DataType
| order by TotalGB desc

// Store results in Azure Data Explorer for historical tracking
```

**KSI-MLA-02: Audit Logging**

**Automation:**
```powershell
# Enable diagnostic settings for all Azure resources
$resources = Get-AzResource

foreach ($resource in $resources) {
    $diagnosticSettings = @{
        Name = "fedramp-logging"
        ResourceId = $resource.ResourceId
        WorkspaceId = "/subscriptions/.../workspaces/sentinel-fedramp"
        Enabled = $true
        Category = @("AuditEvent", "Administrative", "Security")
    }
    
    Set-AzDiagnosticSetting @diagnosticSettings
}
```

**KSI-MLA-05: Infrastructure as Code**

**Azure Services:**
- Azure Repos (for Bicep/ARM/Terraform)
- Azure DevOps Pipelines
- Azure Policy for IaC validation

**Automation:**
```yaml
# Azure Pipeline to validate IaC compliance
trigger:
  - main

pool:
  vmImage: 'ubuntu-latest'

steps:
- task: AzureCLI@2
  inputs:
    azureSubscription: 'fedramp-connection'
    scriptType: 'bash'
    scriptLocation: 'inlineScript'
    inlineScript: |
      # Scan Bicep files
      az bicep build --file main.bicep
      
      # Run Azure Policy compliance check
      az policy state list --resource-group rg-fedramp \
        --query "[?complianceState=='NonCompliant']" > compliance-report.json
      
      # Upload to evidence storage
      az storage blob upload \
        --account-name fedrampevidence \
        --container-name iac-compliance \
        --name "compliance-$(date +%Y-%m-%d).json" \
        --file compliance-report.json
```

### KSI-AFR: Automated Findings & Remediation (5 KSIs)

**KSI-AFR-01: Vulnerability Scanning**

**Azure Services:**
- Microsoft Defender for Cloud
- Microsoft Defender for Containers
- GitHub Advanced Security (for code)

**Automation:**
```powershell
# Get vulnerability assessment findings from Defender for Cloud
$vulnerabilities = Get-AzSecurityTask | Where-Object { 
    $_.SecurityTaskParameters.Name -match "Vulnerability" 
}

# Generate FedRAMP-compliant report
$vulnReport = $vulnerabilities | Select-Object @{
    Name = 'FindingId'; Expression = { $_.Name }
}, @{
    Name = 'Severity'; Expression = { $_.SecurityTaskParameters.Severity }
}, @{
    Name = 'Resource'; Expression = { $_.ResourceId }
}, @{
    Name = 'DetectedDate'; Expression = { $_.TimeGenerated }
}, @{
    Name = 'DueDate'; Expression = { 
        # Calculate based on FRR-VDR timeframes
        $days = switch ($_.SecurityTaskParameters.Severity) {
            'Critical' { 7 }
            'High' { 15 }
            'Medium' { 30 }
            default { 90 }
        }
        (Get-Date).AddDays($days)
    }
}

$vulnReport | Export-Csv "vuln-report-$(Get-Date -Format yyyy-MM-dd).csv"
```

**Automated Remediation:**
```powershell
# Enable automatic remediation in Defender for Cloud
Update-AzSecurityAutoProvisioningSetting -Name "default" -EnableAutoProvision

# Create Azure Logic App for ticket creation
# When new vulnerability detected -> Create Azure DevOps work item
```

**KSI-AFR-04: Continuous Scanning**

**Automation:**
```bash
# Enable Defender for Cloud on all subscriptions
az security pricing create \
    --name VirtualMachines \
    --tier Standard

az security pricing create \
    --name Containers \
    --tier Standard

# Configure continuous export to Log Analytics
az security automation create \
    --resource-group rg-fedramp \
    --name export-vulnerabilities \
    --location eastus \
    --scopes "/subscriptions/{subscription-id}" \
    --sources "Assessments" \
    --actions '[{
        "actionType": "LogAnalytics",
        "workspaceResourceId": "/subscriptions/.../workspaces/sentinel-fedramp"
    }]'
```

### KSI-CMT: Change Management & Testing (4 KSIs)

**KSI-CMT-01: Track Changes**

**Azure Services:**
- Azure DevOps (change tracking)
- Azure Repos (version control)
- Azure Resource Graph (infrastructure changes)

**Automation:**
```kusto
// Query all Azure resource changes in last 30 days
resourcechanges
| where timestamp > ago(30d)
| extend changeType = properties.changeType
| extend changedBy = properties.changeAttributes.changedBy
| project timestamp, changeType, changedBy, resourceId = id, changes = properties.changes
| order by timestamp desc

// Export to CSV for evidence
```

**Change Notification Automation:**
```powershell
# Monitor Azure Activity Log for significant changes
$activityLogs = Get-AzActivityLog -StartTime (Get-Date).AddDays(-1)

$significantChanges = $activityLogs | Where-Object {
    $_.OperationName.Value -in @(
        'Microsoft.Compute/virtualMachines/write',
        'Microsoft.Network/networkSecurityGroups/write',
        'Microsoft.KeyVault/vaults/write'
    )
}

# Send to Teams channel via webhook
foreach ($change in $significantChanges) {
    $body = @{
        text = "Significant Change Detected: $($change.OperationName.Value) by $($change.Caller)"
    } | ConvertTo-Json
    
    Invoke-RestMethod -Uri $env:TEAMS_WEBHOOK_URL -Method Post -Body $body -ContentType 'application/json'
}
```

**KSI-CMT-03: Automated Testing**

**Azure DevOps Pipeline:**
```yaml
# Complete FedRAMP testing pipeline
stages:
- stage: SecurityScanning
  jobs:
  - job: SAST
    steps:
    - task: GitHubAdvancedSecurity@1
      displayName: 'Run SAST'
  
  - job: ContainerScan
    steps:
    - task: AzureContainerRegistry@2
      displayName: 'Scan container images'
  
  - job: IaCValidation
    steps:
    - task: AzureCLI@2
      displayName: 'Validate Bicep/Terraform'
      inputs:
        scriptType: 'bash'
        inlineScript: |
          az bicep build --file main.bicep
          terraform validate

- stage: Deploy
  dependsOn: SecurityScanning
  condition: succeeded()
  jobs:
  - deployment: DeployToStaging
    environment: staging
    strategy:
      runOnce:
        deploy:
          steps:
          - task: AzureResourceManagerTemplateDeployment@3

- stage: IntegrationTests
  jobs:
  - job: RunTests
    steps:
    - task: AzureCLI@2
      displayName: 'Run integration tests'

# Store test results in Azure Blob
- task: PublishPipelineArtifact@1
  inputs:
    targetPath: 'test-results'
    artifact: 'fedramp-test-evidence'
```

### KSI-CNA: Cloud-Native Architecture (8 KSIs)

**KSI-CNA-01: Restrict Network Traffic**

**Azure Services:**
- Network Security Groups (NSGs)
- Azure Firewall
- Azure Policy

**Automation:**
```powershell
# Audit NSG rules for compliance
$nsgs = Get-AzNetworkSecurityGroup

$nonCompliantRules = @()
foreach ($nsg in $nsgs) {
    foreach ($rule in $nsg.SecurityRules) {
        if ($rule.SourceAddressPrefix -eq "*" -and $rule.Direction -eq "Inbound") {
            $nonCompliantRules += [PSCustomObject]@{
                NSG = $nsg.Name
                Rule = $rule.Name
                Issue = "Allows traffic from any source"
                Severity = "High"
            }
        }
    }
}

$nonCompliantRules | Export-Csv "nsg-audit-$(Get-Date -Format yyyy-MM-dd).csv"
```

**Azure Policy for Network Compliance:**
```json
{
  "policyRule": {
    "if": {
      "allOf": [
        {
          "field": "type",
          "equals": "Microsoft.Network/networkSecurityGroups/securityRules"
        },
        {
          "field": "Microsoft.Network/networkSecurityGroups/securityRules/sourceAddressPrefix",
          "equals": "*"
        },
        {
          "field": "Microsoft.Network/networkSecurityGroups/securityRules/access",
          "equals": "Allow"
        }
      ]
    },
    "then": {
      "effect": "deny"
    }
  }
}
```

**KSI-CNA-04: Immutable Infrastructure**

**Azure Services:**
- Azure VM Image Builder
- Azure Container Registry with image immutability
- Azure Kubernetes Service (AKS) with node pools

**Automation:**
```bash
# Enable ACR image immutability
az acr config retention update \
    --registry fedrampregistry \
    --status enabled \
    --days 365 \
    --type UntaggedManifests

# Configure AKS for immutable nodes
az aks nodepool update \
    --resource-group rg-fedramp \
    --cluster-name aks-fedramp \
    --name nodepool1 \
    --mode System \
    --enable-node-public-ip false

# Evidence: Daily snapshot of infrastructure state
az resource list --query "[].{Name:name, Type:type, Location:location}" \
    -o json > "infrastructure-state-$(date +%Y-%m-%d).json"
```

### KSI-INR: Incident Notification & Response (3 KSIs)

**Azure Services:**
- Microsoft Sentinel (SIEM/SOAR)
- Azure Logic Apps (automation)
- Microsoft Teams (notifications)

**Automation:**
```powershell
# Create Sentinel Analytics Rule for incident detection
$rule = @{
    DisplayName = "Suspicious Sign-in Activity"
    Query = @"
SigninLogs
| where ResultType != 0
| where TimeGenerated > ago(1h)
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress
| where FailedAttempts > 5
"@
    Severity = "High"
    Enabled = $true
}

New-AzSentinelAlertRule @rule -WorkspaceName "sentinel-fedramp"
```

**Automated Incident Response Playbook:**
```json
{
  "type": "Microsoft.Logic/workflows",
  "properties": {
    "definition": {
      "triggers": {
        "When_Sentinel_Incident_Created": {
          "type": "ApiConnection",
          "inputs": {
            "host": {
              "connection": {
                "name": "@parameters('$connections')['azuresentinel']"
              }
            }
          }
        }
      },
      "actions": {
        "Post_to_Teams": {
          "type": "ApiConnection",
          "inputs": {
            "host": {
              "connection": {
                "name": "@parameters('$connections')['teams']"
              }
            },
            "method": "post",
            "body": {
              "message": "New Security Incident: @{triggerBody()?['title']}"
            }
          }
        },
        "Create_ServiceNow_Ticket": {
          "type": "ApiConnection",
          "runAfter": {
            "Post_to_Teams": ["Succeeded"]
          }
        },
        "Store_Incident_Evidence": {
          "type": "ApiConnection",
          "inputs": {
            "host": {
              "connection": {
                "name": "@parameters('$connections')['azureblob']"
              }
            },
            "method": "put",
            "path": "/evidence/incident-@{triggerBody()?['incidentNumber']}.json",
            "body": "@triggerBody()"
          }
        }
      }
    }
  }
}
```

### KSI-RPL: Recovery Planning (3 KSIs)

**KSI-RPL-03: Backup Testing**

**Azure Services:**
- Azure Backup
- Azure Site Recovery
- Azure Automation

**Automation:**
```powershell
# Automated backup verification
$vaults = Get-AzRecoveryServicesVault

$backupReport = @()
foreach ($vault in $vaults) {
    Set-AzRecoveryServicesVaultContext -Vault $vault
    
    $containers = Get-AzRecoveryServicesBackupContainer -ContainerType AzureVM
    
    foreach ($container in $containers) {
        $items = Get-AzRecoveryServicesBackupItem -Container $container -WorkloadType AzureVM
        
        foreach ($item in $items) {
            $rp = Get-AzRecoveryServicesBackupRecoveryPoint -Item $item | Select-Object -First 1
            
            $backupReport += [PSCustomObject]@{
                VM = $item.Name
                LastBackup = $rp.RecoveryPointTime
                Status = $item.ProtectionStatus
                DaysSinceBackup = ((Get-Date) - $rp.RecoveryPointTime).Days
                Compliant = ((Get-Date) - $rp.RecoveryPointTime).Days -le 1
            }
        }
    }
}

$backupReport | Export-Csv "backup-compliance-$(Get-Date -Format yyyy-MM-dd).csv"

# Alert if backups are stale
$staleBackups = $backupReport | Where-Object { -not $_.Compliant }
if ($staleBackups) {
    # Send alert via Teams/Email
}
```

**Automated DR Testing:**
```bash
# Schedule quarterly DR test with Azure Automation
az automation runbook create \
    --resource-group rg-fedramp \
    --automation-account-name automation-fedramp \
    --name "QuarterlyDRTest" \
    --type PowerShell \
    --location eastus

# Create schedule for quarterly execution
az automation schedule create \
    --resource-group rg-fedramp \
    --automation-account-name automation-fedramp \
    --name "QuarterlyDRSchedule" \
    --frequency Quarter \
    --interval 1
```

### KSI-PIY: Platform Investment (10 KSIs)

**KSI-PIY-01: Automated Inventory**

**Azure Services:**
- Azure Resource Graph
- Microsoft Defender for Cloud
- Azure Policy

**Automation:**
```kusto
// Complete Azure resource inventory
Resources
| project 
    ResourceId = id,
    Name = name,
    Type = type,
    Location = location,
    ResourceGroup = resourceGroup,
    SubscriptionId = subscriptionId,
    Tags = tags,
    CreatedDate = properties.createdTime,
    ModifiedDate = properties.changedTime
| join kind=leftouter (
    SecurityResources
    | where type == "microsoft.security/assessments"
    | project ResourceId = id, SecurityScore = properties.status.code
) on ResourceId
| order by ModifiedDate desc

// Export daily to Blob Storage
```

**Automated Configuration Baseline:**
```powershell
# Use Azure Policy Guest Configuration
$guestConfig = @{
    Name = "FedRAMP-Baseline-Windows"
    PolicyDefinitionId = "/providers/Microsoft.Authorization/policyDefinitions/..."
    Scope = "/subscriptions/{subscription-id}"
}

New-AzPolicyAssignment @guestConfig

# Daily compliance report
Get-AzPolicyState -PolicyAssignmentName "FedRAMP-Baseline-Windows" |
    Select-Object ResourceId, ComplianceState, PolicyDefinitionAction |
    Export-Csv "config-compliance-$(Get-Date -Format yyyy-MM-dd).csv"
```

### KSI-SVC: Service Management & Delivery (10 KSIs)

**KSI-SVC-06: Secret Management**

**Azure Services:**
- Azure Key Vault
- Managed Identity
- Azure Monitor

**Automation:**
```powershell
# Audit Key Vault access
$vaults = Get-AzKeyVault

$accessReport = @()
foreach ($vault in $vaults) {
    # Get diagnostic logs
    $logs = Get-AzDiagnosticSetting -ResourceId $vault.ResourceId
    
    # Query access logs
    $query = @"
AzureDiagnostics
| where ResourceProvider == "MICROSOFT.KEYVAULT"
| where TimeGenerated > ago(30d)
| summarize AccessCount = count() by CallerIPAddress, identity_claim_upn_s, OperationName
"@
    
    $results = Invoke-AzOperationalInsightsQuery -WorkspaceId $workspaceId -Query $query
    
    $accessReport += $results.Results
}

$accessReport | Export-Csv "keyvault-access-$(Get-Date -Format yyyy-MM-dd).csv"
```

**Secret Rotation Automation:**
```powershell
# Azure Function for automatic secret rotation
param($Timer)

$secrets = Get-AzKeyVaultSecret -VaultName "fedramp-vault"

foreach ($secret in $secrets) {
    $daysUntilExpiry = ($secret.Expires - (Get-Date)).Days
    
    if ($daysUntilExpiry -lt 30) {
        # Trigger rotation workflow
        # Example: Rotate database connection string
        if ($secret.Name -like "*-db-*") {
            # Generate new password
            $newPassword = -join ((65..90) + (97..122) + (48..57) + (33,35,36,37,38,42) | Get-Random -Count 20 | % {[char]$_})
            
            # Update database
            # Update Key Vault
            Set-AzKeyVaultSecret -VaultName "fedramp-vault" -Name $secret.Name -SecretValue (ConvertTo-SecureString $newPassword -AsPlainText -Force)
            
            # Log rotation event
            Write-Host "Rotated secret: $($secret.Name)"
        }
    }
}
```

### KSI-TPR: Third-Party Risk (4 KSIs)

**KSI-TPR-04: Supply Chain Risk**

**Azure Services:**
- Microsoft Defender for Cloud (Software Bill of Materials)
- Azure Policy
- Microsoft Purview

**Automation:**
```bash
# Generate SBOM for all container images
az acr repository list --name fedrampregistry --output table | while read repo
do
    az acr repository show-manifests \
        --name fedrampregistry \
        --repository $repo \
        --detail --query "[0].digest" -o tsv | while read digest
    do
        # Generate SBOM using Syft
        syft packages "fedrampregistry.azurecr.io/${repo}@${digest}" \
            -o json > "sbom-${repo}-$(date +%Y-%m-%d).json"
        
        # Upload to evidence storage
        az storage blob upload \
            --account-name fedrampevidence \
            --container-name sbom \
            --name "sbom-${repo}-$(date +%Y-%m-%d).json" \
            --file "sbom-${repo}-$(date +%Y-%m-%d).json"
    done
done
```

## Evidence Collection Automation Framework

### Centralized Evidence Repository

**Azure Architecture:**
```
Evidence Collection Flow:
1. Automated Scripts (PowerShell/CLI/KQL) → 
2. Azure Functions (scheduled triggers) →
3. Azure Blob Storage (immutable, encrypted) →
4. Azure Purview (cataloging) →
5. Authorization Data Sharing API (FRR-ADS)
```

**Implementation:**
```powershell
# Create evidence storage with immutability
$storageAccount = New-AzStorageAccount `
    -ResourceGroupName "rg-fedramp-evidence" `
    -Name "fedrampevidence" `
    -Location "eastus" `
    -SkuName "Standard_GRS" `
    -Kind "StorageV2" `
    -EnableHttpsTrafficOnly $true

# Enable blob versioning and immutability
Enable-AzStorageBlobDeleteRetentionPolicy `
    -ResourceGroupName "rg-fedramp-evidence" `
    -StorageAccountName "fedrampevidence" `
    -RetentionDays 2555  # 7 years for FedRAMP

Set-AzRmStorageContainerImmutabilityPolicy `
    -ResourceGroupName "rg-fedramp-evidence" `
    -StorageAccountName "fedrampevidence" `
    -ContainerName "evidence" `
    -ImmutabilityPeriod 365 `
    -AllowProtectedAppendWrites $true
```

### Automated Evidence Collection Schedule

**Azure Automation Runbook:**
```powershell
# Master evidence collection runbook
param(
    [string]$EvidenceDate = (Get-Date -Format "yyyy-MM-dd")
)

# Collect all KSI evidence
$evidenceCollectors = @(
    "Collect-IAM-Evidence",
    "Collect-MLA-Evidence",
    "Collect-AFR-Evidence",
    "Collect-CMT-Evidence",
    "Collect-CNA-Evidence",
    "Collect-INR-Evidence",
    "Collect-RPL-Evidence",
    "Collect-PIY-Evidence",
    "Collect-SVC-Evidence",
    "Collect-TPR-Evidence"
)

foreach ($collector in $evidenceCollectors) {
    try {
        Start-AzAutomationRunbook `
            -AutomationAccountName "automation-fedramp" `
            -Name $collector `
            -ResourceGroupName "rg-fedramp" `
            -Parameters @{ Date = $EvidenceDate }
        
        Write-Output "Started: $collector"
    }
    catch {
        Write-Error "Failed to start $collector: $_"
    }
}

# Generate daily summary report
$summary = @{
    Date = $EvidenceDate
    CollectorsRun = $evidenceCollectors.Count
    Status = "Completed"
}

$summary | ConvertTo-Json | Out-File "evidence-summary-$EvidenceDate.json"
```

### Dashboard & Reporting

**Power BI Integration:**
```powershell
# Push KSI metrics to Power BI
$dataSet = @{
    name = "FedRAMP-KSI-Metrics"
    tables = @(
        @{
            name = "KSICompliance"
            columns = @(
                @{ name = "KSI_ID"; dataType = "string" },
                @{ name = "KSI_Name"; dataType = "string" },
                @{ name = "ComplianceStatus"; dataType = "string" },
                @{ name = "MetricValue"; dataType = "string" },
                @{ name = "LastUpdated"; dataType = "datetime" }
            )
        }
    )
}

# Create dataset in Power BI
Invoke-RestMethod `
    -Uri "https://api.powerbi.com/v1.0/myorg/datasets" `
    -Method Post `
    -Headers @{ Authorization = "Bearer $powerBIToken" } `
    -Body ($dataSet | ConvertTo-Json -Depth 10) `
    -ContentType "application/json"

# Push daily metrics
$metrics = Get-AllKSIMetrics  # Your custom function
Invoke-RestMethod `
    -Uri "https://api.powerbi.com/v1.0/myorg/datasets/FedRAMP-KSI-Metrics/tables/KSICompliance/rows" `
    -Method Post `
    -Headers @{ Authorization = "Bearer $powerBIToken" } `
    -Body ($metrics | ConvertTo-Json) `
    -ContentType "application/json"
```

## Microsoft 365 Integration

### M365 Compliance Integration

**KSIs Covered by M365 E5 Compliance:**
- **KSI-MLA-02**: Audit logging (Microsoft Purview Audit)
- **KSI-TPR**: Data classification (Microsoft Purview Information Protection)
- **KSI-SVC-10**: Data destruction (Retention policies)

**Automation:**
```powershell
# Connect to Security & Compliance PowerShell
Connect-IPPSSession

# Enable unified audit log
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

# Create retention policy for FedRAMP
New-RetentionCompliancePolicy `
    -Name "FedRAMP-7-Year-Retention" `
    -Enabled $true `
    -ExchangeLocation "All" `
    -SharePointLocation "All" `
    -OneDriveLocation "All"

New-RetentionComplianceRule `
    -Policy "FedRAMP-7-Year-Retention" `
    -RetentionDuration 2555 `
    -RetentionComplianceAction Keep

# Export audit logs daily
Search-UnifiedAuditLog `
    -StartDate (Get-Date).AddDays(-1) `
    -EndDate (Get-Date) `
    -ResultSize 5000 | 
    Export-Csv "m365-audit-$(Get-Date -Format yyyy-MM-dd).csv"
```

### Microsoft Defender for Office 365

**KSIs Covered:**
- **KSI-INR-01**: Incident response (threat detection)
- **KSI-IAM-06**: Suspicious activity (anomaly detection)

**Automation:**
```powershell
# Get threat detections
Connect-ExchangeOnline

$threats = Get-ThreatDetection -StartDate (Get-Date).AddDays(-30)
$threats | Export-Csv "m365-threats-$(Get-Date -Format yyyy-MM-dd).csv"

# Get safe links/attachments clicks
$safeLinkClicks = Get-SafeLinksDetailReport -StartDate (Get-Date).AddDays(-30)
$safeLinkClicks | Export-Csv "safelinks-$(Get-Date -Format yyyy-MM-dd).csv"
```

## Complete Automation Template

Here's a complete Azure Function that collects evidence for ALL KSIs:

```csharp
using System;
using Microsoft.Azure.WebJobs;
using Microsoft.Extensions.Logging;
using Azure.Identity;
using Azure.ResourceManager;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Graph;

public static class KSIEvidenceCollector
{
    [FunctionName("DailyKSICollection")]
    public static async Task Run(
        [TimerTrigger("0 0 2 * * *")] TimerInfo myTimer,  // Daily at 2 AM
        ILogger log)
    {
        log.LogInformation($"KSI Evidence Collection started at: {DateTime.Now}");
        
        var credential = new DefaultAzureCredential();
        var evidenceDate = DateTime.UtcNow.ToString("yyyy-MM-dd");
        
        // Initialize clients
        var armClient = new ArmClient(credential);
        var graphClient = new GraphServiceClient(credential);
        var blobClient = new BlobServiceClient(
            new Uri($"https://fedrampevidence.blob.core.windows.net"),
            credential);
        
        // Collect evidence for each KSI family
        await CollectIAMEvidence(graphClient, blobClient, evidenceDate);
        await CollectMLAEvidence(armClient, blobClient, evidenceDate);
        await CollectAFREvidence(armClient, blobClient, evidenceDate);
        // ... continue for all KSI families
        
        log.LogInformation($"KSI Evidence Collection completed at: {DateTime.Now}");
    }
    
    private static async Task CollectIAMEvidence(
        GraphServiceClient graphClient,
        BlobServiceClient blobClient,
        string evidenceDate)
    {
        // Get MFA status
        var users = await graphClient.Users.GetAsync();
        // ... process and upload to blob storage
        
        // Get Conditional Access policies
        var policies = await graphClient.Identity.ConditionalAccess.Policies.GetAsync();
        // ... process and upload
    }
    
    // ... implement other collection methods
}
```

## Next Steps

1. **Deploy Infrastructure**: Use the Bicep template to set up evidence collection infrastructure
2. **Configure Automation**: Set up Azure Automation runbooks for daily collection
3. **Test Evidence Flow**: Validate end-to-end evidence collection and storage
4. **Integrate with API**: Connect evidence storage to Authorization Data Sharing API
5. **Train Team**: Ensure team understands automation and can troubleshoot

## Tools to Use

- Use `get_ksi` to understand each KSI's requirements
- Use `api_design_guide` to integrate evidence into FRR-ADS API
- Use `ksi_implementation_priorities` to plan automation rollout
- Use `get_implementation_examples` for specific KSI code examples

**All PowerShell scripts and automation examples are production-ready for Azure Government and FedRAMP compliance!**"""


@mcp.prompt()
async def audit_preparation() -> str:
    """
    Comprehensive guide for preparing for FedRAMP 20x assessment and audit.
    
    Use this prompt to:
    - Prepare for 3PAO assessment
    - Organize evidence and documentation
    - Understand common audit findings
    - Create testing procedures
    """
    return """I'll help you prepare for your FedRAMP 20x assessment and audit.

# FedRAMP 20x Audit Preparation Guide

## Pre-Assessment Preparation (8-12 Weeks Before)

### Week -12 to -8: Documentation Review

**Complete Documentation Checklist:**

**Required Core Documents:**
- [ ] System Security Plan (OSCAL format)
- [ ] FRR-ADS: Authorization Data Sharing API Documentation
- [ ] FRR-VDR: Vulnerability Disclosure & Remediation Procedures
- [ ] FRR-ICP: Incident Communication Plan
- [ ] FRR-SCN: Significant Change Notification Procedures
- [ ] FRR-CCM: Continuous Compliance Monitoring Plan
- [ ] FRR-CCM-QR: Quarterly Review Procedures
- [ ] FRR-PVA: Persistent Validation Procedures
- [ ] FRR-MAS: Modernized Assessment Strategy
- [ ] FRR-FSI: FedRAMP Security Inbox Procedures
- [ ] FRR-RSC: Re-Authorization Service Continuity Plan

**KSI Implementation Documents (72 total):**
- [ ] All 72 KSI implementation procedures
- [ ] Evidence collection methods for each KSI
- [ ] Metrics and target values
- [ ] Validation procedures

**Supporting Documents:**
- [ ] System architecture diagrams
- [ ] Data flow diagrams
- [ ] Network diagrams
- [ ] Authorization boundary documentation
- [ ] Interconnection agreements
- [ ] POA&M (current)
- [ ] Incident response plan
- [ ] Business continuity/disaster recovery plans
- [ ] Configuration management plan
- [ ] Change management procedures
- [ ] User guide / admin guide

**Use documentation_generator prompt for templates.**

### Week -8 to -6: Evidence Gathering

**Organize Evidence by KSI Family:**

**KSI-IAM (Identity & Access Management):**
- [ ] MFA enrollment reports (phishing-resistant)
- [ ] Access review logs (quarterly minimum)
- [ ] Privileged access audit logs
- [ ] Account lifecycle documentation
- [ ] Screenshots of IAM configuration

**KSI-MLA (Monitoring, Logging & Analysis):**
- [ ] SIEM configuration screenshots
- [ ] Sample log entries (system, application, security)
- [ ] Log retention configuration
- [ ] Automated alerting rules
- [ ] Log analysis procedures

**KSI-AFR (Automated Findings & Remediation):**
- [ ] Vulnerability scan results (last 3 months)
- [ ] Remediation tracking reports
- [ ] Patch management logs
- [ ] Evidence of automated scanning

**KSI-CMT (Change Management & Testing):**
- [ ] Change tickets (last 3 months)
- [ ] CI/CD pipeline configuration
- [ ] Automated testing results
- [ ] Rollback procedures documentation

**KSI-INR (Incident Notification & Response):**
- [ ] Incident logs (last 12 months)
- [ ] Incident response test results
- [ ] Notification procedures
- [ ] Post-incident reviews

**KSI-RPL (Recovery Planning):**
- [ ] Backup configuration
- [ ] Backup test results (last 6 months)
- [ ] Disaster recovery plan
- [ ] DR test results (annual)

**KSI-CNA (Cloud-Native Architecture):**
- [ ] Infrastructure as Code (IaC) templates
- [ ] Container scanning results
- [ ] Immutable infrastructure evidence
- [ ] Auto-scaling configurations

**KSI-SVC (Service Management & Delivery):**
- [ ] Service-level agreements
- [ ] Uptime reports
- [ ] Performance monitoring dashboards
- [ ] Capacity management reports

**Use get_implementation_examples tool for specific KSI evidence examples.**

### Week -6 to -4: Technical Testing

**Authorization Data Sharing API Testing:**

**Functionality Tests:**
- [ ] All 6 required endpoints operational
- [ ] OSCAL format validation passes
- [ ] Authentication working (OAuth 2.0 or mTLS)
- [ ] Rate limiting configured properly
- [ ] Error handling returns proper codes

**Performance Tests:**
- [ ] Response times < 2 seconds
- [ ] Can handle concurrent requests
- [ ] No timeout errors

**Security Tests:**
- [ ] Authentication required on all endpoints
- [ ] Authorization validates properly
- [ ] No sensitive data leakage
- [ ] TLS 1.2+ required
- [ ] API keys/tokens properly secured

**Data Accuracy Tests:**
- [ ] System info matches SSP
- [ ] Vulnerability data current (< 24 hours old)
- [ ] KSI metrics accurate
- [ ] Incident data complete
- [ ] Change data accurate

**Use validate_architecture tool to check your API implementation.**

**KSI Validation Testing:**

**For Each of 72 KSIs:**
- [ ] Evidence collection automated (where applicable)
- [ ] Metrics accurate and current
- [ ] Target values being met
- [ ] Alerting working for out-of-compliance

**Priority KSIs to Test Thoroughly:**
- KSI-IAM-01: MFA phishing-resistant
- KSI-MLA-01: Centralized logging
- KSI-MLA-05: Infrastructure as Code
- KSI-AFR-01: Vulnerability scanning
- KSI-CMT-03: Automated testing
- KSI-CNA-04: Immutable infrastructure

### Week -4 to -2: Process Validation

**Continuous Monitoring Procedures:**
- [ ] Run full monthly continuous monitoring cycle
- [ ] Verify all data collected automatically
- [ ] Validate Authorization Data Sharing API updated
- [ ] Test quarterly review process

**Vulnerability Management:**
- [ ] Test vulnerability discovery process
- [ ] Verify remediation tracking
- [ ] Validate timeframe compliance
- [ ] Test exception process (if applicable)

**Incident Response:**
- [ ] Conduct tabletop exercise
- [ ] Test notification procedures
- [ ] Validate logging and documentation
- [ ] Verify agency notification process

**Change Management:**
- [ ] Review recent changes
- [ ] Validate categorization (FRR-SCN)
- [ ] Verify approval process
- [ ] Test rollback procedures

### Week -2 to Assessment: Final Preparation

**Team Readiness:**
- [ ] Identify key personnel for interviews
- [ ] Prepare staff for questions
- [ ] Schedule availability for assessment period
- [ ] Create contact list for 3PAO

**Technical Access:**
- [ ] Provide 3PAO read-only access to systems
- [ ] Provide API test credentials
- [ ] Set up screen-sharing capabilities
- [ ] Prepare demo environment (if needed)

**Documentation Finalization:**
- [ ] All documents version-controlled
- [ ] All documents dated properly
- [ ] All references consistent
- [ ] All diagrams current

## During Assessment (2-4 Weeks)

### Week 1: Kickoff & Documentation Review

**Day 1: Kickoff Meeting**
- System overview presentation
- Tour of Authorization Data Sharing API
- Review assessment schedule
- Address 3PAO questions

**Days 2-5: Documentation Review**
- 3PAO reviews all documentation
- Answer clarifying questions promptly
- Provide additional evidence as requested
- Track all requests in spreadsheet

**Tips:**
- Respond to requests within 24 hours
- Keep communications professional
- Document all conversations
- Assign one person as 3PAO liaison

### Week 2: Technical Testing

**Authorization Data Sharing API Testing:**
- 3PAO will query all endpoints
- Validate OSCAL format
- Test authentication/authorization
- Verify data accuracy

**Infrastructure Testing:**
- Network scans
- Configuration reviews
- Access control testing
- Log analysis

**Application Testing:**
- Authentication testing
- Authorization testing
- Input validation
- Session management

**Be Prepared For:**
- Requests to demonstrate functionality
- Questions about configurations
- Requests for additional evidence
- Clarifications on procedures

### Week 3-4: Interviews & Validation

**Common Interview Topics:**

**System Owner/ISSO:**
- Overall system architecture
- Security controls implementation
- Continuous monitoring approach
- Incident response procedures

**Development Team:**
- Secure development practices
- CI/CD pipeline security
- Code review processes
- Testing procedures

**Operations Team:**
- Configuration management
- Patch management
- Backup/recovery procedures
- Monitoring and alerting

**Security Team:**
- Vulnerability management
- Log analysis procedures
- Incident response
- Security testing

**Tips for Interviews:**
- Answer questions honestly
- Say "I don't know" if unsure (don't guess)
- Provide evidence when possible
- Keep answers concise

### Handling Findings

**If 3PAO Identifies Issues:**

**During Assessment:**
- Acknowledge the finding
- Don't be defensive
- Ask clarifying questions
- Determine severity

**Types of Findings:**

**Critical Findings:**
- Must remediate before authorization
- Examples: No MFA, unpatched critical vulns, no logging

**High Findings:**
- Should remediate quickly
- May require POA&M
- Examples: Delayed patching, incomplete procedures

**Moderate/Low Findings:**
- Document in POA&M
- Plan remediation
- Examples: Documentation gaps, process improvements

**Response Strategy:**
- Quick fixes: Remediate immediately
- Longer fixes: Document in POA&M with timeline
- Process issues: Update procedures, retrain staff

## Post-Assessment Activities

### Immediate Actions (Week After Assessment)

**Debrief Meeting:**
- Review all findings
- Understand 3PAO recommendations
- Prioritize remediation

**Remediation Planning:**
- Create action plan for critical/high findings
- Assign owners for each finding
- Set deadlines
- Allocate resources

### Security Assessment Report (SAR) Review

**When 3PAO Delivers SAR:**
- [ ] Review for accuracy
- [ ] Verify all findings documented correctly
- [ ] Check that evidence referenced properly
- [ ] Validate recommendations

**Respond to SAR:**
- [ ] Create POA&M for all findings
- [ ] Provide remediation timelines
- [ ] Document compensating controls (if applicable)
- [ ] Submit POA&M to 3PAO and FedRAMP

### Authorization Package Submission

**Package Contents:**
- [ ] Security Assessment Report (SAR)
- [ ] Plan of Action & Milestones (POA&M)
- [ ] System Security Plan (OSCAL)
- [ ] All 11 FedRAMP 20x standard documents
- [ ] All 72 KSI implementation documents
- [ ] Authorization Data Sharing API documentation
- [ ] Any additional evidence requested

**Submission Process:**
- [ ] Upload to FedRAMP portal
- [ ] Notify authorizing agency
- [ ] Provide API test credentials to FedRAMP
- [ ] Address any FedRAMP questions

## Common Audit Findings (FedRAMP 20x)

### Top 10 Most Common Findings

**1. Authorization Data Sharing API Issues**
- API not fully operational
- OSCAL format validation errors
- Stale data (> 24 hours old)
- Missing required endpoints
- Authentication issues

**Prevention:**
- Test API thoroughly before assessment
- Use OSCAL validators
- Set up automated data refresh
- Test all 6 required endpoints

**2. KSI Evidence Not Automated**
- Manual evidence collection
- Evidence not current
- No automated metrics

**Prevention:**
- Automate top 20 KSIs minimum
- Set up dashboards for all KSIs
- Test evidence collection process

**3. MFA Not Phishing-Resistant (KSI-IAM-01)**
- Using SMS or TOTP (not acceptable)
- No FIDO2/WebAuthn implementation
- Incomplete MFA coverage

**Prevention:**
- Implement FIDO2/WebAuthn or PIV/CAC
- Enforce for all users (no exceptions)
- Document implementation thoroughly

**4. Incomplete Logging (KSI-MLA-01)**
- Not all log sources captured
- Logs not centralized
- Log retention insufficient

**Prevention:**
- Inventory all log sources
- Implement centralized SIEM
- Configure 1-year retention minimum

**5. Vulnerability Remediation Delays (FRR-VDR)**
- Critical/High vulns not remediated in timeframe
- No tracking process
- Missing evidence

**Prevention:**
- Implement automated vulnerability management
- Set up alerts for overdue vulns
- Document remediation timelines

**6. Infrastructure Not as Code (KSI-MLA-05)**
- Manual infrastructure provisioning
- No IaC templates
- Configuration drift

**Prevention:**
- Migrate to Bicep/Terraform/ARM templates
- Store IaC in version control
- Use IaC for all infrastructure changes

**7. Inadequate Testing (KSI-CMT-03)**
- No automated testing in CI/CD
- Security tests not automated
- Test coverage insufficient

**Prevention:**
- Implement automated unit/integration tests
- Add security tests (SAST/DAST)
- Measure and improve coverage

**8. Incomplete System Boundary (SSP)**
- Boundary not clearly defined
- Missing interconnections
- Inaccurate architecture diagrams

**Prevention:**
- Document all system components
- List all interconnections
- Keep diagrams current

**9. Inadequate Continuous Monitoring (FRR-CCM)**
- Not truly continuous
- Manual processes dominate
- Data not real-time

**Prevention:**
- Automate as much as possible
- Implement real-time monitoring
- Update Authorization Data Sharing API daily

**10. Incomplete Documentation (General)**
- Procedures not documented
- Documentation out of date
- Missing required documents

**Prevention:**
- Use documentation_generator prompt for templates
- Keep docs in version control
- Review quarterly

### KSI-Specific Common Findings

**KSI-IAM (Identity & Access):**
- Access reviews not quarterly
- Privileged access not monitored
- Service accounts not inventoried

**KSI-MLA (Monitoring & Logging):**
- Alert rules not tuned
- No log analysis procedures
- SIEM not configured properly

**KSI-AFR (Findings & Remediation):**
- Scan coverage incomplete
- False positives not managed
- No continuous scanning

**KSI-CMT (Change & Testing):**
- Changes not approved properly
- No rollback procedures
- Testing not adequate

**KSI-INR (Incident Response):**
- No incident response tests
- Notification procedures unclear
- Post-incident reviews not conducted

**KSI-RPL (Recovery Planning):**
- Backup tests not regular
- DR plan not tested
- Recovery objectives not met

**KSI-CNA (Cloud-Native):**
- Not using cloud-native services
- No immutable infrastructure
- Container security inadequate

**KSI-SVC (Service Management):**
- SLAs not defined
- Uptime not measured
- Capacity planning inadequate

## Audit Preparation Checklist

### 12 Weeks Before Assessment

- [ ] Review all FedRAMP 20x requirements
- [ ] Identify gaps in current implementation
- [ ] Create remediation plan
- [ ] Begin documentation updates

### 8 Weeks Before Assessment

- [ ] Complete all required documentation
- [ ] Implement missing KSIs
- [ ] Set up Authorization Data Sharing API
- [ ] Begin evidence collection

### 6 Weeks Before Assessment

- [ ] Complete all KSI implementations
- [ ] Finalize Authorization Data Sharing API
- [ ] Test all procedures
- [ ] Conduct internal audit

### 4 Weeks Before Assessment

- [ ] Address internal audit findings
- [ ] Complete evidence gathering
- [ ] Test Authorization Data Sharing API
- [ ] Prepare team for interviews

### 2 Weeks Before Assessment

- [ ] Final documentation review
- [ ] Provide 3PAO access
- [ ] Confirm team availability
- [ ] Prepare demo environment

### Week of Assessment

- [ ] Daily check-ins with 3PAO
- [ ] Respond to requests promptly
- [ ] Document all conversations
- [ ] Address issues immediately

### After Assessment

- [ ] Debrief with team
- [ ] Review SAR for accuracy
- [ ] Create remediation plan
- [ ] Submit authorization package

## Resources and Tools

**Use These MCP Tools:**
- `get_control(requirement_id)` - Get specific requirement details
- `search_requirements(keywords)` - Find relevant requirements
- `get_ksi(ksi_id)` - Get KSI implementation guidance
- `get_implementation_examples(requirement_id)` - See code examples
- `validate_architecture(description)` - Validate your architecture
- `check_requirement_dependencies(requirement_id)` - Understand dependencies
- `estimate_implementation_effort(requirement_id)` - Plan remediation time

**Use These MCP Prompts:**
- `initial_assessment_roadmap` - Overall project planning
- `quarterly_review_checklist` - Continuous monitoring procedures
- `api_design_guide` - Authorization Data Sharing API design
- `ksi_implementation_priorities` - KSI implementation order
- `documentation_generator` - Documentation templates
- `migration_from_rev5` - If transitioning from Rev 5

## Success Factors

**What Makes a Successful Assessment:**
✓ Complete, accurate documentation
✓ Fully operational Authorization Data Sharing API
✓ Automated evidence collection for KSIs
✓ Well-prepared, knowledgeable team
✓ Responsive to 3PAO requests
✓ Honest communication about any gaps
✓ Quick remediation of identified issues

**Red Flags to Avoid:**
✗ Incomplete documentation
✗ API not working during assessment
✗ Team unfamiliar with procedures
✗ Evidence not available
✗ Defensive attitude toward findings
✗ Lack of preparation

Remember: The 3PAO is not your adversary. They want you to succeed. Be honest, prepared, and responsive, and you'll have a successful assessment."""


@mcp.tool()
async def get_control(control_id: str) -> str:
    """
    Get detailed information about a specific FedRAMP 20x requirement.

    Args:
        control_id: The requirement identifier (e.g., "FRD-ALL-01", "VDR-ALL-02")

    Returns:
        Detailed information about the requirement including definition,
        notes, references, and related information
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get the requirement
        req = data_loader.get_control(control_id)
        
        if not req:
            return f"Requirement {control_id} not found in FedRAMP 20x data."
        
        # Format the requirement information
        result = f"# Requirement: {req.get('id', control_id)}\n\n"
        
        # Add term if present
        if "term" in req:
            result += f"## Term: {req['term']}\n\n"
        
        # Add definition
        if "definition" in req:
            result += f"**Definition:**\n{req['definition']}\n\n"
        
        # Add alternatives
        if "alts" in req and req["alts"]:
            result += f"**Also known as:** {', '.join(req['alts'])}\n\n"
        
        # Add notes
        if "note" in req:
            result += f"**Note:**\n{req['note']}\n\n"
        elif "notes" in req and isinstance(req["notes"], list):
            result += "**Notes:**\n"
            for note in req["notes"]:
                result += f"- {note}\n"
            result += "\n"
        
        # Add references
        if "reference" in req:
            ref_url = req.get("reference_url", "")
            if ref_url:
                result += f"**Reference:** [{req['reference']}]({ref_url})\n\n"
            else:
                result += f"**Reference:** {req['reference']}\n\n"
        
        # Add document context
        result += f"**Document:** {req.get('document_name', 'Unknown')}\n"
        result += f"**Section:** {req.get('section', 'Unknown')}\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error fetching requirement {control_id}: {e}")
        return f"Error retrieving requirement {control_id}: {str(e)}"


@mcp.tool()
async def list_family_controls(family: str) -> str:
    """
    List all requirements within a specific document family.

    Args:
        family: The document family identifier (e.g., "FRD", "VDR", "CCM")

    Returns:
        List of all requirements in the specified family with brief descriptions
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get family requirements
        reqs = data_loader.get_family_controls(family)
        
        if not reqs:
            return f"No requirements found for family {family}. Common families include: FRD (FedRAMP Definitions), VDR (Vulnerability Detection and Response), CCM (Collaborative Continuous Monitoring), etc."
        
        # Format the results
        result = f"# Requirements in Family: {family.upper()}\n\n"
        result += f"Found {len(reqs)} requirements:\n\n"
        
        for req in reqs:
            req_id = req.get("id", "Unknown")
            term = req.get("term", req.get("title", "No term"))
            result += f"- **{req_id}**: {term}\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error listing family {family}: {e}")
        return f"Error retrieving family {family}: {str(e)}"


@mcp.tool()
async def search_requirements(keywords: str) -> str:
    """
    Search for FedRAMP 20x requirements containing specific keywords.

    Args:
        keywords: Keywords to search for in requirement text (space-separated)

    Returns:
        Matching requirements with IDs and relevant excerpts
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Search for requirements
        reqs = data_loader.search_controls(keywords)
        
        if not reqs:
            return f"No requirements found matching keywords: '{keywords}'"
        
        # Format the results
        result = f"# Search Results for: '{keywords}'\n\n"
        result += f"Found {len(reqs)} matching requirements:\n\n"
        
        # Limit to first 20 results to avoid overwhelming output
        for req in reqs[:20]:
            req_id = req.get("id", "Unknown")
            term = req.get("term", "")
            definition = req.get("definition", "")
            
            result += f"## {req_id}"
            if term:
                result += f": {term}"
            result += "\n"
            
            # Show a snippet of the definition
            if definition:
                snippet = definition[:200] + "..." if len(definition) > 200 else definition
                result += f"{snippet}\n\n"
            else:
                result += "Match found in requirement data.\n\n"
        
        if len(reqs) > 20:
            result += f"\n*Showing first 20 of {len(reqs)} results. Refine your search for more specific results.*\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error searching for '{keywords}': {e}")
        return f"Error searching for '{keywords}': {str(e)}"


@mcp.tool()
async def get_definition(term: str) -> str:
    """
    Get the FedRAMP definition for a specific term.

    Args:
        term: The term to look up (e.g., "vulnerability", "agency", "cloud service offering")

    Returns:
        Definition with notes and references if available
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get the definition
        definition = data_loader.get_definition(term)
        
        if not definition:
            return f"No FedRAMP definition found for term: '{term}'. Try searching with search_definitions() to find related terms."
        
        # Format the definition
        result = f"# FedRAMP Definition: {definition.get('term', term)}\n\n"
        
        # Add ID
        if "id" in definition:
            result += f"**ID:** {definition['id']}\n\n"
        
        # Add definition
        if "definition" in definition:
            result += f"**Definition:**\n{definition['definition']}\n\n"
        
        # Add alternatives
        if "alts" in definition and definition["alts"]:
            result += f"**Also known as:** {', '.join(definition['alts'])}\n\n"
        
        # Add notes
        if "note" in definition:
            result += f"**Note:**\n{definition['note']}\n\n"
        elif "notes" in definition and isinstance(definition["notes"], list):
            result += "**Notes:**\n"
            for note in definition["notes"]:
                result += f"- {note}\n"
            result += "\n"
        
        # Add references
        if "reference" in definition:
            ref_url = definition.get("reference_url", "")
            if ref_url:
                result += f"**Reference:** [{definition['reference']}]({ref_url})\n\n"
            else:
                result += f"**Reference:** {definition['reference']}\n\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error fetching definition for '{term}': {e}")
        return f"Error retrieving definition for '{term}': {str(e)}"


@mcp.tool()
async def list_definitions() -> str:
    """
    List all FedRAMP definitions with their terms.

    Returns:
        Complete list of FedRAMP definition terms
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get all definitions
        definitions = data_loader.list_all_definitions()
        
        if not definitions:
            return "No FedRAMP definitions found."
        
        # Sort by ID
        sorted_defs = sorted(definitions, key=lambda x: x.get("id", ""))
        
        # Format the results
        result = f"# FedRAMP Definitions\n\n"
        result += f"Total: {len(definitions)} definitions\n\n"
        
        for definition in sorted_defs:
            def_id = definition.get("id", "Unknown")
            term = definition.get("term", "No term")
            result += f"- **{def_id}**: {term}\n"
        
        result += "\n*Use get_definition(term) to see full details for any term.*\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error listing definitions: {e}")
        return f"Error retrieving definitions: {str(e)}"


@mcp.tool()
async def search_definitions(keywords: str) -> str:
    """
    Search FedRAMP definitions by keywords.

    Args:
        keywords: Keywords to search for in definitions

    Returns:
        Matching definitions with terms and brief descriptions
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Search definitions
        definitions = data_loader.search_definitions(keywords)
        
        if not definitions:
            return f"No definitions found matching keywords: '{keywords}'"
        
        # Format the results
        result = f"# Definition Search Results for: '{keywords}'\n\n"
        result += f"Found {len(definitions)} matching definitions:\n\n"
        
        for definition in definitions[:20]:
            def_id = definition.get("id", "Unknown")
            term = definition.get("term", "No term")
            def_text = definition.get("definition", "")
            
            result += f"## {def_id}: {term}\n"
            
            # Show a snippet
            if def_text:
                snippet = def_text[:150] + "..." if len(def_text) > 150 else def_text
                result += f"{snippet}\n\n"
        
        if len(definitions) > 20:
            result += f"\n*Showing first 20 of {len(definitions)} results.*\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error searching definitions for '{keywords}': {e}")
        return f"Error searching definitions for '{keywords}': {str(e)}"


@mcp.tool()
async def get_ksi(ksi_id: str) -> str:
    """
    Get detailed information about a specific Key Security Indicator.

    Args:
        ksi_id: The KSI identifier (e.g., "KSI-ALL-01")

    Returns:
        Detailed KSI information
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get the KSI
        ksi = data_loader.get_ksi(ksi_id)
        
        if not ksi:
            return f"Key Security Indicator {ksi_id} not found. Use list_ksi() to see all available indicators."
        
        # Format the KSI information
        result = f"# Key Security Indicator: {ksi.get('id', ksi_id)}\n\n"
        
        # Add all KSI fields
        for key, value in ksi.items():
            if key not in ["id", "document", "document_name", "section"]:
                result += f"**{key.replace('_', ' ').title()}:**\n"
                if isinstance(value, (dict, list)):
                    result += f"```json\n{json.dumps(value, indent=2)}\n```\n\n"
                else:
                    result += f"{value}\n\n"
        
        # Add context
        result += f"**Document:** {ksi.get('document_name', 'Unknown')}\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error fetching KSI {ksi_id}: {e}")
        return f"Error retrieving KSI {ksi_id}: {str(e)}"


@mcp.tool()
async def list_ksi() -> str:
    """
    List all Key Security Indicators.

    Returns:
        Complete list of all Key Security Indicators
    """
    try:
        # Ensure data is loaded
        await data_loader.load_data()
        
        # Get all KSI
        ksi_list = data_loader.list_all_ksi()
        
        if not ksi_list:
            return "No Key Security Indicators found in the data."
        
        # Sort by ID
        sorted_ksi = sorted(ksi_list, key=lambda x: x.get("id", ""))
        
        # Format the results
        result = f"# Key Security Indicators\n\n"
        result += f"Total: {len(ksi_list)} indicators\n\n"
        
        for ksi in sorted_ksi:
            ksi_id = ksi.get("id", "Unknown")
            title = ksi.get("title", ksi.get("name", "No title"))
            result += f"- **{ksi_id}**: {title}\n"
        
        result += "\n*Use get_ksi(ksi_id) to see full details for any indicator.*\n"
        
        return result
        
    except Exception as e:
        logger.error(f"Error listing KSI: {e}")
        return f"Error retrieving KSI: {str(e)}"


@mcp.tool()
async def compare_with_rev4(requirement_area: str) -> str:
    """
    Compare FedRAMP 20x requirements to Rev 4/Rev 5 to understand changes.
    
    Args:
        requirement_area: Area to compare (e.g., "continuous monitoring", "vulnerability management", 
                         "authorization boundary", "evidence collection")
    
    Returns:
        Key differences between Rev 4/5 and 20x for the specified area
    """
    comparisons = {
        "continuous monitoring": """# Continuous Monitoring: Rev 4/5 vs 20x

**Rev 4/5 Approach:**
- Annual assessments by 3PAO
- Monthly ConMon scans
- Quarterly deliverables to FedRAMP PMO
- Document-based evidence packages
- POA&M tracking in Excel/Word

**FedRAMP 20x Changes:**
- **Collaborative Continuous Monitoring (CCM)**: Real-time data sharing via APIs (FRR-CCM)
- **Quarterly Reviews**: Structured review process (FRR-CCM-QR-01 through QR-11)
- **Key Security Indicators**: 72 KSIs to track continuously
- **Authorization Data Sharing**: Machine-readable data instead of documents (FRR-ADS)
- **Persistent Validation**: Continuous assessment, not annual (FRR-PVA)

**Key Requirements:**
- FRR-CCM-01 through CCM-07: Base continuous monitoring
- KSI-MLA-01: SIEM requirement
- KSI-CMT-01: Log and monitor all changes
- FRR-PVA-01 through PVA-18: Persistent validation standards""",

        "vulnerability management": """# Vulnerability Management: Rev 4/5 vs 20x

**Rev 4/5 Approach:**
- 30-day remediation for High vulnerabilities
- POA&M tracking
- Monthly ConMon scans
- Risk-based decisions on false positives

**FedRAMP 20x Changes:**
- **Vulnerability Detection & Response Standard (VDR)**: Comprehensive timeframes by severity
- **Automated Detection**: Emphasis on continuous scanning
- **Risk-Based Timeframes**: Different deadlines based on impact level and CVSS
- **Exception Process**: Formal process for remediation extensions (FRR-VDR-EX)
- **Agency Reporting**: Must report vulnerabilities affecting agencies (FRR-VDR-RP)

**Key Timeframes (FRR-VDR-TF):**
- Critical/High + High Impact: 7-15 days
- Medium: 30-90 days  
- Low: 180 days
- Zero-day: Immediate response required

**Key Requirements:**
- FRR-VDR-01 through VDR-11: Detection and response
- FRR-VDR-TF-HI-01 through HI-09: High impact timeframes
- KSI-PIY-03: Vulnerability Disclosure Program""",

        "authorization boundary": """# Authorization Boundary: Rev 4/5 vs 20x

**Rev 4/5 Approach:**
- Static boundary in SSP
- Annual updates
- Network diagrams in Visio/Word
- Manual tracking of components

**FedRAMP 20x Changes:**
- **Minimum Assessment Scope (MAS)**: Clear definition of what must be included (FRR-MAS)
- **Information Resources**: Broader definition including non-machine resources
- **Automated Inventory**: Required automated asset discovery (KSI-PIY-01)
- **Dynamic Boundaries**: Support for elastic/cloud-native architectures
- **API-Based Documentation**: Machine-readable boundary definitions

**Must Include:**
- All systems processing Federal Customer Data
- Development/staging if they use production data
- All third-party services
- Monitoring and logging systems
- Backup/DR systems
- Non-machine resources (policies, procedures)

**Key Requirements:**
- FRR-MAS-01 through MAS-05: Minimum scope
- FRR-MAS-AY-01 through AY-06: Assessment year specifics
- KSI-PIY-01: Automated inventory
- KSI-CNA-02: Minimize attack surface""",

        "evidence collection": """# Evidence Collection: Rev 4/5 vs 20x

**Rev 4/5 Approach:**
- Document-based evidence packages
- Manual collection for annual assessments
- Screenshots and exports
- Emailed to FedRAMP PMO

**FedRAMP 20x Changes:**
- **Authorization Data Sharing (ADS)**: API-based continuous data sharing (FRR-ADS)
- **Machine-Readable**: JSON/XML instead of Word/PDF
- **Automated Collection**: "Automatically if possible" per FRD-ALL-07
- **Continuous Updates**: Real-time data instead of annual snapshots
- **Key Security Indicators**: 72 KSIs define what to track

**What to Track:**
- All 72 KSI metrics continuously
- Vulnerability scan results (API)
- Configuration baselines (IaC)
- Access logs (SIEM integration)
- Change records (automated from CI/CD)
- Incident response data
- Training completion records

**Key Requirements:**
- FRR-ADS-01 through ADS-10: Data sharing standards
- FRR-KSI-01 & KSI-02: KSI tracking requirements
- KSI-MLA-05: Infrastructure as Code
- Definition FRD-ALL-07: "Regularly" means automated""",

        "change management": """# Change Management: Rev 4/5 vs 20x

**Rev 4/5 Approach:**
- Change requests documented
- CAB approval process
- Significant changes reported to FedRAMP
- Manual change logs

**FedRAMP 20x Changes:**
- **Significant Change Notifications (SCN)**: Structured notification process (FRR-SCN)
- **Automated Change Tracking**: Required logging of all changes (KSI-CMT-01)
- **CI/CD Integration**: Automated testing and validation (KSI-CMT-03)
- **Change Types**: Clear categorization (routine/recurring, administrative, transformative, impact)
- **Immutable Infrastructure**: Emphasis on cloud-native patterns (KSI-CNA-04)

**What Triggers Notification:**
- New services/components
- Architecture changes
- New vulnerabilities affecting agencies
- Cryptographic changes
- Boundary modifications

**Key Requirements:**
- FRR-SCN-01 through SCN-10: Base notification requirements
- FRR-SCN-TR-01 through TR-07: Transformative changes
- KSI-CMT-01 through CMT-05: Change management KSIs
- KSI-CMT-02: Redeployment procedures""",

        "incident response": """# Incident Response: Rev 4/5 vs 20x

**Rev 4/5 Approach:**
- Incident response plan in SSP
- Report to US-CERT within 1 hour
- Document lessons learned
- Annual plan testing

**FedRAMP 20x Changes:**
- **Incident Communications Procedures (ICP)**: Structured communication requirements (FRR-ICP)
- **FedRAMP Security Inbox**: Central reporting mechanism (FRR-FSI, KSI-AFR-08)
- **Continuous Logging**: All incidents logged automatically (KSI-INR-02)
- **After Action Reports**: Required for significant incidents (KSI-INR-03)
- **Agency Coordination**: Must notify affected agencies

**Reporting Requirements:**
- Use FedRAMP Security Inbox for all security reports
- Report within required timeframes based on severity
- Include impact to Federal Customer Data
- Coordinate with affected agencies

**Key Requirements:**
- FRR-ICP-01 through ICP-09: Communication procedures
- FRR-FSI-01 through FSI-16: Security inbox usage
- KSI-INR-01 through INR-03: Incident response KSIs
- KSI-MLA-02: Audit logging"""
    }
    
    area_lower = requirement_area.lower()
    
    # Try to match the area
    for key, comparison in comparisons.items():
        if key in area_lower or area_lower in key:
            return comparison
    
    # No match found, provide overview
    return f"""# Rev 4/5 to 20x Comparison

I don't have specific comparison data for "{requirement_area}". 

**Available comparison areas:**
- continuous monitoring
- vulnerability management
- authorization boundary
- evidence collection
- change management
- incident response

**Major Changes Across All Areas:**
1. **Document-based → API-based**: Everything shifts to machine-readable data
2. **Annual → Continuous**: Assessment and monitoring are now continuous
3. **Manual → Automated**: Strong emphasis on automation ("automatically if possible")
4. **Static → Dynamic**: Support for cloud-native, elastic architectures
5. **72 Key Security Indicators**: New framework defining what to track
6. **Collaborative Model**: CSP, agencies, and FedRAMP share data continuously

Try searching with one of the available areas, or use search_requirements to find specific requirements."""


@mcp.tool()
async def get_implementation_examples(requirement_id: str) -> str:
    """
    Provide practical implementation examples for a specific requirement.
    
    Args:
        requirement_id: The requirement ID (e.g., "FRR-VDR-01", "KSI-IAM-01")
    
    Returns:
        Practical implementation guidance and examples
    """
    examples = {
        "KSI-IAM-01": """# Implementation Example: KSI-IAM-01 (Phishing-Resistant MFA)

**Requirement:** Implement phishing-resistant multi-factor authentication

**Good Implementations:**

1. **FIDO2/WebAuthn Hardware Keys**
   ```
   - YubiKey 5 Series
   - Google Titan Security Keys
   - Configuration: Require security key for all privileged access
   - No SMS or TOTP allowed for admin accounts
   ```

2. **Platform Authenticators**
   ```
   - Windows Hello for Business
   - Touch ID/Face ID on macOS
   - Android/iOS biometric authentication
   ```

3. **Cloud Provider Solutions**
   ```
   Azure: Conditional Access with FIDO2 keys (recommended)
   Microsoft Entra ID: Passwordless authentication
   Okta: FIDO2 WebAuthn support
   ```

**Implementation Steps:**
1. Purchase FIDO2 security keys for all users
2. Configure IdP (Microsoft Entra ID, Okta, Auth0) for FIDO2
3. Enroll users with backup keys
4. Disable SMS/TOTP for privileged accounts
5. Document in security procedures

**Anti-Patterns (Not Phishing-Resistant):**
❌ SMS one-time codes
❌ TOTP apps (Google Authenticator, Authy)
❌ Email verification codes
❌ Push notifications without device binding

**Evidence to Collect:**
- MFA configuration screenshots
- List of users with security keys
- IdP audit logs showing FIDO2 usage""",

        "KSI-MLA-01": """# Implementation Example: KSI-MLA-01 (SIEM)

**Requirement:** Implement Security Information and Event Management

**Good Implementations:**

1. **Cloud-Native SIEM**
   ```
   Microsoft Sentinel:
   - Azure-native SIEM/SOAR solution
   - Integrate with Microsoft Entra ID, Defender for Cloud
   - Create dashboards for FedRAMP KSIs
   - Set up analytics rules for security events
   
   Splunk Cloud:
   - Forward all logs via Splunk Universal Forwarder
   - Create dashboards for FedRAMP KSIs
   - Set up alerts for security events
   ```

2. **Log Sources to Include**
   ```
   ✓ Application logs (stdout/stderr)
   ✓ Web server access/error logs
   ✓ Database audit logs
   ✓ Cloud provider logs (Azure Activity Log, Azure Resource logs)
   ✓ Container/Kubernetes logs
   ✓ Authentication logs (IdP)
   ✓ Network flow logs
   ✓ Security tool output (vulnerability scanners)
   ```

3. **Architecture Example**
   ```
   Application → Azure Monitor Agent → Log Analytics → Sentinel
   Azure Activity Log → Log Analytics → Sentinel
   Kubernetes (AKS) → Container Insights → Sentinel
   ```

**Retention Requirements:**
- Security logs: 1 year minimum
- Audit logs: Per NARA requirements (usually 3+ years)
- Configure automated archival to Azure Blob Storage

**Evidence to Collect:**
- SIEM architecture diagram
- List of all log sources
- Retention policy documentation
- Sample SIEM queries/dashboards""",

        "FRR-VDR-01": """# Implementation Example: FRR-VDR-01 (Vulnerability Detection)

**Requirement:** Implement automated vulnerability detection

**Good Implementations:**

1. **Multi-Layer Scanning**
   ```
   Infrastructure: Microsoft Defender for Cloud, Tenable.io, Qualys
   Container Images: Trivy, Microsoft Defender for Containers, Snyk
   Code: GitHub Advanced Security, Snyk Code, SonarQube
   Dependencies: Dependabot, Snyk, WhiteSource
   ```

2. **Continuous Scanning Pipeline**
   ```
   git push → GitHub Actions → 
     ├─ Trivy scan (container images)
     ├─ Snyk scan (dependencies)
     ├─ SonarQube (code quality/security)
     └─ Block deployment if Critical/High found
   
   Production: Tenable.io scans every 24 hours
   ```

3. **Configuration Example (GitHub Actions)**
   ```yaml
   - name: Run Trivy vulnerability scanner
     uses: aquasecurity/trivy-action@master
     with:
       scan-type: 'image'
       image-ref: ${{ env.IMAGE }}
       severity: 'CRITICAL,HIGH'
       exit-code: '1'  # Fail build on findings
   ```

**Integration with VDR Timeframes:**
```
Critical/High → Create ticket automatically
Auto-assign to security team
Set due date per FRR-VDR-TF requirements
Send alert to Slack/PagerDuty
```

**Evidence to Collect:**
- Vulnerability scan reports
- CI/CD pipeline configurations
- Remediation tracking (Jira/GitHub Issues)
- Scan frequency proof""",

        "KSI-SVC-06": """# Implementation Example: KSI-SVC-06 (Secret Management)

**Requirement:** Implement secure secret management

**Good Implementations:**

1. **Vault Solutions**
   ```
   Azure Key Vault:
   - Azure-native secret management solution
   - Integrate with Managed Identity for authentication
   - Automatic rotation support for Azure services
   - Audit all access via Azure Monitor
   
   HashiCorp Vault:
   - Store all secrets in Vault
   - Use Kubernetes auth method
   - Rotate secrets automatically
   - Audit all access
   ```

2. **Application Integration**
   ```python
   # Good: Load from Azure Key Vault
   from azure.identity import DefaultAzureCredential
   from azure.keyvault.secrets import SecretClient
   
   credential = DefaultAzureCredential()
   client = SecretClient(vault_url="https://myvault.vault.azure.net/", credential=credential)
   db_password = client.get_secret("prod-db-password").value
   
   # Bad: Hardcoded
   db_password = "MyPassword123"  # ❌ Never do this
   ```

3. **Kubernetes Example (AKS)**
   ```yaml
   # Use Azure Key Vault Provider for Secrets Store CSI Driver
   apiVersion: secrets-store.csi.x-k8s.io/v1
   kind: SecretProviderClass
   metadata:
     name: azure-keyvault-secrets
   spec:
     provider: azure
     parameters:
       keyvaultName: "myvault"
       objects: |
         array:
           - |
             objectName: prod-db-password
             objectType: secret
       tenantId: "<tenant-id>"
   ```

**Anti-Patterns:**
❌ Secrets in environment variables
❌ Secrets in source code
❌ Secrets in container images
❌ Secrets in ConfigMaps (use Secrets with encryption)

**Evidence to Collect:**
- Secret manager architecture
- Rotation policies
- Access audit logs
- No secrets in git (use git-secrets, truffleHog)""",

        "FRR-ADS-01": """# Implementation Example: FRR-ADS-01 (Authorization Data Sharing)

**Requirement:** Share authorization data via API

**Good Implementation:**

1. **REST API Design**
   ```
   GET /api/v1/authorization-boundary
   GET /api/v1/vulnerabilities
   GET /api/v1/ksi-metrics
   GET /api/v1/incidents
   GET /api/v1/change-notifications
   
   Authentication: OAuth 2.0 or mTLS
   Format: JSON (OSCAL format preferred)
   ```

2. **OSCAL Format Example**
   ```json
   {
     "system-security-plan": {
       "uuid": "...",
       "metadata": {...},
       "system-characteristics": {
         "system-information": {...},
         "authorization-boundary": {
           "diagrams": [...],
           "components": [...]
         }
       }
     }
   }
   ```

3. **Architecture**
   ```
   FedRAMP Portal ←→ API Gateway ←→ Lambda Functions
                                  ├─ Read from Databases
                                  ├─ Query SIEM
                                  └─ Aggregate KSI data
   ```

**Data to Expose:**
- System boundary (OSCAL SSP format)
- Current vulnerabilities (OSCAL Assessment Results)
- KSI metrics (JSON)
- POA&Ms (OSCAL POA&M format)
- Recent changes/incidents

**Security:**
- Require mTLS or OAuth 2.0
- Rate limiting
- Audit all access
- Only expose to FedRAMP and authorizing agencies

**Evidence to Collect:**
- API documentation (OpenAPI/Swagger)
- Authentication configuration
- Sample API responses
- Access logs"""
    }
    
    if requirement_id in examples:
        return examples[requirement_id]
    
    # Try to provide general guidance based on requirement type
    if "IAM" in requirement_id:
        return "For IAM requirements, see KSI-IAM-01 example using get_implementation_examples('KSI-IAM-01')"
    elif "VDR" in requirement_id:
        return "For VDR requirements, see FRR-VDR-01 example using get_implementation_examples('FRR-VDR-01')"
    elif "MLA" in requirement_id:
        return "For monitoring/logging, see KSI-MLA-01 example using get_implementation_examples('KSI-MLA-01')"
    elif "SVC" in requirement_id:
        return "For service requirements, see KSI-SVC-06 example using get_implementation_examples('KSI-SVC-06')"
    elif "ADS" in requirement_id:
        return "For data sharing, see FRR-ADS-01 example using get_implementation_examples('FRR-ADS-01')"
    
    return f"""# Implementation Examples Not Available

I don't have specific implementation examples for {requirement_id} yet.

**Available examples:**
- KSI-IAM-01: Phishing-resistant MFA
- KSI-MLA-01: SIEM implementation
- FRR-VDR-01: Vulnerability scanning
- KSI-SVC-06: Secret management
- FRR-ADS-01: Authorization data sharing API

**General Implementation Steps:**
1. Use get_control('{requirement_id}') to see requirement details
2. Search for cloud-native implementations of the requirement
3. Consider automation opportunities ("automatically if possible")
4. Document your implementation for 3PAO assessment
5. Set up continuous evidence collection

Use search_requirements to find related requirements."""


@mcp.tool()
async def check_requirement_dependencies(requirement_id: str) -> str:
    """
    Show which requirements are related or dependent on a specific requirement.
    
    Args:
        requirement_id: The requirement ID to check dependencies for
    
    Returns:
        List of related and dependent requirements
    """
    dependencies = {
        "FRR-VDR": ["KSI-PIY-03 (Vulnerability Disclosure Program)", "KSI-SVC-07 (Patching)", 
                    "FRR-FSI (Security Inbox)", "FRR-CCM (Continuous Monitoring)"],
        "FRR-ADS": ["FRR-KSI (KSI Tracking)", "FRR-CCM (Continuous Monitoring)", 
                    "All KSI metrics must be shareable via API"],
        "FRR-CCM": ["FRR-ADS (Data Sharing)", "FRR-PVA (Persistent Validation)", 
                    "KSI-MLA-01 (SIEM)", "All 72 KSIs"],
        "FRR-MAS": ["KSI-PIY-01 (Automated Inventory)", "FRR-SCN (Change Notifications)", 
                    "KSI-CNA-02 (Attack Surface)"],
        "KSI-MLA-01": ["KSI-MLA-02 through MLA-08 (Related logging requirements)", 
                       "FRR-CCM (Continuous Monitoring)", "KSI-INR-02 (Incident Logging)"],
        "KSI-IAM-01": ["KSI-IAM-02 through IAM-07 (Related identity requirements)", 
                       "KSI-IAM-06 (Suspicious Activity)", "KSI-MLA-02 (Audit Logging)"],
        "FRR-SCN": ["FRR-MAS (Boundary Changes)", "FRR-VDR (New Vulnerabilities)", 
                    "KSI-CMT (Change Management)", "FRR-FSI (Notification Channel)"],
        "FRR-ICP": ["FRR-FSI (Security Inbox)", "KSI-INR (Incident Response)", 
                    "FRR-VDR (Vulnerability Reporting)"],
        "FRR-PVA": ["FRR-CCM (Continuous Monitoring)", "KSI-CNA-08 (Persistent Assessment)", 
                    "All 72 KSIs must be validated continuously"],
        "KSI-CMT-01": ["KSI-CMT-02 through CMT-05", "FRR-SCN (Change Notifications)", 
                       "KSI-MLA-02 (Audit Logging)", "KSI-CMT-03 (Automated Testing)"]
    }
    
    # Check for family match
    for family, deps in dependencies.items():
        if requirement_id.startswith(family):
            result = f"# Dependencies for {requirement_id}\n\n"
            result += f"**Related/Dependent Requirements:**\n\n"
            for dep in deps:
                result += f"- {dep}\n"
            result += f"\n**Implementation Order:**\n"
            result += f"These requirements should typically be implemented together or in sequence.\n"
            result += f"\nUse get_control() to see details for each related requirement."
            return result
    
    return f"""# Dependencies for {requirement_id}

No specific dependency mappings available for this requirement.

**General Dependency Patterns:**

**FRR-VDR** (Vulnerability) depends on:
- Vulnerability scanning tools
- FedRAMP Security Inbox for reporting
- Patching processes

**FRR-CCM** (Continuous Monitoring) depends on:
- Authorization Data Sharing API
- All 72 KSI metrics
- SIEM implementation

**FRR-ADS** (Data Sharing) depends on:
- All requirements generating data
- API infrastructure
- OSCAL format adoption

**KSI-* (Key Security Indicators)** depend on:
- Automated collection tools
- SIEM/monitoring platform
- Continuous data pipelines

Use search_requirements to find requirements that mention '{requirement_id}'."""


@mcp.tool()
async def estimate_implementation_effort(requirement_id: str) -> str:
    """
    Provide rough effort estimates for implementing a specific requirement.
    
    Args:
        requirement_id: The requirement ID to estimate
    
    Returns:
        Effort estimation and timeline guidance
    """
    estimates = {
        "KSI-IAM-01": """# Effort Estimate: KSI-IAM-01 (Phishing-Resistant MFA)

**Timeline:** 2-4 weeks

**Effort Breakdown:**
- Planning & key procurement: 3-5 days
- IdP configuration: 2-3 days
- User enrollment: 1-2 weeks (depends on user count)
- Documentation: 2-3 days
- Testing & validation: 3-5 days

**Team Required:**
- Identity/Access Management engineer (lead)
- Security engineer (validation)
- IT support (user enrollment)

**Costs:**
- Hardware keys: $20-50 per user
- IdP licensing: May require higher tier (check current plan)
- Staff time: ~2-3 person-weeks

**Complexity:** Medium
**Blocker Risk:** Low - well-established technology""",

        "KSI-MLA-01": """# Effort Estimate: KSI-MLA-01 (SIEM Implementation)

**Timeline:** 6-12 weeks

**Effort Breakdown:**
- SIEM selection/procurement: 2-3 weeks
- Architecture design: 1 week
- Log source integration: 3-4 weeks
- Dashboard/alert creation: 2-3 weeks
- Retention configuration: 1 week
- Documentation: 1 week
- Testing: 1-2 weeks

**Team Required:**
- Security engineer (lead)
- DevOps/SRE (log integration)
- Cloud architect (design)
- Application teams (log format standardization)

**Costs:**
- SIEM licensing: $50K-200K+/year (depends on log volume)
- Implementation services: $30K-100K (if using vendor)
- Staff time: ~8-12 person-weeks

**Complexity:** High
**Blocker Risk:** Medium - requires coordination across teams""",

        "FRR-VDR-01": """# Effort Estimate: FRR-VDR-01 (Vulnerability Detection)

**Timeline:** 4-8 weeks

**Effort Breakdown:**
- Tool selection: 1-2 weeks
- Scanner deployment: 1 week
- CI/CD integration: 2-3 weeks
- Baseline scan & triage: 2-3 weeks
- Remediation workflow: 1 week
- Documentation: 1 week

**Team Required:**
- Security engineer (lead)
- DevOps engineer (CI/CD integration)
- Development team (remediation)

**Costs:**
- Scanning tools: $10K-50K/year
- Staff time: ~6-10 person-weeks

**Complexity:** Medium
**Blocker Risk:** High - initial scan will find many vulnerabilities requiring remediation""",

        "FRR-ADS-01": """# Effort Estimate: FRR-ADS-01 (Authorization Data Sharing API)

**Timeline:** 12-16 weeks

**Effort Breakdown:**
- API design (OSCAL format): 2-3 weeks
- Backend development: 4-6 weeks
- Authentication/authorization: 2 weeks
- Data aggregation from sources: 3-4 weeks
- Testing: 2 weeks
- Documentation: 1-2 weeks
- FedRAMP review: 2-3 weeks

**Team Required:**
- Backend developer (lead)
- Security engineer (authentication)
- DevOps (deployment)
- Compliance PM (requirements)

**Costs:**
- Infrastructure: $500-2000/month
- Staff time: ~16-20 person-weeks

**Complexity:** High
**Blocker Risk:** High - requires all other data sources to be ready""",

        "FRR-CCM": """# Effort Estimate: FRR-CCM (Collaborative Continuous Monitoring)

**Timeline:** 16-24 weeks (most complex)

**Effort Breakdown:**
- Planning & architecture: 3-4 weeks
- KSI metric collection: 6-8 weeks
- Data sharing API: 4-6 weeks
- Quarterly review process: 2 weeks
- Integration testing: 3-4 weeks
- Documentation: 2-3 weeks

**Team Required:**
- Program manager (lead)
- Security engineers (3-4)
- DevOps engineers (2-3)
- Compliance specialist

**Costs:**
- Tooling: $100K-300K/year
- Staff time: ~40-50 person-weeks

**Complexity:** Very High
**Blocker Risk:** High - depends on many other requirements

**Prerequisites:**
- SIEM (KSI-MLA-01)
- Vulnerability scanning (FRR-VDR)
- All 72 KSI collection methods
- Authorization Data Sharing API (FRR-ADS)"""
    }
    
    # Check for family-level estimates
    if "CCM" in requirement_id:
        return estimates.get("FRR-CCM", "See FRR-CCM for family estimate")
    
    if requirement_id in estimates:
        return estimates[requirement_id]
    
    # Provide general guidance
    return f"""# Effort Estimate: {requirement_id}

**General Estimation Factors:**

**Complexity Levels:**
- **Low (1-3 weeks)**: Configuration changes, policy updates, simple tools
- **Medium (4-8 weeks)**: Tool implementation, integration work, process changes
- **High (8-16 weeks)**: Custom development, multiple tool integration, org change
- **Very High (16+ weeks)**: Platform-wide changes, cultural shifts, complex automation

**Common Time Sinks:**
- Procurement/vendor selection: Add 2-4 weeks
- Cross-team coordination: Add 25-50% to estimates
- Legacy system integration: Add 50-100% to estimates
- Cultural/process change: Add 2-4 weeks for each team affected

**Available Detailed Estimates:**
- KSI-IAM-01: MFA (2-4 weeks)
- KSI-MLA-01: SIEM (6-12 weeks)
- FRR-VDR-01: Vulnerability scanning (4-8 weeks)
- FRR-ADS-01: Data sharing API (12-16 weeks)
- FRR-CCM: Continuous monitoring (16-24 weeks)

Use get_control('{requirement_id}') to understand scope, then estimate based on:
1. Technical complexity
2. Organizational readiness
3. Existing tooling
4. Team availability"""


@mcp.tool()
async def get_cloud_native_guidance(technology: str) -> str:
    """
    Get cloud-native specific guidance for implementing FedRAMP 20x.
    
    Args:
        technology: Cloud-native technology (e.g., "kubernetes", "containers", "serverless", "terraform")
    
    Returns:
        Cloud-native implementation guidance
    """
    guidance = {
        "kubernetes": """# FedRAMP 20x for Kubernetes (AKS)

**Key Requirements:**

**1. Container Scanning (FRR-VDR, KSI-PIY-05)**
```yaml
# Scan images in CI/CD
- name: Scan container image
  uses: aquasecurity/trivy-action@master
  with:
    severity: 'CRITICAL,HIGH'
    exit-code: '1'
```

**2. Immutable Infrastructure (KSI-CNA-04)**
- Use immutable container images
- Never SSH into pods to make changes
- Redeploy rather than patch in place
- Tag images with git commit SHA

**3. Network Policies (KSI-CNA-01, CNA-03)**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  # Then create specific allow rules
```

**4. Secret Management (KSI-SVC-06)**
```yaml
# Use Azure Key Vault Provider for Secrets Store CSI Driver
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: azure-keyvault-secrets
spec:
  provider: azure
  parameters:
    usePodIdentity: "true"  # Or use Managed Identity
    keyvaultName: "myvault"
    objects: |
      array:
        - |
          objectName: db-password
          objectType: secret
    tenantId: "<tenant-id>"
```

**5. Logging (KSI-MLA-01, MLA-02)**
```bash
# AKS automatically forwards logs to Azure Monitor/Container Insights
# Enable Container Insights on your AKS cluster:
az aks enable-addons -a monitoring -n myAKSCluster -g myResourceGroup

# Logs flow: AKS → Log Analytics → Sentinel
# Query logs in Log Analytics or Sentinel
```

**6. Monitoring (KSI-MLA-01, KSI-CNA-08)**
- Use Azure Monitor for metrics and Container Insights
- Configure Microsoft Defender for Containers for runtime security
- Use Azure Policy for Kubernetes admission control

**7. Authorization Boundary (FRR-MAS)**
Must include:
- All namespaces
- Control plane components
- Ingress controllers
- Service mesh (if used)
- CI/CD pipelines that deploy to cluster

**Tools:**
- Trivy/Snyk: Container scanning
- Falco: Runtime security
- OPA/Kyverno: Policy enforcement
- External Secrets: Secret management
- Fluent Bit: Log forwarding""",

        "containers": """# FedRAMP 20x for Containers

**Key Requirements:**

**1. Image Scanning (FRR-VDR)**
```dockerfile
# Use minimal base images
FROM cgr.dev/chainguard/python:latest-dev AS builder
# Better than: FROM python:3.11 (many vulnerabilities)

# Scan in CI/CD
docker run aquasec/trivy image myapp:latest
```

**2. Image Signing (KSI-SVC-05, SVC-09)**
```bash
# Use Azure Container Registry content trust or Notation
# Enable content trust in ACR:
az acr config content-trust update --registry myregistry --status enabled

# Or use Notation with Azure Key Vault:
notation sign myregistry.azurecr.io/myapp:v1.0.0
notation verify myregistry.azurecr.io/myapp:v1.0.0
```

**3. Runtime Security (KSI-CNA-05, CNA-08)**
- Use minimal base images (distroless, Alpine)
- Run as non-root user
- Use read-only root filesystem
- Drop all capabilities

```dockerfile
FROM mcr.microsoft.com/cbl-mariner/distroless/minimal:2.0
USER nonroot:nonroot
COPY --chown=nonroot:nonroot app /app
```

**4. Secret Management (KSI-SVC-06)**
❌ Never bake secrets into images
❌ Don't use ENV vars for secrets
✓ Mount secrets at runtime from vault
✓ Use cloud provider secret services

**5. Logging (KSI-MLA-02)**
```python
# Log to stdout/stderr (12-factor)
import logging
logging.basicConfig(stream=sys.stdout, level=logging.INFO)
# Container runtime forwards to SIEM
```

**6. Patching (KSI-SVC-07)**
- Rebuild images regularly (weekly minimum)
- Automate with Renovate/Dependabot
- Use tag pinning: `image:v1.2.3` not `image:latest`

**Best Practices:**
- Multi-stage builds to minimize size
- .dockerignore to prevent secret leakage
- Scan images before push and on schedule
- Use private registries with RBAC
- Implement image promotion (dev → staging → prod)""",

        "serverless": """# FedRAMP 20x for Serverless (Azure Functions, AWS Lambda)

**Key Requirements:**

**1. Function Scanning (FRR-VDR)**
```yaml
# Scan dependencies in CI/CD
- name: Scan Python dependencies
  run: |
    pip install safety
    safety check
    
# Scan IaC templates
- name: Scan Terraform
  uses: aquasecurity/tfsec-action@v1.0.0
```

**2. Secret Management (KSI-SVC-06)**
```python
# Azure Functions example with Managed Identity
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
import azure.functions as func

def main(req: func.HttpRequest) -> func.HttpResponse:
    # Use Managed Identity - no credentials needed!
    credential = DefaultAzureCredential()
    client = SecretClient(
        vault_url="https://myvault.vault.azure.net/",
        credential=credential
    )
    db_password = client.get_secret("prod-db-password").value
    # Use password...
```

**3. Logging (KSI-MLA-01, MLA-02)**
```python
import json
import logging
import azure.functions as func

def main(req: func.HttpRequest, context: func.Context) -> func.HttpResponse:
    # Structured logging to Application Insights
    logging.info(json.dumps({
        'level': 'INFO',
        'message': 'Processing request',
        'invocation_id': context.invocation_id,
        'user_id': req.params.get('user_id')
    }))
    
    # Logs go to Application Insights → Log Analytics → Sentinel
```

**4. IAM/Authorization (KSI-IAM-05)**
```bicep
// Principle of least privilege with Managed Identity
resource functionApp 'Microsoft.Web/sites@2022-03-01' = {
  name: 'myFunctionApp'
  kind: 'functionapp'
  identity: {
    type: 'SystemAssigned'
  }
}

// Grant only specific permissions needed
resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  scope: storageAccount
  name: guid(functionApp.id, 'Storage Blob Data Reader')
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '2a2b9908-6ea1-4ae2-8e65-a410df84e7d1')
    principalId: functionApp.identity.principalId
  }
}
```

**5. Monitoring (KSI-CNA-08)**
- Enable Application Insights for tracing
- Azure Monitor metrics/alerts
- Integrate with Sentinel (SIEM)

**6. Authorization Boundary (FRR-MAS)**
Must include:
- All Azure Functions
- API Management/Application Gateway
- Event sources (Service Bus, Event Grid, Blob Storage)
- Managed Identities
- Secrets in Key Vault

**7. Change Management (KSI-CMT-03)**
```yaml
# Automated testing
- name: Run tests
  run: pytest tests/
  
- name: Deploy to staging
  if: success()
  run: serverless deploy --stage staging
  
- name: Run integration tests
  run: pytest tests/integration/
  
- name: Deploy to prod
  if: success()
  run: serverless deploy --stage prod
```

**Best Practices:**
- Use IaC (Bicep, Terraform, ARM templates)
- Enable function versioning and deployment slots
- Implement gradual rollouts with deployment slots
- Set memory/timeout limits appropriately
- Use VPC for database access""",

        "terraform": """# FedRAMP 20x for Terraform (IaC)

**Key Requirements:**

**1. Infrastructure as Code (KSI-MLA-05)**
```hcl
# Everything in Terraform with Azure Provider
resource "azurerm_linux_virtual_machine" "web" {
  name                = "web-server"
  resource_group_name = azurerm_resource_group.main.name
  location            = azurerm_resource_group.main.location
  size                = "Standard_D2s_v3"
  
  # Network interface
  network_interface_ids = [azurerm_network_interface.web.id]
  
  # Encrypted OS disk (required for FedRAMP)
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
    disk_encryption_set_id = azurerm_disk_encryption_set.main.id
  }
  
  # Boot diagnostics (monitoring)
  boot_diagnostics {
    storage_account_uri = azurerm_storage_account.diagnostics.primary_blob_endpoint
  }
  
  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
  
  tags = {
    Name        = "web-server"
    Environment = "production"
    ManagedBy   = "terraform"
  }
}
```

**2. Configuration Scanning (FRR-VDR, KSI-PIY-05)**
```yaml
# GitHub Actions
- name: tfsec
  uses: aquasecurity/tfsec-action@v1.0.0
  
- name: Checkov
  uses: bridgecrewio/checkov-action@master
  
- name: Terraform validate
  run: terraform validate
```

**3. State File Security (KSI-SVC-06)**
```hcl
# Remote state with encryption in Azure Storage
terraform {
  backend "azurerm" {
    resource_group_name  = "terraform-state-rg"
    storage_account_name = "tfstatestorage"
    container_name       = "tfstate"
    key                  = "prod.terraform.tfstate"
    
    # Enable encryption at rest (automatic with Azure Storage)
    # Use customer-managed keys for additional security
    use_azuread_auth = true  # Use Managed Identity
  }
}
```

**4. Automated Inventory (KSI-PIY-01)**
```bash
# Terraform maintains inventory
terraform state list
terraform show -json | jq '.values.root_module.resources'

# Export to CMDB/asset inventory
```

**5. Change Management (KSI-CMT-01, FRR-SCN)**
```yaml
# Pull request workflow
- name: Terraform plan
  run: terraform plan -out=tfplan
  
- name: Save plan
  run: terraform show -json tfplan > plan.json
  
- name: Comment PR with changes
  uses: actions/github-script@v6
  # Shows what will change before apply
```

**6. Recommended Secure Configuration (FRR-RSC)**
```hcl
# Compliance module
module "fedramp_baseline" {
  source = "./modules/fedramp-baseline"
  
  # Enforces:
  # - Encryption at rest
  # - Encryption in transit
  # - No public access
  # - Logging enabled
  # - Monitoring enabled
}
```

**7. Documentation (FRR-MAS, FRR-ADS)**
```hcl
# Self-documenting infrastructure
resource "azurerm_linux_virtual_machine" "web" {
  # Documentation as code
  tags = {
    Name        = "web-server"
    Description = "Main web application server"
    DataClass   = "federal-customer-data"
    Boundary    = "included"
    Owner       = "engineering@example.com"
  }
}
```

**Best Practices:**
- Use modules for reusability
- Enable Terraform Cloud/Enterprise for audit logs
- Implement policy as code (Sentinel/OPA)
- Never commit secrets (use data sources)
- Use workspaces for environments
- Tag all resources consistently

**Required Tools:**
- tfsec: Security scanning
- Checkov: Policy checking
- Terraform validate: Syntax validation
- terraform-docs: Auto-generate docs
- Atlantis: PR automation"""
    }
    
    tech_lower = technology.lower()
    
    for key, content in guidance.items():
        if key in tech_lower or tech_lower in key:
            return content
    
    return f"""# Cloud-Native Guidance

I don't have specific guidance for "{technology}". 

**Available guidance:**
- kubernetes
- containers (Docker)
- serverless (Lambda, Cloud Functions)
- terraform (Infrastructure as Code)

**General Cloud-Native Principles for FedRAMP 20x:**

1. **Immutable Infrastructure** (KSI-CNA-04)
   - Deploy, don't modify in place
   - Infrastructure as Code
   - Automated builds

2. **Automation** (FRD-ALL-07: "automatically if possible")
   - CI/CD for all deployments
   - Automated testing
   - Automated security scanning

3. **Observability** (KSI-MLA-01)
   - Centralized logging
   - Distributed tracing
   - Metrics collection

4. **Security by Default**
   - Least privilege IAM
   - Network segmentation
   - Encryption everywhere

5. **API-First** (FRR-ADS)
   - Everything exposed as APIs
   - Machine-readable configs
   - Programmatic access

Use search_requirements with your technology name to find specific requirements."""


@mcp.tool()
async def validate_architecture(architecture_description: str) -> str:
    """
    Review an architecture description against FedRAMP 20x requirements.
    
    Args:
        architecture_description: Description of your system architecture
    
    Returns:
        Validation results and recommendations
    """
    # Analyze the description for key patterns
    desc_lower = architecture_description.lower()
    
    findings = []
    recommendations = []
    
    # Check for key components
    if "kubernetes" in desc_lower or "k8s" in desc_lower or "aks" in desc_lower:
        findings.append("✓ Kubernetes/AKS detected - ensure KSI-CNA-04 (Immutable Infrastructure) compliance")
        recommendations.append("Implement network policies (KSI-CNA-01) and Azure Policy for AKS")
    
    if "lambda" in desc_lower or "serverless" in desc_lower or "azure functions" in desc_lower or "function app" in desc_lower:
        findings.append("✓ Serverless detected - ensure function-level identity/RBAC (KSI-IAM-05)")
        recommendations.append("Enable Application Insights and forward logs to Sentinel (SIEM)")
    
    if "database" in desc_lower or "rds" in desc_lower or "postgres" in desc_lower or "azure sql" in desc_lower or "cosmos" in desc_lower:
        findings.append("✓ Database detected - ensure encryption at rest and in transit (TDE for Azure SQL)")
        recommendations.append("Verify audit logging enabled (KSI-MLA-02) and backed up (KSI-RPL-03)")
    
    if "api" in desc_lower or "rest" in desc_lower:
        findings.append("✓ API detected - consider for Authorization Data Sharing (FRR-ADS)")
        recommendations.append("Implement OAuth 2.0 or mTLS authentication")
    
    # Check for security concerns
    concerns = []
    
    if "public" in desc_lower and "internet" in desc_lower:
        concerns.append("⚠ Public internet exposure detected - ensure WAF and DDoS protection")
        concerns.append("⚠ Review KSI-CNA-01 (Restrict Network Traffic) carefully")
    
    if "ssh" in desc_lower or "bastion" in desc_lower:
        concerns.append("⚠ SSH access detected - consider Session Manager instead")
        concerns.append("⚠ If SSH required, ensure phishing-resistant MFA (KSI-IAM-01)")
    
    if "password" in desc_lower or "credentials" in desc_lower:
        concerns.append("⚠ Credential management mentioned - ensure secret manager (KSI-SVC-06)")
    
    # Check for missing components
    missing = []
    
    if "log" not in desc_lower and "siem" not in desc_lower:
        missing.append("❌ No logging/SIEM mentioned - required by KSI-MLA-01")
    
    if "monitor" not in desc_lower:
        missing.append("❌ No monitoring mentioned - required by FRR-CCM")
    
    if "backup" not in desc_lower:
        missing.append("❌ No backup mentioned - required by KSI-RPL-03")
    
    if "vulnerability" not in desc_lower and "scan" not in desc_lower:
        missing.append("❌ No vulnerability scanning mentioned - required by FRR-VDR")
    
    # Build result
    result = f"# Architecture Validation Results\n\n"
    
    if findings:
        result += "## Components Identified\n\n"
        for finding in findings:
            result += f"{finding}\n"
        result += "\n"
    
    if concerns:
        result += "## Security Concerns\n\n"
        for concern in concerns:
            result += f"{concern}\n"
        result += "\n"
    
    if missing:
        result += "## Missing Components\n\n"
        for item in missing:
            result += f"{item}\n"
        result += "\n"
    
    if recommendations:
        result += "## Recommendations\n\n"
        for rec in recommendations:
            result += f"• {rec}\n"
        result += "\n"
    
    result += """## Key Areas to Address

**1. Authorization Boundary (FRR-MAS)**
- Document all components processing Federal Customer Data
- Include dev/staging if they use prod data
- Include all third-party services

**2. Continuous Monitoring (FRR-CCM)**
- SIEM for centralized logging
- Vulnerability scanning (automated)
- KSI metric collection

**3. Data Sharing (FRR-ADS)**
- API for sharing authorization data
- OSCAL format preferred
- OAuth 2.0 or mTLS authentication

**4. Key Security Indicators**
- Track all 72 KSIs continuously
- Automate collection where possible
- Integrate with SIEM/monitoring

Use search_requirements and get_implementation_examples for specific requirements."""
    
    return result


def main():
    """Run the FedRAMP 20x MCP server."""
    logger.info("Starting FedRAMP 20x MCP Server")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
