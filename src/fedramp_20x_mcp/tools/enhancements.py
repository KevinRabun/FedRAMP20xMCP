"""
FedRAMP 20x MCP Server - Enhancements Tools

This module contains tool implementation functions for enhancements.
"""
import json
import logging
from typing import Any

logger = logging.getLogger(__name__)

async def compare_with_rev4_impl(requirement_area: str, data_loader) -> str:
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



async def get_implementation_examples_impl(requirement_id: str, data_loader) -> str:
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
   Format: Machine-readable (JSON/XML required; OSCAL is one optional NIST standard approach)
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



async def check_requirement_dependencies_impl(requirement_id: str, data_loader) -> str:
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



async def estimate_implementation_effort_impl(requirement_id: str, data_loader) -> str:
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



async def get_cloud_native_guidance_impl(technology: str, data_loader) -> str:
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
# Per Azure WAF Security pillar: https://learn.microsoft.com/azure/aks/csi-secrets-store-driver
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
- Use Azure Monitor for metrics and Container Insights per Azure WAF Operational Excellence
- Configure Microsoft Defender for Containers for runtime security (Azure WAF Security: https://learn.microsoft.com/azure/defender-for-cloud/defender-for-containers-introduction)
- Use Azure Policy for Kubernetes admission control per Azure WAF Governance

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
# Per Azure WAF Security: https://learn.microsoft.com/azure/container-registry/container-registry-content-trust
# Enable content trust in ACR:
az acr config content-trust update --registry myregistry --status enabled

# Or use Notation with Azure Key Vault:
notation sign myregistry.azurecr.io/myapp:v1.0.0
notation verify myregistry.azurecr.io/myapp:v1.0.0
```

**3. Runtime Security (KSI-CNA-05, KSI-CNA-08)**
- Use minimal base images (distroless, Alpine) per Azure WAF Security best practices
- Run as non-root user
- Use read-only root filesystem
- Drop all capabilities

```dockerfile
# Use Microsoft-maintained distroless images per Azure CAF
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
# Per Azure WAF Security and Azure Functions best practices: https://learn.microsoft.com/azure/azure-functions/security-concepts
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

4. **Security by Default** (Azure WAF Security Pillar)
   - Least privilege IAM (KSI-IAM-05)
   - Network segmentation (KSI-CNA-01)
   - Encryption everywhere (Azure WAF: https://learn.microsoft.com/azure/security/fundamentals/encryption-overview)

5. **API-First** (FRR-ADS)
   - Everything exposed as APIs
   - Machine-readable configs
   - Programmatic access

Use search_requirements with your technology name to find specific requirements."""



async def validate_architecture_impl(architecture_description: str, data_loader) -> str:
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
        recommendations.append("Implement network policies per KSI-CNA-01 using Azure Policy for AKS (Azure WAF: https://learn.microsoft.com/azure/aks/best-practices)")
    
    if "lambda" in desc_lower or "serverless" in desc_lower or "azure functions" in desc_lower or "function app" in desc_lower:
        findings.append("✓ Serverless detected - ensure function-level identity/RBAC per KSI-IAM-05")
        recommendations.append("Enable Application Insights per Azure WAF Operational Excellence and forward to Sentinel for KSI-MLA-01 compliance (https://learn.microsoft.com/azure/azure-functions/security-concepts)")
    
    if "database" in desc_lower or "rds" in desc_lower or "postgres" in desc_lower or "azure sql" in desc_lower or "cosmos" in desc_lower:
        findings.append("✓ Database detected - ensure encryption per Azure WAF Security pillar (TDE for Azure SQL: https://learn.microsoft.com/azure/azure-sql/database/transparent-data-encryption-tde-overview)")
        recommendations.append("Verify audit logging enabled per KSI-MLA-02 and backed up per KSI-RPL-03 (Azure WAF Reliability: https://learn.microsoft.com/azure/well-architected/reliability/)")
    
    if "api" in desc_lower or "rest" in desc_lower:
        findings.append("✓ API detected - consider for Authorization Data Sharing (FRR-ADS)")
        recommendations.append("Implement OAuth 2.0 or mTLS authentication")
    
    # Check for security concerns
    concerns = []
    
    if "public" in desc_lower and "internet" in desc_lower:
        concerns.append("⚠ Public internet exposure detected - ensure WAF and DDoS protection (Azure WAF: https://learn.microsoft.com/azure/web-application-firewall/)")
        concerns.append("⚠ Review KSI-CNA-01 (Restrict Network Traffic) carefully")
    
    if "ssh" in desc_lower or "bastion" in desc_lower:
        concerns.append("⚠ SSH access detected - consider Azure Bastion for secure RDP/SSH per Azure WAF Security (https://learn.microsoft.com/azure/bastion/bastion-overview)")
        concerns.append("⚠ If SSH required, ensure phishing-resistant MFA per KSI-IAM-01")
    
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
- Machine-readable format required (JSON/XML); OSCAL is one optional NIST standard approach
- OAuth 2.0 or mTLS authentication

**4. Key Security Indicators**
- Track all 72 KSIs continuously
- Automate collection where possible
- Integrate with SIEM/monitoring

Use search_requirements and get_implementation_examples for specific requirements."""
    
    return result



async def get_ksi_implementation_matrix_impl(ksi_family: str, data_loader) -> str:
    """
    Get implementation matrix showing all KSIs in a family with Azure services, effort, and priority.
    
    Provides engineers with a high-level view of what needs to be implemented for a KSI family,
    including recommended Azure services, complexity, and suggested implementation order.
    
    Args:
        ksi_family: KSI family code (e.g., "IAM", "MLA", "CNA", "AFR", "SVC", "RPL", "TPR", "INR", "PIY", "CMT")
    
    Returns:
        Implementation matrix with all KSIs in the family
    """
    await data_loader.load_data()
    
    family_upper = ksi_family.upper()
    
    # Get all KSIs for this family
    all_ksis = data_loader.list_all_ksi()
    family_ksis = [k for k in all_ksis if k.get('id', '').startswith(f'KSI-{family_upper}-')]
    
    if not family_ksis:
        available_families = sorted(set(k.get('id', '').split('-')[1] for k in all_ksis if '-' in k.get('id', '')))
        return f"""No KSIs found for family '{ksi_family}'.

**Available KSI Families:**
{', '.join(available_families)}

Use get_ksi_implementation_matrix with one of the above family codes."""
    
    family_name_map = {
        'IAM': 'Identity and Access Management',
        'MLA': 'Monitoring, Logging, and Auditing',
        'AFR': 'Automated Findings and Remediation',
        'CNA': 'Cloud-Native Architecture',
        'SVC': 'Service Management',
        'RPL': 'Recovery and Planning',
        'TPR': 'Third-Party Risk',
        'INR': 'Incident Response',
        'PIY': 'Privacy and Inventory',
        'CMT': 'Change Management and Testing'
    }
    
    azure_services_map = {
        'IAM': ['Microsoft Entra ID', 'Conditional Access', 'Privileged Identity Management', 'Azure RBAC', 'Microsoft Entra ID Protection'],
        'MLA': ['Azure Monitor', 'Log Analytics', 'Microsoft Sentinel', 'Application Insights', 'Azure Policy', 'Azure Automation'],
        'AFR': ['Microsoft Defender for Cloud', 'Microsoft Defender for Containers', 'Azure Policy', 'Azure Security Center', 'GitHub Advanced Security'],
        'CNA': ['Azure Kubernetes Service', 'Azure Container Registry', 'Azure Policy for AKS', 'Azure Firewall', 'Azure Virtual Network'],
        'SVC': ['Azure Key Vault', 'Azure Automation', 'Azure Update Management', 'Azure Backup', 'Azure Monitor'],
        'RPL': ['Azure Backup', 'Azure Site Recovery', 'Azure Blob Storage', 'Recovery Services Vault', 'Azure Policy'],
        'TPR': ['Microsoft Purview', 'Azure Policy', 'Microsoft Defender for Cloud', 'Azure Security Center'],
        'INR': ['Microsoft Sentinel', 'Azure Logic Apps', 'Azure Monitor', 'Microsoft Defender XDR', 'Azure Automation'],
        'PIY': ['Microsoft Purview', 'Azure Resource Graph', 'Azure Policy', 'Microsoft Defender for Cloud', 'Azure Automation'],
        'CMT': ['Azure DevOps', 'GitHub Actions', 'Azure Policy', 'Azure Monitor', 'Azure Automation', 'Azure Resource Manager']
    }
    
    complexity_map = {
        'KSI-IAM-01': 'Medium', 'KSI-IAM-02': 'Medium', 'KSI-IAM-03': 'Low', 'KSI-IAM-04': 'Low', 'KSI-IAM-05': 'Medium', 'KSI-IAM-06': 'High', 'KSI-IAM-07': 'Medium',
        'KSI-MLA-01': 'High', 'KSI-MLA-02': 'High', 'KSI-MLA-03': 'Medium', 'KSI-MLA-04': 'Medium', 'KSI-MLA-05': 'High', 'KSI-MLA-06': 'Low', 'KSI-MLA-07': 'Low', 'KSI-MLA-08': 'Medium',
        'KSI-AFR-01': 'Medium', 'KSI-AFR-02': 'High', 'KSI-AFR-03': 'Medium', 'KSI-AFR-04': 'Medium', 'KSI-AFR-05': 'Low',
        'KSI-CNA-01': 'Medium', 'KSI-CNA-02': 'Low', 'KSI-CNA-03': 'Medium', 'KSI-CNA-04': 'High', 'KSI-CNA-05': 'Medium', 'KSI-CNA-06': 'High', 'KSI-CNA-07': 'Medium', 'KSI-CNA-08': 'High',
        'KSI-SVC-01': 'Medium', 'KSI-SVC-02': 'Medium', 'KSI-SVC-03': 'Medium', 'KSI-SVC-04': 'High', 'KSI-SVC-05': 'High', 'KSI-SVC-06': 'High', 'KSI-SVC-07': 'Medium', 'KSI-SVC-08': 'Low', 'KSI-SVC-09': 'Medium',
        'KSI-RPL-01': 'Medium', 'KSI-RPL-02': 'Medium', 'KSI-RPL-03': 'High', 'KSI-RPL-04': 'Medium',
        'KSI-TPR-01': 'Low', 'KSI-TPR-02': 'Medium', 'KSI-TPR-03': 'Medium', 'KSI-TPR-04': 'High',
        'KSI-INR-01': 'Medium', 'KSI-INR-02': 'Medium', 'KSI-INR-03': 'Low',
        'KSI-PIY-01': 'High', 'KSI-PIY-02': 'Medium', 'KSI-PIY-03': 'Low', 'KSI-PIY-04': 'Medium', 'KSI-PIY-05': 'Medium',
        'KSI-CMT-01': 'High', 'KSI-CMT-02': 'Medium', 'KSI-CMT-03': 'High', 'KSI-CMT-04': 'Medium', 'KSI-CMT-05': 'Low'
    }
    
    priority_map = {
        'KSI-IAM-01': 'Critical', 'KSI-MLA-01': 'Critical', 'KSI-MLA-02': 'Critical', 'KSI-AFR-01': 'Critical', 'KSI-SVC-06': 'Critical',
        'KSI-IAM-02': 'High', 'KSI-IAM-05': 'High', 'KSI-CNA-04': 'High', 'KSI-CNA-08': 'High', 'KSI-RPL-03': 'High', 'KSI-PIY-01': 'High', 'KSI-CMT-01': 'High', 'KSI-CMT-03': 'High',
    }
    
    family_name = family_name_map.get(family_upper, family_upper)
    azure_services = azure_services_map.get(family_upper, ['Microsoft Entra ID', 'Azure Monitor', 'Azure Policy'])
    
    result = f"""# {family_upper} Implementation Matrix: {family_name}

## Overview

**KSI Count:** {len(family_ksis)} KSIs in this family
**Recommended Azure Services:**
"""
    
    for service in azure_services:
        result += f"- {service}\n"
    
    result += f"""

## Implementation Matrix

| KSI ID | Name | Complexity | Priority | Estimated Effort |
|--------|------|------------|----------|------------------|
"""
    
    for ksi in sorted(family_ksis, key=lambda x: x.get('id', '')):
        ksi_id = ksi.get('id', 'N/A')
        name = ksi.get('name', 'N/A')
        complexity = complexity_map.get(ksi_id, 'Medium')
        priority = priority_map.get(ksi_id, 'Medium')
        
        effort_map = {
            'Low': '1-2 weeks',
            'Medium': '3-4 weeks',
            'High': '6-8 weeks'
        }
        effort = effort_map.get(complexity, '3-4 weeks')
        
        result += f"| {ksi_id} | {name[:40]}... | {complexity} | {priority} | {effort} |\n"
    
    result += f"""

## Suggested Implementation Order

### Phase 1: Foundation (Critical Priority)
"""
    
    critical = [k for k in family_ksis if priority_map.get(k.get('id'), 'Medium') == 'Critical']
    if critical:
        for ksi in critical:
            result += f"1. **{ksi.get('id')}**: {ksi.get('name')}\n"
    else:
        result += "*No critical priority items in this family*\n"
    
    result += f"""

### Phase 2: Core Capabilities (High Priority)
"""
    
    high = [k for k in family_ksis if priority_map.get(k.get('id'), 'Medium') == 'High']
    if high:
        for ksi in high:
            result += f"- {ksi.get('id')}: {ksi.get('name')}\n"
    else:
        result += "*High priority items should be addressed after critical items*\n"
    
    result += f"""

### Phase 3: Complete Coverage (Medium/Low Priority)
*Implement remaining KSIs for full compliance*

## Quick Start Guide

### 1. Set Up Azure Infrastructure
```bash
# Create resource group for {family_upper} resources
az group create --name rg-fedramp-{family_upper.lower()} --location eastus

# Deploy monitoring/logging infrastructure
az deployment group create \\
    --resource-group rg-fedramp-{family_upper.lower()} \\
    --template-file infrastructure.bicep
```

### 2. Configure Azure Services
"""
    
    for i, service in enumerate(azure_services[:3], 1):
        result += f"{i}. Configure {service}\n"
    
    result += f"""

### 3. Implement Evidence Collection
```python
# Use provided code templates
# Example: Collect {family_upper} evidence
python collect_{family_upper.lower()}_evidence.py
```

### 4. Test and Validate
- Verify all KSIs can be demonstrated
- Ensure evidence collection is automated
- Test integration with Authorization Data Sharing API

## Key Dependencies

**Prerequisites:**
- Azure subscription with appropriate permissions
- Microsoft Entra ID tenant
- Log Analytics workspace
- Azure Key Vault for secrets

**Related Requirements:**
- FRR-CCM: Continuous monitoring
- FRR-ADS: Authorization data sharing
- FRR-KSI: KSI tracking requirements

## Common Challenges

### Challenge 1: Data Collection Frequency
**Solution:** Use Azure Functions with timer triggers for automated collection

### Challenge 2: Cross-Service Integration
**Solution:** Use Managed Identities for service-to-service authentication

### Challenge 3: Evidence Retention
**Solution:** Azure Blob Storage with immutability policies

## Detailed Implementation

For detailed implementation of specific KSIs:
- Use `get_implementation_examples("KSI-{family_upper}-##")` for code examples
- Use `get_infrastructure_code_for_ksi("KSI-{family_upper}-##")` for IaC templates
- Use `generate_implementation_checklist("KSI-{family_upper}-##")` for step-by-step guide
- Use `generate_implementation_questions("KSI-{family_upper}-##")` for planning discussions

## Resources

- **Azure Documentation:** https://learn.microsoft.com/azure/
- **FedRAMP 20x Docs:** https://github.com/FedRAMP/docs
- **NIST 800-53:** https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final

*Generated by FedRAMP 20x MCP Server - KSI Implementation Matrix Tool*
"""
    
    return result



async def generate_implementation_checklist_impl(ksi_id: str, data_loader) -> str:
    """
    Generate actionable implementation checklist for a specific KSI.
    
    Provides engineers with a step-by-step checklist for implementing a KSI,
    including Azure service setup, code deployment, testing, and evidence collection.
    
    Args:
        ksi_id: The KSI identifier (e.g., "KSI-IAM-01", "KSI-MLA-01")
    
    Returns:
        Detailed implementation checklist with Azure-specific steps
    """
    await data_loader.load_data()
    
    ksi = data_loader.get_ksi(ksi_id)
    if not ksi:
        return f"KSI '{ksi_id}' not found. Use list_ksi to see all available KSIs."
    
    ksi_name = ksi.get('name', 'N/A')
    ksi_description = ksi.get('description', 'N/A')
    category = ksi.get('category', 'N/A')
    
    result = f"""# Implementation Checklist: {ksi_id}

## {ksi_name}

**Category:** {category}
**Description:** {ksi_description}

---

## Pre-Implementation Checklist

### Prerequisites
- [ ] Azure subscription with Owner or Contributor role
- [ ] Microsoft Entra ID Global Administrator access (if IAM changes needed)
- [ ] Azure CLI installed and authenticated (`az login`)
- [ ] Development environment set up (VS Code, Azure extensions)
- [ ] Git repository for Infrastructure as Code

### Planning
- [ ] Read FedRAMP 20x requirement for {ksi_id}
- [ ] Identify which systems/services are in scope
- [ ] Review related KSIs and requirements
- [ ] Determine evidence collection frequency
- [ ] Get stakeholder approval for implementation approach

### Resource Preparation
- [ ] Create resource group: `rg-fedramp-{ksi_id.lower().replace('-', '')}`
- [ ] Set up Azure Key Vault for secrets
- [ ] Create Log Analytics workspace (if not already exists)
- [ ] Set up Azure Blob Storage for evidence

---

## Implementation Steps

### Step 1: Infrastructure Deployment

**1.1 Create IaC Templates**
- [ ] Generate Bicep template: `get_infrastructure_code_for_ksi("{ksi_id}", "bicep")`
- [ ] Review and customize template for your environment
- [ ] Add to git repository
- [ ] Create parameters file with environment-specific values

**1.2 Deploy Infrastructure**
```bash
# Create resource group
az group create \\
    --name rg-fedramp-{ksi_id.lower()} \\
    --location eastus

# Deploy Bicep template
az deployment group create \\
    --resource-group rg-fedramp-{ksi_id.lower()} \\
    --template-file main.bicep \\
    --parameters @parameters.json

# Verify deployment
az deployment group show \\
    --resource-group rg-fedramp-{ksi_id.lower()} \\
    --name main
```

- [ ] Infrastructure deployed successfully
- [ ] All resources visible in Azure Portal
- [ ] No deployment errors or warnings

### Step 2: Azure Service Configuration

"""
    
    # Add family-specific configuration steps
    family = ksi_id.split('-')[1] if '-' in ksi_id else ''
    
    if family == 'IAM':
        result += """**2.1 Configure Microsoft Entra ID**
- [ ] Enable Conditional Access policies
- [ ] Configure MFA settings (phishing-resistant required)
- [ ] Set up Privileged Identity Management (PIM) for admin roles
- [ ] Configure Azure RBAC for least privilege
- [ ] Enable Identity Protection

**2.2 Set Up Monitoring**
- [ ] Enable diagnostic settings for Entra ID
- [ ] Forward sign-in logs to Log Analytics
- [ ] Forward audit logs to Log Analytics
- [ ] Configure alerts for suspicious activity

"""
    elif family == 'MLA':
        result += """**2.1 Configure Azure Monitor & Sentinel**
- [ ] Deploy Microsoft Sentinel workspace
- [ ] Enable all relevant data connectors
- [ ] Configure log retention (1 year minimum)
- [ ] Set up Log Analytics workspace
- [ ] Enable diagnostic settings for all Azure resources

**2.2 Configure Logging**
- [ ] Configure Application Insights for applications
- [ ] Set up diagnostic settings for each resource
- [ ] Forward logs to Log Analytics
- [ ] Configure log retention policies
- [ ] Test log ingestion

"""
    elif family == 'AFR':
        result += """**2.1 Configure Microsoft Defender**
- [ ] Enable Microsoft Defender for Cloud
- [ ] Enable Defender for Containers
- [ ] Enable Defender for Servers
- [ ] Configure vulnerability assessment
- [ ] Set up security recommendations

**2.2 Configure Vulnerability Scanning**
- [ ] Enable Microsoft Defender for Container Registries
- [ ] Configure GitHub Advanced Security (if using GitHub)
- [ ] Set up CI/CD pipeline scanning
- [ ] Configure scan frequency
- [ ] Set up alerting for findings

"""
    elif family == 'SVC':
        result += """**2.1 Configure Azure Key Vault**
- [ ] Deploy Azure Key Vault
- [ ] Configure access policies or RBAC
- [ ] Enable soft delete and purge protection
- [ ] Configure diagnostic logging
- [ ] Set up secret rotation policies

**2.2 Configure Automation**
- [ ] Create Azure Automation account
- [ ] Set up Managed Identity
- [ ] Configure runbooks for secret rotation
- [ ] Test automation workflows
- [ ] Configure schedules

"""
    else:
        result += """**2.1 Configure Azure Services**
- [ ] Deploy required Azure services
- [ ] Configure service-specific settings
- [ ] Enable diagnostic logging
- [ ] Set up Managed Identities
- [ ] Configure networking and security

**2.2 Set Up Monitoring**
- [ ] Enable Azure Monitor
- [ ] Configure Log Analytics workspace
- [ ] Set up alerting rules
- [ ] Configure dashboards
- [ ] Test data collection

"""
    
    result += f"""### Step 3: Code Deployment

**3.1 Generate Evidence Collection Code**
- [ ] Generate code template: `get_evidence_collection_code("{ksi_id}", "python")`
- [ ] Review and customize for your environment
- [ ] Add to git repository
- [ ] Set up CI/CD pipeline

**3.2 Deploy Collection Function**
```bash
# Deploy Azure Function
func azure functionapp publish func-{ksi_id.lower()}-collector

# Verify deployment
az functionapp show \\
    --name func-{ksi_id.lower()}-collector \\
    --resource-group rg-fedramp-{ksi_id.lower()}

# Test function
curl https://func-{ksi_id.lower()}-collector.azurewebsites.net/api/health
```

- [ ] Function deployed successfully
- [ ] Function app is running
- [ ] Managed Identity configured
- [ ] Application Insights enabled

**3.3 Configure Collection Schedule**
- [ ] Set up timer trigger (daily/weekly based on requirement)
- [ ] Configure retry policies
- [ ] Set up error alerting
- [ ] Test scheduled execution

### Step 4: Testing & Validation

**4.1 Unit Testing**
- [ ] Test evidence collection logic
- [ ] Test data formatting
- [ ] Test error handling
- [ ] Test authentication (Managed Identity)
- [ ] All tests passing

**4.2 Integration Testing**
- [ ] Test end-to-end evidence collection
- [ ] Verify evidence stored correctly in Blob Storage
- [ ] Test evidence retrieval
- [ ] Verify evidence format (JSON/OSCAL)
- [ ] Test API integration (if applicable)

**4.3 Compliance Validation**
- [ ] Evidence demonstrates compliance with {ksi_id}
- [ ] Evidence is complete and accurate
- [ ] Evidence collection is automated
- [ ] Evidence retention meets requirements (1+ years)
- [ ] Evidence is accessible via API (FRR-ADS)

**4.4 Security Testing**
- [ ] No secrets in code or logs
- [ ] All secrets stored in Azure Key Vault
- [ ] Managed Identity working correctly
- [ ] Least privilege access configured
- [ ] Network security properly configured

### Step 5: Documentation

**5.1 Technical Documentation**
- [ ] Architecture diagram created
- [ ] Data flow diagram created
- [ ] Infrastructure documented (IaC in git)
- [ ] API documentation (if applicable)
- [ ] Runbook for troubleshooting

**5.2 Compliance Documentation**
- [ ] Control implementation statement written
- [ ] Evidence collection procedure documented
- [ ] Add to System Security Plan (SSP)
- [ ] Update Authorization Boundary diagram
- [ ] Document in Configuration Management Plan

**5.3 Operational Documentation**
- [ ] Daily operations runbook
- [ ] Escalation procedures
- [ ] Backup and recovery procedures
- [ ] Contact information for support

### Step 6: Evidence Collection Setup

**6.1 Configure Evidence Storage**
- [ ] Blob Storage container created
- [ ] Immutability policy configured
- [ ] Lifecycle management configured
- [ ] Access policies configured
- [ ] Encryption verified

**6.2 Test Evidence Collection**
```bash
# Manually trigger collection
az functionapp function invoke \\
    --name func-{ksi_id.lower()}-collector \\
    --function-name CollectEvidence \\
    --resource-group rg-fedramp-{ksi_id.lower()}

# Verify evidence stored
az storage blob list \\
    --account-name st{ksi_id.lower().replace('-', '')}evidence \\
    --container-name evidence
```

- [ ] Evidence collection executed successfully
- [ ] Evidence file created in Blob Storage
- [ ] Evidence contains expected data
- [ ] Evidence format is correct

**6.3 Set Up Evidence Monitoring**
- [ ] Configure alerts for collection failures
- [ ] Create dashboard for collection status
- [ ] Set up weekly evidence review
- [ ] Document evidence access procedures

### Step 7: Integration with FRR-ADS

**7.1 API Setup**
- [ ] Expose evidence via Authorization Data Sharing API
- [ ] Configure authentication (OAuth 2.0 or mTLS)
- [ ] Test API endpoints
- [ ] Document API for FedRAMP PMO
- [ ] Provide API credentials to authorized users

**7.2 API Testing**
- [ ] Test GET requests for evidence
- [ ] Test authentication
- [ ] Test rate limiting
- [ ] Test error handling
- [ ] All API tests passing

---

## Post-Implementation Checklist

### Monitoring & Maintenance
- [ ] Set up alerts for collection failures
- [ ] Configure weekly evidence reviews
- [ ] Schedule quarterly access reviews
- [ ] Plan for infrastructure updates
- [ ] Document lessons learned

### Compliance Validation
- [ ] Internal audit completed
- [ ] All evidence requirements met
- [ ] Documentation complete and approved
- [ ] 3PAO review scheduled (if applicable)
- [ ] Stakeholders notified of completion

### Continuous Improvement
- [ ] Monitor collection performance
- [ ] Optimize collection efficiency
- [ ] Address any gaps identified
- [ ] Update documentation as needed
- [ ] Plan for future enhancements

---

## Troubleshooting Common Issues

### Issue: Evidence collection failing
**Troubleshooting steps:**
1. Check Azure Function logs in Application Insights
2. Verify Managed Identity has correct permissions
3. Test connectivity to data sources
4. Check for API rate limiting
5. Review error messages in logs

### Issue: Evidence format incorrect
**Troubleshooting steps:**
1. Review evidence specification
2. Check data transformation logic
3. Validate against OSCAL schema (if using OSCAL)
4. Test with sample data
5. Review FedRAMP requirements

### Issue: API authentication failing
**Troubleshooting steps:**
1. Verify credentials/tokens
2. Check token expiration
3. Review access policies
4. Test authentication independently
5. Check network connectivity

---

## Success Criteria

✅ All checklist items completed
✅ Evidence collected automatically on schedule
✅ Evidence demonstrates compliance with {ksi_id}
✅ Documentation complete and approved
✅ Team trained on operation and troubleshooting
✅ Integration with FRR-ADS API working
✅ Monitoring and alerting configured
✅ Internal audit passed

---

## Next Steps

1. **Mark completion:** Update project tracker with completion status
2. **Schedule review:** Set up quarterly review of implementation
3. **Train team:** Ensure all team members understand operations
4. **Document lessons:** Capture lessons learned for future KSIs
5. **Move to next KSI:** Use `get_ksi_implementation_matrix` to identify next priority

---

## Related Tools

- `get_implementation_examples("{ksi_id}")` - Get code examples
- `get_infrastructure_code_for_ksi("{ksi_id}")` - Get IaC templates
- `get_evidence_collection_code("{ksi_id}")` - Get collection code
- `generate_implementation_questions("{ksi_id}")` - Planning questions
- `get_cloud_native_guidance("azure")` - Azure-specific guidance

*Generated by FedRAMP 20x MCP Server - Implementation Checklist Tool*
"""
    
    return result



async def generate_implementation_questions_impl(requirement_id: str, data_loader) -> str:
    """
    Generate strategic interview questions for product managers and engineers.
    
    Helps teams think through FedRAMP 20x implementation considerations by providing
    thoughtful questions about architecture, operations, compliance, and trade-offs.
    
    Works with both requirements (e.g., "FRR-CCM-01") and KSIs (e.g., "KSI-IAM-01").
    
    Args:
        requirement_id: The requirement or KSI ID to generate questions for
    
    Returns:
        Strategic questions organized by stakeholder role and concern area
    """
    await data_loader.load_data()
    
    # Try to get as requirement first, then as KSI
    item = data_loader.get_control(requirement_id)
    if not item:
        item = data_loader.get_ksi(requirement_id)
    
    if not item:
        return f"Requirement or KSI '{requirement_id}' not found. Please check the ID format (e.g., 'FRR-CCM-01' or 'KSI-IAM-01')."
    
    title = item.get('title', item.get('name', 'N/A'))
    description = item.get('description', item.get('statement', 'N/A'))
    family = item.get('family', 'N/A')
    
    result = f"""# Implementation Questions for {requirement_id}

## Requirement Overview
**Title:** {title}
**Family:** {family}
**Description:** {description}

---

## Strategic Questions for Product Managers

### Business & Risk Perspective:
1. **Business Impact**: How will implementing this requirement affect our product roadmap and time-to-market?
   
2. **Customer Value**: Which of our federal customers will benefit most from this compliance capability?
   
3. **Competitive Position**: How does implementing this requirement differentiate us in the FedRAMP marketplace?
   
4. **Resource Allocation**: What trade-offs are we making by prioritizing this requirement over other features?
   
5. **Cost-Benefit**: What's the total cost of ownership (TCO) for implementing and maintaining this control long-term?

### Planning & Prioritization:
6. **Dependencies**: What other requirements or KSIs must be implemented before this one?
   
7. **Phasing**: Should this be implemented in phases, or does it require a complete solution from day one?
   
8. **Quick Wins**: Are there interim measures we can implement to partially satisfy this requirement faster?
   
9. **Vendor Support**: Do Azure or Microsoft 365 services already provide capabilities we can leverage?
   
10. **Documentation**: What policy and procedure documentation will we need to create and maintain?

---

## Technical Questions for Engineers

### Architecture & Design:
11. **System Design**: How does this requirement influence our overall system architecture?
    
12. **Azure Services**: Which Azure or Microsoft 365 services can help us meet this requirement natively?
    
13. **Automation**: What aspects of this requirement can be automated vs. require manual processes?
    
14. **Scalability**: Will our implementation scale as our customer base and data volumes grow?
    
15. **Performance**: What performance impacts should we expect from implementing this control?

### Implementation Details:
16. **Integration**: How does this integrate with our existing security and compliance infrastructure?
    
17. **Configuration**: What configuration management is needed to maintain consistency across environments?
    
18. **Monitoring**: How will we monitor and alert on compliance status for this requirement?
    
19. **Testing**: How can we test that this control is working effectively? What does "good" look like?
    
20. **Evidence**: What evidence needs to be collected, and how will we automate its collection?

### Operations & Maintenance:
21. **Day-to-Day**: What are the ongoing operational tasks required to maintain this control?
    
22. **Troubleshooting**: What failure modes should we anticipate, and how will we diagnose issues?
    
23. **Updates**: How will updates to Azure services or our application affect this control?
    
24. **Disaster Recovery**: How does this requirement fit into our disaster recovery and business continuity plans?
    
25. **Technical Debt**: What technical debt might we accumulate with a quick implementation vs. a more robust solution?

---

## Cross-Functional Questions

### Security & Compliance:
26. **Defense in Depth**: How does this control work with other controls to provide defense in depth?
    
27. **Audit Trail**: What audit trails are required, and how long must we retain them?
    
28. **Access Control**: Who needs access to configure, monitor, or modify this control?
    
29. **Incident Response**: How does this requirement impact our incident response procedures?
    
30. **Continuous Monitoring**: How will we continuously validate compliance with this requirement?

### User Experience:
31. **User Impact**: Will implementing this requirement affect user experience or workflows?
    
32. **Training**: What training will users or administrators need for this control?
    
33. **Communication**: How should we communicate changes to customers and stakeholders?
    
34. **Support**: What support burden will this create for our customer success team?
    
35. **Accessibility**: Does this control maintain accessibility and usability standards?

---

## Azure-Specific Considerations

### Azure Implementation:
"""
    
    # Add Azure-specific questions based on family/keywords
    keywords = title.lower() + ' ' + description.lower()
    
    if any(word in keywords for word in ['identity', 'access', 'authentication', 'authorization']):
        result += """
36. **Entra ID Configuration**: How should we configure Microsoft Entra ID to support this requirement?
    
37. **RBAC Design**: What Azure RBAC roles and assignments are needed?
    
38. **Conditional Access**: Should we implement Conditional Access policies for this control?
    
39. **Privileged Access**: Do we need Privileged Identity Management (PIM) for just-in-time access?
"""
    
    if any(word in keywords for word in ['monitor', 'log', 'audit', 'visibility', 'detect']):
        result += """
40. **Log Analytics**: What logs need to be sent to Azure Monitor and retained for how long?
    
41. **Sentinel Integration**: Should Microsoft Sentinel be used for threat detection or compliance monitoring?
    
42. **Alerting Strategy**: What alerts should be configured, and who should receive them?
    
43. **Dashboard Design**: What compliance dashboards should we create for visibility?
"""
    
    if any(word in keywords for word in ['configuration', 'policy', 'governance', 'compliance']):
        result += """
44. **Azure Policy**: What Azure Policies should be created to enforce this requirement?
    
45. **Blueprints**: Should we use Azure Blueprints to package this control for repeatable deployment?
    
46. **Management Groups**: How should management group hierarchy support this control?
    
47. **Resource Tags**: What tagging strategy is needed for compliance tracking?
"""
    
    if any(word in keywords for word in ['security', 'vulnerability', 'threat', 'protection']):
        result += """
48. **Defender Configuration**: How should Microsoft Defender for Cloud be configured?
    
49. **Security Baseline**: Does this align with Azure Security Benchmark recommendations?
    
50. **Vulnerability Scanning**: What vulnerability scanning tools should be integrated?
    
51. **Penetration Testing**: How will we conduct penetration testing for this control?
"""
    
    if any(word in keywords for word in ['data', 'encryption', 'confidential', 'protection']):
        result += """
52. **Key Vault**: How should Azure Key Vault be used for secrets and key management?
    
53. **Encryption Strategy**: What data needs encryption at rest and in transit?
    
54. **Data Classification**: How does data classification affect implementation?
    
55. **Data Residency**: Are there data residency requirements that impact Azure region selection?
"""
    
    result += """

---

## Decision Framework

### Must Answer Before Implementation:
- [ ] Have we clearly defined what "compliance" means for this requirement?
- [ ] Do we have executive sponsorship and budget approval?
- [ ] Have we identified all affected systems and data flows?
- [ ] Do we know who is accountable for this control's success?
- [ ] Have we validated our approach with a FedRAMP expert or 3PAO?

### Success Criteria:
- [ ] Control can be demonstrated to work as designed
- [ ] Evidence collection is automated and reliable
- [ ] Documentation is complete and approved
- [ ] Team is trained on operation and troubleshooting
- [ ] Control passes internal testing and review

### Red Flags to Watch For:
- [ ] No clear owner or accountability for the control
- [ ] Significant manual processes that don't scale
- [ ] Heavy reliance on undocumented configurations
- [ ] No monitoring or alerting for control failures
- [ ] Implementation differs significantly from documented design

---

## Next Steps

1. **Research Phase**: Gather information about Azure capabilities and best practices
2. **Design Phase**: Create architecture diagrams and implementation plans
3. **Review Phase**: Get design reviewed by security, compliance, and architecture teams
4. **Prototype Phase**: Build proof-of-concept in non-production environment
5. **Test Phase**: Validate control works as designed and collects proper evidence
6. **Document Phase**: Create all required policies, procedures, and runbooks
7. **Deploy Phase**: Implement in production with proper change management
8. **Validate Phase**: Conduct internal audit to verify compliance
9. **Monitor Phase**: Continuously monitor and report on control effectiveness

---

## Recommended Resources

### Microsoft Documentation:
- Azure Security Benchmark: https://learn.microsoft.com/en-us/security/benchmark/azure/
- Azure Well-Architected Framework: https://learn.microsoft.com/en-us/azure/well-architected/
- FedRAMP on Azure: https://learn.microsoft.com/en-us/azure/compliance/offerings/offering-fedramp

### FedRAMP Resources:
- FedRAMP.gov: https://www.fedramp.gov/
- FedRAMP 20x Documentation: https://github.com/FedRAMP/docs
- FedRAMP Marketplace: https://marketplace.fedramp.gov/

### Community:
- Azure Community: https://techcommunity.microsoft.com/t5/azure/ct-p/Azure
- FedRAMP PMO: https://www.fedramp.gov/program-basics/

---

*Use these questions to facilitate team discussions, planning sessions, and design reviews. The goal is to ensure thorough thinking about implementation before committing resources.*

*Generated by FedRAMP 20x MCP Server - Implementation Questions Tool*
"""
    
    return result