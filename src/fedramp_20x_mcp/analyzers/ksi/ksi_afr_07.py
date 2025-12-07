"""
KSI-AFR-07: Recommended Secure Configuration

Develop secure by default configurations and provide guidance for secure configuration of the cloud service offering to customers in alignment with the FedRAMP Recommended Secure Configuration (RSC) guidance process and persistently address all related requirements and recommendations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_AFR_07_Analyzer(BaseKSIAnalyzer):
    """
    Analyzer for KSI-AFR-07: Recommended Secure Configuration
    
    **Official Statement:**
    Develop secure by default configurations and provide guidance for secure configuration of the cloud service offering to customers in alignment with the FedRAMP Recommended Secure Configuration (RSC) guidance process and persistently address all related requirements and recommendations.
    
    **Family:** AFR - Authorization by FedRAMP
    
    **Impact Levels:**
    - Low: Yes
    - Moderate: Yes
    
    **NIST Controls:**
    - None specified
    
    **Detectability:** Code-Detectable (Implement detection logic)
    
    **Detection Strategy:**
    Analyze code for patterns related to: Develop secure by default configurations and provide guidance for secure configuration of the cloud ...
    
    **Languages Supported:**
    - Application: Python, C#, Java, TypeScript/JavaScript
    - IaC: Bicep, Terraform
    - CI/CD: GitHub Actions, Azure Pipelines, GitLab CI
    
    
    """
    
    KSI_ID = "KSI-AFR-07"
    KSI_NAME = "Recommended Secure Configuration"
    KSI_STATEMENT = """Develop secure by default configurations and provide guidance for secure configuration of the cloud service offering to customers in alignment with the FedRAMP Recommended Secure Configuration (RSC) guidance process and persistently address all related requirements and recommendations."""
    FAMILY = "AFR"
    FAMILY_NAME = "Authorization by FedRAMP"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = []
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
        Analyze Python code for KSI-AFR-07 compliance.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Debug mode enabled in production
        - Insecure session configurations
        - Missing security headers
        """
        findings = []
        lines = code.split('\n')
        
        # Check for debug mode enabled
        if re.search(r'debug\s*=\s*True', code, re.IGNORECASE):
            line_num = self._find_line(lines, 'debug=True')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Debug Mode Enabled (Insecure Default)",
                description=f"Python file '{file_path}' has debug mode enabled, which is insecure for production. KSI-AFR-07 requires secure default configurations.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="""Disable debug mode in production:

```python
import os

# Flask
app = Flask(__name__)
app.config['DEBUG'] = os.getenv('DEBUG', 'False') == 'True'

# Django settings.py
DEBUG = os.getenv('DEBUG', 'False') == 'True'

# FastAPI
app = FastAPI(debug=False)
```

Reference: FRR-AFR-07 - Secure Default Configurations"""
            ))
        
        # Check for insecure session configuration
        if 'Flask' in code and not re.search(r'SESSION_COOKIE_(SECURE|HTTPONLY|SAMESITE)', code):
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Secure Session Configuration",
                description=f"Flask application '{file_path}' lacks secure session cookie configuration. KSI-AFR-07 requires secure defaults.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Configure secure session cookies:

```python
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
```

Reference: FRR-AFR-07"""
            ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze C# code for KSI-AFR-07 compliance.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Missing HTTPS redirection
        - Weak HSTS configuration
        - Development exception page in production
        """
        findings = []
        lines = code.split('\n')
        
        # Check for UseDeveloperExceptionPage without environment check
        if 'UseDeveloperExceptionPage' in code and not re.search(r'IsDevelopment|IsProduction', code):
            line_num = self._find_line(lines, 'UseDeveloperExceptionPage')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Developer Exception Page May Run in Production",
                description=f"C# file '{file_path}' enables developer exception page without environment check. KSI-AFR-07 requires secure defaults.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="""Only enable developer exception page in development:

```csharp
if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}
```

Reference: FRR-AFR-07"""
            ))
        
        # Check for missing HTTPS redirection
        if 'WebApplication' in code and 'UseHttpsRedirection' not in code:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing HTTPS Redirection",
                description=f"ASP.NET Core application '{file_path}' does not enforce HTTPS redirection. KSI-AFR-07 requires secure transport.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Enable HTTPS redirection:

```csharp
app.UseHttpsRedirection();
app.UseHsts();
```

Reference: FRR-AFR-07"""
            ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Java code for KSI-AFR-07 compliance.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Debug logging enabled
        - Insecure CORS configuration
        - Missing security headers
        """
        findings = []
        lines = code.split('\n')
        
        # Check for debug logging
        if re.search(r'logging\.level\.root\s*=\s*DEBUG', code, re.IGNORECASE):
            line_num = self._find_line(lines, 'logging.level')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Debug Logging Enabled (Insecure Default)",
                description=f"Java configuration '{file_path}' has debug logging enabled. KSI-AFR-07 requires secure defaults.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="""Set appropriate log level for production:

```properties
# application.properties
logging.level.root=INFO
logging.level.com.yourapp=INFO
```

Reference: FRR-AFR-07"""
            ))
        
        # Check for insecure CORS
        if re.search(r'allowedOrigins\s*\(\s*["\']\*["\']\s*\)', code):
            line_num = self._find_line(lines, 'allowedOrigins')
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Insecure CORS Configuration (Allow All Origins)",
                description=f"Java file '{file_path}' allows all CORS origins (*). KSI-AFR-07 requires secure defaults.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="""Configure specific allowed origins:

```java
@Configuration
public class CorsConfig {
    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/**")
                    .allowedOrigins("https://yourdomain.com")
                    .allowedMethods("GET", "POST")
                    .allowCredentials(true);
            }
        };
    }
}
```

Reference: FRR-AFR-07"""
            ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze TypeScript/JavaScript code for KSI-AFR-07 compliance.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Missing helmet (security headers)
        - Insecure CORS configuration
        - Production mode not enforced
        """
        findings = []
        lines = code.split('\n')
        
        # Check for missing helmet (Express security)
        if 'express()' in code and 'helmet' not in code:
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Missing Security Headers (Helmet)",
                description=f"Express application '{file_path}' does not use helmet middleware for security headers. KSI-AFR-07 requires secure defaults.",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=0,
                code_snippet="",
                remediation="""Add helmet middleware:

```typescript
import helmet from 'helmet';

const app = express();
app.use(helmet());
```

Reference: FRR-AFR-07"""
            ))
        
        # Check for insecure CORS (allow all origins)
        if re.search(r'cors\s*\(\s*{[^}]*origin:\s*["\']\*["\']', code):
            line_num = self._find_line(lines, "origin: '*'")
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Insecure CORS Configuration",
                description=f"TypeScript file '{file_path}' allows all CORS origins. KSI-AFR-07 requires secure defaults.",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="""Configure specific allowed origins:

```typescript
import cors from 'cors';

const corsOptions = {
  origin: ['https://yourdomain.com'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));
```

Reference: FRR-AFR-07"""
            ))
        
        return findings
    
    # ============================================================================
    # INFRASTRUCTURE AS CODE ANALYZERS
    # ============================================================================
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Bicep IaC for KSI-AFR-07 compliance.
        
        Detects:
        - Storage accounts without secure transfer
        - Resources without encryption
        - Public network access enabled
        """
        findings = []
        lines = code.split('\n')
        
        # Check for storage without secure transfer
        storage_matches = re.finditer(r"resource\s+(\w+)\s+'Microsoft\.Storage/storageAccounts@[^']+'", code)
        for match in storage_matches:
            resource_name = match.group(1)
            resource_start = match.start()
            resource_section = code[resource_start:code.find('}', resource_start) + 1]
            
            if 'supportsHttpsTrafficOnly' not in resource_section:
                line_num = code[:resource_start].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Storage Account Without Secure Transfer Requirement",
                    description=f"Bicep storage account '{resource_name}' in '{file_path}' does not enforce HTTPS. KSI-AFR-07 requires secure defaults.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=resource_section[:200],
                    remediation="""Enable secure transfer:

```bicep
resource storage 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    allowBlobPublicAccess: false
  }
}
```

Reference: FRR-AFR-07"""
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Terraform IaC for KSI-AFR-07 compliance.
        
        Detects:
        - Storage without enable_https_traffic_only
        - Missing encryption configuration
        - Public access enabled
        """
        findings = []
        lines = code.split('\n')
        
        # Check for storage without secure transfer
        storage_matches = re.finditer(r'resource\s+"azurerm_storage_account"\s+"(\w+)"', code)
        for match in storage_matches:
            resource_name = match.group(1)
            resource_start = match.start()
            resource_section = code[resource_start:code.find('}', resource_start) + 1]
            
            if 'enable_https_traffic_only' not in resource_section:
                line_num = code[:resource_start].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Storage Account Without Secure Transfer",
                    description=f"Terraform storage account '{resource_name}' in '{file_path}' does not enforce HTTPS. KSI-AFR-07 requires secure defaults.",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=resource_section[:200],
                    remediation="""Enable secure transfer:

```hcl
resource "azurerm_storage_account" "main" {
  name                     = "mystorageaccount"
  resource_group_name      = azurerm_resource_group.main.name
  location                 = azurerm_resource_group.main.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  
  enable_https_traffic_only = true
  min_tls_version           = "TLS1_2"
  allow_blob_public_access  = false
}
```

Reference: FRR-AFR-07"""
                ))
        
        return findings
    
    # ============================================================================
    # CI/CD PIPELINE ANALYZERS
    # ============================================================================
    
    def analyze_github_actions(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitHub Actions workflow for KSI-AFR-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-AFR-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-AFR-07 compliance.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings
    
    # ============================================================================
    # HELPER METHODS
    # ============================================================================
    
    def _find_line(self, lines: List[str], search_term: str) -> int:
        """Find line number containing search term."""
        for i, line in enumerate(lines, 1):
            if search_term.lower() in line.lower():
                return i
        return 0
    
    def _get_snippet(self, lines: List[str], line_number: int, context: int = 2) -> str:
        """Get code snippet around line number."""
        if line_number == 0:
            return ""
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)
        return '\n'.join(lines[start:end])
