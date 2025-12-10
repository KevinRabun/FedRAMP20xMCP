"""
KSI-AFR-07: Recommended Secure Configuration

Develop secure by default configurations and provide guidance for secure configuration of the cloud service offering to customers in alignment with the FedRAMP Recommended Secure Configuration (RSC) guidance process and persistently address all related requirements and recommendations.

Official FedRAMP 20x Definition
Source: https://github.com/FedRAMP/docs/blob/main/data/FRMR.KSI.key-security-indicators.json
Version: 25.11C (Published: 2025-12-01)
"""

import re
from typing import List, Dict, Any
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer
from ..ast_utils import ASTParser, CodeLanguage


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
        Analyze Python code for KSI-AFR-07 compliance using AST.
        
        Frameworks: Flask, Django, FastAPI, Azure SDK
        
        Detects:
        - Debug mode enabled in production
        - Insecure session configurations
        - Missing security headers
        """
        # Parse code with tree-sitter AST
        parser = ASTParser(CodeLanguage.PYTHON)
        tree = parser.parse(code)
        
        if tree and tree.root_node:
            return self._analyze_python_ast(code, file_path, parser, tree)
        else:
            return self._analyze_python_regex(code, file_path)
    
    def _analyze_python_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for Python."""
        findings = []
        lines = code.split('\n')
        
        # Check for debug mode enabled (hardcoded True, not environment-based)
        # Match: debug=True, DEBUG = True, ['DEBUG'] = True, etc.
        has_hardcoded_debug = bool(re.search(r"(debug|DEBUG)['\"]*\s*[\]\s]*=\s*True", code))
        
        if has_hardcoded_debug:
            result = self._find_line(lines, 'debug=True')

            line_num = result['line_num'] if result else 0
            if line_num == 0:
                result = self._find_line(lines, 'debug = True')

                line_num = result['line_num'] if result else 0
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
        is_flask = any('Flask' in line for line in lines)
        has_session_config = any('SESSION_COOKIE_' in line for line in lines)
        
        if is_flask and not has_session_config:
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
    
    def _analyze_python_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis for Python."""
        findings = []
        lines = code.split('\n')
        
        # Check for debug mode enabled
        if re.search(r'debug\s*=\s*True', code, re.IGNORECASE):
            result = self._find_line(lines, 'debug=True')

            line_num = result['line_num'] if result else 0
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
        Analyze C# code for KSI-AFR-07 compliance using AST.
        
        Frameworks: ASP.NET Core, Entity Framework, Azure SDK
        
        Detects:
        - Missing HTTPS redirection
        - Weak HSTS configuration
        - Development exception page in production
        """
        # Parse code with tree-sitter AST
        parser = ASTParser(CodeLanguage.CSHARP)
        tree = parser.parse(code)
        
        if tree and tree.root_node:
            return self._analyze_csharp_ast(code, file_path, parser, tree)
        else:
            return self._analyze_csharp_regex(code, file_path)
    
    def _analyze_csharp_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for C#."""
        findings = []
        lines = code.split('\n')
        
        # Check for UseDeveloperExceptionPage without environment check
        has_dev_exception = any('UseDeveloperExceptionPage' in line for line in lines)
        has_env_check = any('IsDevelopment' in line or 'IsProduction' in line for line in lines)
        
        if has_dev_exception and not has_env_check:
            result = self._find_line(lines, 'UseDeveloperExceptionPage')

            line_num = result['line_num'] if result else 0
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
        has_web_app = any('WebApplication' in line for line in lines)
        has_https = any('UseHttpsRedirection' in line for line in lines)
        
        if has_web_app and not has_https:
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
    
    def _analyze_csharp_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis for C#."""
        findings = []
        lines = code.split('\n')
        
        # Check for UseDeveloperExceptionPage without environment check
        if 'UseDeveloperExceptionPage' in code and not re.search(r'IsDevelopment|IsProduction', code):
            result = self._find_line(lines, 'UseDeveloperExceptionPage')

            line_num = result['line_num'] if result else 0
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
        Analyze Java code for KSI-AFR-07 compliance using AST.
        
        Frameworks: Spring Boot, Spring Security, Azure SDK
        
        Detects:
        - Debug logging enabled
        - Insecure CORS configuration
        - Missing security headers
        """
        # Parse code with tree-sitter AST
        parser = ASTParser(CodeLanguage.JAVA)
        tree = parser.parse(code)
        
        if tree and tree.root_node:
            return self._analyze_java_ast(code, file_path, parser, tree)
        else:
            return self._analyze_java_regex(code, file_path)
    
    def _analyze_java_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for Java."""
        findings = []
        lines = code.split('\n')
        
        # Check for debug logging (matches both Java code and .properties files)
        has_debug_logging = any('logging.level' in line.lower() and 'debug' in line.lower() for line in lines)
        
        if has_debug_logging:
            result = self._find_line(lines, 'logging.level')

            line_num = result['line_num'] if result else 0
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
        has_wildcard_cors = any('allowedOrigins' in line and '*' in line for line in lines)
        
        if has_wildcard_cors:
            result = self._find_line(lines, 'allowedOrigins')

            line_num = result['line_num'] if result else 0
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
    
    def _analyze_java_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis for Java."""
        findings = []
        lines = code.split('\n')
        
        # Check for debug logging
        if re.search(r'logging\.level\.root\s*=\s*DEBUG', code, re.IGNORECASE):
            result = self._find_line(lines, 'logging.level')

            line_num = result['line_num'] if result else 0
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
            result = self._find_line(lines, 'allowedOrigins')

            line_num = result['line_num'] if result else 0
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
        Analyze TypeScript/JavaScript code for KSI-AFR-07 compliance using AST.
        
        Frameworks: Express, NestJS, Next.js, React, Angular, Azure SDK
        
        Detects:
        - Missing helmet (security headers)
        - Insecure CORS configuration
        - Production mode not enforced
        """
        # Parse code with tree-sitter AST
        parser = ASTParser(CodeLanguage.TYPESCRIPT)
        tree = parser.parse(code)
        
        if tree and tree.root_node:
            return self._analyze_typescript_ast(code, file_path, parser, tree)
        else:
            return self._analyze_typescript_regex(code, file_path)
    
    def _analyze_typescript_ast(self, code: str, file_path: str, parser: ASTParser, tree) -> List[Finding]:
        """AST-based analysis for TypeScript/JavaScript."""
        findings = []
        lines = code.split('\n')
        
        # Check for missing helmet (Express security)
        has_express = any('express()' in line for line in lines)
        has_helmet = any('helmet' in line for line in lines)
        
        if has_express and not has_helmet:
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
        has_wildcard_cors = any("origin: '*'" in line or 'origin:"*"' in line or "origin:'*'" in line for line in lines)
        
        if has_wildcard_cors:
            result = self._find_line(lines, "origin: '*'")

            line_num = result['line_num'] if result else 0
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
    
    def _analyze_typescript_regex(self, code: str, file_path: str = "") -> List[Finding]:
        """Fallback regex-based analysis for TypeScript/JavaScript."""
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
            result = self._find_line(lines, "origin: '*'")

            line_num = result['line_num'] if result else 0
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
        
        Note: Using regex - tree-sitter not available for Bicep.
        
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
            
            # Find the matching closing brace for the resource block
            # Count braces to find the correct closing brace
            brace_count = 0
            pos = resource_start
            resource_end = len(code)
            for i, char in enumerate(code[resource_start:], start=resource_start):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        resource_end = i + 1
                        break
            
            resource_section = code[resource_start:resource_end]
            
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
        
        Note: Using regex - tree-sitter not available for Terraform.
        
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
            
            # Find the matching closing brace for the resource block
            # Count braces to find the correct closing brace
            brace_count = 0
            resource_end = len(code)
            for i, char in enumerate(code[resource_start:], start=resource_start):
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        resource_end = i + 1
                        break
            
            resource_section = code[resource_start:resource_end]
            
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
        
        Note: Using regex - tree-sitter not available for GitHub Actions YAML.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitHub Actions detection if applicable
        
        return findings
    
    def analyze_azure_pipelines(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze Azure Pipelines YAML for KSI-AFR-07 compliance.
        
        Note: Using regex - tree-sitter not available for Azure Pipelines YAML.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement Azure Pipelines detection if applicable
        
        return findings
    
    def analyze_gitlab_ci(self, code: str, file_path: str = "") -> List[Finding]:
        """
        Analyze GitLab CI YAML for KSI-AFR-07 compliance.
        
        Note: Using regex - tree-sitter not available for GitLab CI YAML.
        
        TODO: Implement detection logic if applicable.
        """
        findings = []
        
        # TODO: Implement GitLab CI detection if applicable
        
        return findings

    def get_evidence_automation_recommendations(self) -> Dict[str, Any]:
        """
        Get recommendations for automating evidence collection for KSI-AFR-07.
        
        Returns:
            Dict containing automation recommendations
        """
        return {
            "ksi_id": self.ksi_id,
            "ksi_name": "Recommended Secure Configuration",
            "evidence_type": "config-based",
            "automation_feasibility": "high",
            "azure_services": [
                "Azure Policy",
                "Microsoft Defender for Cloud",
                "Azure Automation DSC",
                "Azure DevOps",
                "Azure Advisor"
            ],
            "collection_methods": [
                "Azure Policy guest configuration to audit OS and application secure baseline compliance",
                "Defender for Cloud secure score and recommendations for FedRAMP-aligned security configurations",
                "Azure Automation DSC to enforce and report on configuration drift from secure baselines",
                "Azure DevOps to maintain and version-control secure configuration documentation and standards"
            ],
            "implementation_steps": [
                "1. Define FedRAMP Recommended Secure Configuration (RSC) baselines in Azure Policy guest configuration: (a) Windows Server hardening (CIS benchmarks), (b) Linux hardening (CIS benchmarks), (c) Azure PaaS service secure configurations",
                "2. Assign Azure Policy initiatives: (a) Enable guest configuration VM extension on all VMs, (b) Apply FedRAMP High/Moderate baseline policies, (c) Configure audit-only mode initially for baseline assessment",
                "3. Enable Defender for Cloud with FedRAMP security standards: (a) Activate FedRAMP High/Moderate regulatory compliance dashboard, (b) Configure secure score thresholds and alerts, (c) Enable auto-remediation for critical config gaps",
                "4. Document secure configuration guidance in Azure DevOps: (a) Create wiki pages for each Azure service with FedRAMP-aligned configs, (b) Store IaC templates with secure-by-default settings, (c) Version control all baseline documents",
                "5. Deploy Azure Automation DSC for configuration enforcement: (a) Author DSC configurations for Windows/Linux baselines, (b) Onboard all VMs to Automation State Configuration, (c) Monitor compliance reports",
                "6. Generate monthly evidence package via Azure Automation runbook: (a) Export Policy compliance reports, (b) Export Defender secure score history, (c) Export DSC compliance status, (d) Package documentation from DevOps"
            ],
            "evidence_artifacts": [
                "Azure Policy Compliance Report showing guest configuration audit results for secure baselines",
                "Defender for Cloud Secure Score Report with FedRAMP regulatory compliance status",
                "Azure Automation DSC Compliance Report showing configuration drift and remediation actions",
                "Secure Configuration Documentation Package from Azure DevOps with baseline guides and IaC templates",
                "Azure Advisor Recommendations Report filtered for security and FedRAMP-relevant configuration improvements"
            ],
            "update_frequency": "monthly",
            "responsible_party": "Cloud Security Team / Configuration Management Team"
        }

    def get_evidence_collection_queries(self) -> List[Dict[str, str]]:
        """
        Get specific queries for evidence collection automation.
        
        Returns:
            List of query dictionaries
        """
        return [
            {
                "query_type": "Azure Policy REST API",
                "query_name": "Guest configuration compliance for secure baselines",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.PolicyInsights/policyStates/latest/summarize?api-version=2019-10-01&$filter=policyDefinitionCategory eq 'Guest Configuration'",
                "purpose": "Retrieve compliance status of VMs against FedRAMP secure configuration baselines"
            },
            {
                "query_type": "Microsoft Defender for Cloud REST API",
                "query_name": "FedRAMP regulatory compliance assessment",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Security/regulatoryComplianceStandards/FedRAMP-High/regulatoryComplianceControls?api-version=2019-01-01-preview",
                "purpose": "Get FedRAMP regulatory compliance control assessment results from Defender for Cloud"
            },
            {
                "query_type": "Azure Automation REST API",
                "query_name": "DSC node compliance status",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Automation/automationAccounts/{automationAccount}/nodes?api-version=2019-06-01&$filter=properties/status eq 'Compliant' or properties/status eq 'NonCompliant'",
                "purpose": "Retrieve DSC compliance status for all managed nodes against secure configuration baselines"
            },
            {
                "query_type": "Azure Advisor REST API",
                "query_name": "Security recommendations for configuration improvements",
                "query": "GET https://management.azure.com/subscriptions/{subscriptionId}/providers/Microsoft.Advisor/recommendations?api-version=2020-01-01&$filter=properties/category eq 'Security' and properties/impactedField eq 'Microsoft.Compute/virtualMachines'",
                "purpose": "Identify security-related configuration recommendations from Azure Advisor for FedRAMP workloads"
            },
            {
                "query_type": "Azure DevOps REST API",
                "query_name": "Secure configuration documentation repository",
                "query": "GET https://dev.azure.com/{organization}/{project}/_apis/git/repositories/FedRAMP-Secure-Configurations/items?scopePath=/RSC-Baselines&recursionLevel=Full&api-version=7.0",
                "purpose": "Access version-controlled secure configuration documentation and baseline standards"
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
                "artifact_name": "Azure Policy Guest Configuration Report",
                "artifact_type": "Azure Policy Compliance Export",
                "description": "Compliance report showing VM adherence to FedRAMP secure configuration baselines (CIS benchmarks, hardening standards)",
                "collection_method": "Azure Policy Insights API to export guest configuration compliance data to JSON",
                "storage_location": "Azure Storage Account with compliance report retention for 12 months"
            },
            {
                "artifact_name": "Defender for Cloud Secure Score History",
                "artifact_type": "Defender for Cloud Report",
                "description": "Monthly secure score trends showing configuration security posture against FedRAMP standards",
                "collection_method": "Microsoft Defender for Cloud REST API to retrieve secure score and control assessments",
                "storage_location": "Azure Log Analytics workspace with historical secure score data"
            },
            {
                "artifact_name": "Azure Automation DSC Compliance Report",
                "artifact_type": "DSC State Configuration Report",
                "description": "Report showing configuration drift detection and compliance status for all DSC-managed nodes",
                "collection_method": "Azure Automation API to export DSC node compliance status with drift details",
                "storage_location": "Azure Storage Account with monthly snapshots and CSV exports"
            },
            {
                "artifact_name": "Secure Configuration Documentation Package",
                "artifact_type": "Azure DevOps Repository Export",
                "description": "Complete set of FedRAMP-aligned secure configuration guides, baseline documents, and IaC templates",
                "collection_method": "Azure DevOps Git API to clone/export secure configuration repository with version history",
                "storage_location": "Azure DevOps Repos with branch protection and required reviewers for RSC changes"
            },
            {
                "artifact_name": "Azure Advisor Security Recommendations",
                "artifact_type": "Azure Advisor Report",
                "description": "Security-focused recommendations for configuration improvements aligned with FedRAMP requirements",
                "collection_method": "Azure Advisor REST API to retrieve and filter security recommendations for production workloads",
                "storage_location": "Azure Monitor Logs with Advisor recommendation ingestion and alerting"
            }
        ]
    

