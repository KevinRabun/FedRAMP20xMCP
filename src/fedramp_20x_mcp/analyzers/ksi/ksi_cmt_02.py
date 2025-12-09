"""KSI-CMT-02 Enhanced: Immutable Infrastructure"""

import ast
import re
from typing import List
from ..base import Finding, Severity
from .base import BaseKSIAnalyzer


class KSI_CMT_02_Analyzer(BaseKSIAnalyzer):
    """
    KSI-CMT-02: Redeployment / Immutable Infrastructure
    
    Execute changes through redeployment of version controlled immutable 
    resources rather than direct modification wherever possible.
    
    NIST: CM-2, CM-3, CM-5, CM-6, CM-7, CM-8.1, SI-3
    Focus: Hot reload, runtime config changes, mutable infrastructure
    """
    
    KSI_ID = "KSI-CMT-02"
    KSI_NAME = "Immutable Infrastructure"
    KSI_STATEMENT = "Execute changes through redeployment of version controlled immutable resources rather than direct modification wherever possible."
    FAMILY = "CMT"
    FAMILY_NAME = "Change Management"
    IMPACT_LOW = True
    IMPACT_MODERATE = True
    NIST_CONTROLS = [
        ("cm-2", "Baseline Configuration"),
        ("cm-3", "Configuration Change Control"),
        ("cm-5", "Access Restrictions for Change"),
        ("cm-6", "Configuration Settings"),
        ("cm-7", "Least Functionality"),
        ("cm-8.1", "Updates During Installation and Removal"),
        ("si-3", "Malicious Code Protection")
    ]
    CODE_DETECTABLE = True
    IMPLEMENTATION_STATUS = "IMPLEMENTED"
    
    def __init__(self, language=None, ksi_id: str = "", ksi_name: str = "", ksi_statement: str = ""):
        """Initialize analyzer with backward-compatible API."""
        super().__init__(
            ksi_id=ksi_id or self.KSI_ID,
            ksi_name=ksi_name or self.KSI_NAME,
            ksi_statement=ksi_statement or self.KSI_STATEMENT
        )
        self.direct_language = language
    
    def analyze_python(self, code: str, file_path: str = "") -> List[Finding]:
        """Python: Hot reload, runtime config changes (AST-based)"""
        findings = []
        lines = code.split('\n')
        
        # Try AST parsing
        try:
            tree = ast.parse(code)
            
            # Pattern 1: Hot reload parameters (use_reloader=True, reload=True, debug=True)
            for node in ast.walk(tree):
                if isinstance(node, ast.keyword):
                    # Check for hot reload keywords
                    if node.arg in ['use_reloader', 'reload', 'debug']:
                        if isinstance(node.value, ast.Constant) and node.value.value is True:
                            line_num = node.lineno
                            param_name = node.arg
                            findings.append(Finding(
                                ksi_id=self.KSI_ID,
                                title="Hot reload enabled",
                                description=f"{param_name}=True at line {line_num} violates immutable deployment (NIST CM-3, CM-5)",
                                severity=Severity.HIGH,
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=self._get_snippet(lines, line_num),
                                remediation=f"Disable {param_name}, use CI/CD for changes. Example:\n"
                                           f"app.run(host='0.0.0.0', port=5000, {param_name}=False)"
                            ))
            
            # Pattern 2: setattr() on config objects
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id == 'setattr':
                        # Check if first arg contains 'config'
                        if node.args and len(node.args) >= 1:
                            first_arg = node.args[0]
                            arg_repr = ast.unparse(first_arg) if hasattr(ast, 'unparse') else ''
                            if 'config' in arg_repr.lower():
                                line_num = node.lineno
                                findings.append(Finding(
                                    ksi_id=self.KSI_ID,
                                    title="Runtime configuration modification",
                                    description=f"setattr() on config at line {line_num} bypasses version control (NIST CM-2)",
                                    severity=Severity.MEDIUM,
                                    file_path=file_path,
                                    line_number=line_num,
                                    code_snippet=self._get_snippet(lines, line_num),
                                    remediation="Use environment variables set at deployment:\n"
                                               "import os\n"
                                               "config.setting = os.getenv('SETTING', 'default')"
                                ))
            
            # Pattern 3: os.environ[] assignment
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Subscript):
                            # Check if it's os.environ[...]
                            if isinstance(target.value, ast.Attribute):
                                if (isinstance(target.value.value, ast.Name) and 
                                    target.value.value.id == 'os' and 
                                    target.value.attr == 'environ'):
                                    line_num = node.lineno
                                    findings.append(Finding(
                                        ksi_id=self.KSI_ID,
                                        title="Runtime environment modification",
                                        description=f"os.environ assignment at line {line_num} bypasses version control (NIST CM-2)",
                                        severity=Severity.MEDIUM,
                                        file_path=file_path,
                                        line_number=line_num,
                                        code_snippet=self._get_snippet(lines, line_num),
                                        remediation="Set environment variables at container startup:\n"
                                                   "# In Dockerfile or docker-compose.yml\n"
                                                   "ENV SETTING=value"
                                    ))
            
            # Pattern 4: config.__dict__[] assignment
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Subscript):
                            # Check for .__dict__[...]
                            if isinstance(target.value, ast.Attribute) and target.value.attr == '__dict__':
                                # Check if the object name contains 'config'
                                if isinstance(target.value.value, ast.Name):
                                    obj_name = target.value.value.id
                                    if 'config' in obj_name.lower():
                                        line_num = node.lineno
                                        findings.append(Finding(
                                            ksi_id=self.KSI_ID,
                                            title="Runtime configuration modification",
                                            description=f"config.__dict__ modification at line {line_num} bypasses version control (NIST CM-2)",
                                            severity=Severity.MEDIUM,
                                            file_path=file_path,
                                            line_number=line_num,
                                            code_snippet=self._get_snippet(lines, line_num),
                                            remediation="Use immutable config loaded at startup"
                                        ))
        
        except SyntaxError:
            # Fallback to regex for invalid syntax
            return self._python_regex_fallback(code, file_path, lines)
        
        return findings
    
    def _python_regex_fallback(self, code: str, file_path: str, lines: List[str]) -> List[Finding]:
        """Regex fallback for Python when AST fails"""
        findings = []
        
        # Hot reload patterns
        reload_patterns = [
            (r'use_reloader\s*=\s*True', 'use_reloader parameter'),
            (r'reload\s*=\s*True', 'reload parameter'),
            (r'debug\s*=\s*True', 'debug mode'),
        ]
        for pattern, desc in reload_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Hot reload enabled (Regex Fallback)",
                    description=f"{desc} at line {line_num} violates immutable deployment",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Disable hot reload, use CI/CD for changes"
                ))
        
        # Runtime config modification
        config_patterns = [
            r'setattr\(.*config',
            r'config\.__dict__\[',
            r'os\.environ\[.*\]\s*=',
        ]
        for pattern in config_patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Runtime configuration modification (Regex Fallback)",
                    description=f"Config modification at line {line_num} bypasses version control",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Use environment variables set at deployment"
                ))
        
        return findings
    
    def analyze_csharp(self, code: str, file_path: str = "") -> List[Finding]:
        """C#: Runtime compilation, hot reload"""
        findings = []
        lines = code.split('\n')
        
        # Razor runtime compilation
        if re.search(r'AddRazorRuntimeCompilation|UseRazorRuntimeCompilation', code):
            for match in re.finditer(r'(AddRazorRuntimeCompilation|UseRazorRuntimeCompilation)', code):
                line_num = code[:match.start()].count('\n') + 1
                context = self._get_context(lines, line_num, 5)
                
                # Check if development-only
                is_dev_only = bool(re.search(r'IsDevelopment|#if DEBUG', context))
                if not is_dev_only:
                    findings.append(Finding(
                        ksi_id=self.KSI_ID,
                        title="Razor runtime compilation enabled",
                        description=f"Runtime compilation at line {line_num} violates immutable deployment",
                        severity=Severity.HIGH,
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=self._get_snippet(lines, line_num),
                        remediation="Limit to development only: if (env.IsDevelopment())"
                    ))
        
        # Hot reload
        if re.search(r'UseHotReload|EnableHotReload', code):
            for match in re.finditer(r'(UseHotReload|EnableHotReload)', code):
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Hot reload enabled",
                    description=f"Hot reload at line {line_num} allows runtime changes",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Disable hot reload in production (CM-3)"
                ))
        
        # Runtime config modification
        if re.search(r'Configuration\[.*\]\s*=', code, re.IGNORECASE):
            for match in re.finditer(r'Configuration\[.*\]\s*=', code, re.IGNORECASE):
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Runtime configuration modification",
                    description=f"Config change at line {line_num} bypasses version control",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Set configuration at deployment time (CM-2)"
                ))
        
        return findings
    
    def analyze_java(self, code: str, file_path: str = "") -> List[Finding]:
        """Java: Hot swap, runtime config changes"""
        findings = []
        lines = code.split('\n')
        
        # Spring DevTools (hot swap)
        if re.search(r'spring-boot-devtools|DevToolsPropertyDefaultsPostProcessor', code):
            result = self._find_line(lines, 'devtools')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="Spring DevTools enabled",
                description=f"DevTools at line {line_num} enables hot swap in production",
                severity=Severity.HIGH,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Exclude devtools from production builds"
            ))
        
        # Runtime config modification
        config_patterns = [
            r'System\.setProperty\(',
            r'Environment\.setProperty\(',
        ]
        for pattern in config_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Runtime system property modification",
                    description=f"System property change at line {line_num} bypasses version control",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Set properties at JVM startup (CM-2)"
                ))
        
        return findings
    
    def analyze_typescript(self, code: str, file_path: str = "") -> List[Finding]:
        """TypeScript: Hot module reload, runtime config"""
        findings = []
        lines = code.split('\n')
        
        # Hot module replacement
        hmr_patterns = [
            r'hot:\s*true',
            r'module\.hot',
            r'if\s*\(module\.hot\)',
        ]
        for pattern in hmr_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Hot module replacement enabled",
                    description=f"HMR at line {line_num} allows runtime changes",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Disable HMR in production builds (CM-3)"
                ))
        
        # Runtime config modification
        if re.search(r'process\.env\[.*\]\s*=', code):
            for match in re.finditer(r'process\.env\[.*\]\s*=', code):
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Runtime environment modification",
                    description=f"process.env modification at line {line_num} bypasses version control",
                    severity=Severity.MEDIUM,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Set environment variables at container startup"
                ))
        
        return findings
    
    def analyze_bicep(self, code: str, file_path: str = "") -> List[Finding]:
        """Bicep: Mutable VM operations, manual scaling"""
        findings = []
        lines = code.split('\n')
        
        # VM extensions (mutable operations)
        if re.search(r"Microsoft\.Compute/virtualMachines/extensions", code):
            result = self._find_line(lines, 'virtualMachines/extensions')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="VM extension (mutable operation)",
                description=f"VM extension at line {line_num} modifies running VM instead of redeploying",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Use immutable VM scale sets with custom images (CM-3)"
            ))
        
        # Manual scaling (not autoscale)
        if re.search(r"Microsoft\.Compute/virtualMachineScaleSets", code):
            has_autoscale = bool(re.search(r"Microsoft\.Insights/autoscalesettings", code))
            if not has_autoscale:
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="VMSS without autoscale",
                    description="VM scale set without autoscale requires manual capacity changes",
                    severity=Severity.LOW,
                    file_path=file_path,
                    line_number=1,
                    code_snippet="VMSS detected",
                    remediation="Add autoscalesettings for immutable scaling (CM-2)"
                ))
        
        return findings
    
    def analyze_terraform(self, code: str, file_path: str = "") -> List[Finding]:
        """Terraform: Mutable operations, manual changes"""
        findings = []
        lines = code.split('\n')
        
        # VM extensions
        if re.search(r'azurerm_virtual_machine_extension', code):
            result = self._find_line(lines, 'virtual_machine_extension')

            line_num = result['line_num'] if result else 0
            findings.append(Finding(
                ksi_id=self.KSI_ID,
                title="VM extension (mutable operation)",
                description=f"VM extension at line {line_num} modifies running VM",
                severity=Severity.MEDIUM,
                file_path=file_path,
                line_number=line_num,
                code_snippet=self._get_snippet(lines, line_num),
                remediation="Use immutable infrastructure with custom images"
            ))
        
        # Manual provisioners (anti-pattern)
        if re.search(r'provisioner\s+"(remote-exec|local-exec)"', code):
            for match in re.finditer(r'provisioner\s+"(remote-exec|local-exec)"', code):
                line_num = code[:match.start()].count('\n') + 1
                findings.append(Finding(
                    ksi_id=self.KSI_ID,
                    title="Manual provisioner (anti-pattern)",
                    description=f"Provisioner at line {line_num} performs mutable operations",
                    severity=Severity.HIGH,
                    file_path=file_path,
                    line_number=line_num,
                    code_snippet=self._get_snippet(lines, line_num),
                    remediation="Use immutable images or init scripts (CM-3, CM-5)"
                ))
        
        return findings
    

        """Get code snippet around line"""
        if not lines or line_num < 1:
            return ""
        start = max(0, line_num - context - 1)
        end = min(len(lines), line_num + context)
        return '\n'.join(lines[start:end])

