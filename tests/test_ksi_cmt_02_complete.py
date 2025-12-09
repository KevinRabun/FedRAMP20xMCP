"""
Test suite for KSI-CMT-02 Enhanced: Immutable Infrastructure
Tests AST-based Python analyzer and regex-based C#/Java/TypeScript/IaC analyzers
"""

import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from fedramp_20x_mcp.analyzers.ksi.ksi_cmt_02 import KSI_CMT_02_Analyzer


def test_python_hot_reload_detection():
    """Test Python AST detection of hot reload parameters"""
    code = """
from flask import Flask
app = Flask(__name__)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'python', 'app.py')
    findings = result.findings
    
    assert len(findings) >= 1, f"Expected findings for debug=True, got {len(findings)}"
    hot_reload_findings = [f for f in findings if "Hot reload" in f.title and "debug" in f.description.lower()]
    assert len(hot_reload_findings) >= 1, "Should detect debug=True as hot reload"
    print("[PASS] Python: Detects debug=True hot reload parameter")


def test_python_use_reloader_detection():
    """Test Python AST detection of use_reloader parameter"""
    code = """
from flask import Flask
app = Flask(__name__)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, use_reloader=True)
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'python', 'app.py')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect use_reloader=True"
    assert any("use_reloader" in f.description for f in findings)
    print("[PASS] Python: Detects use_reloader=True parameter")


def test_python_os_environ_assignment():
    """Test Python AST detection of os.environ assignment"""
    code = """
import os

def configure():
    os.environ['DATABASE_URL'] = 'postgresql://localhost/db'
    os.environ['SECRET_KEY'] = 'hardcoded-secret'
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'python', 'config.py')
    findings = result.findings
    
    assert len(findings) >= 2, f"Should detect 2 os.environ assignments, got {len(findings)}"
    env_findings = [f for f in findings if "Runtime environment modification" in f.title]
    assert len(env_findings) >= 2, "Should detect both os.environ assignments"
    print("[PASS] Python: Detects os.environ assignments")


def test_python_setattr_config():
    """Test Python AST detection of setattr() on config objects"""
    code = """
import config

def update_settings():
    setattr(config, 'DEBUG', True)
    setattr(config, 'DATABASE_URL', 'postgresql://localhost/db')
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'python', 'update.py')
    findings = result.findings
    
    assert len(findings) >= 2, f"Should detect 2 setattr calls, got {len(findings)}"
    config_findings = [f for f in findings if "Runtime configuration modification" in f.title]
    assert len(config_findings) >= 2, "Should detect both setattr() calls"
    print("[PASS] Python: Detects setattr() on config objects")


def test_python_config_dict_assignment():
    """Test Python AST detection of config.__dict__[] assignment"""
    code = """
class Config:
    pass

config = Config()
config.__dict__['DEBUG'] = True
config.__dict__['SECRET_KEY'] = 'value'
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'python', 'config.py')
    findings = result.findings
    
    assert len(findings) >= 2, f"Should detect 2 __dict__ assignments, got {len(findings)}"
    dict_findings = [f for f in findings if "Runtime configuration modification" in f.title]
    assert len(dict_findings) >= 2, "Should detect __dict__ modifications"
    print("[PASS] Python: Detects config.__dict__[] assignments")


def test_csharp_razor_runtime_compilation():
    """Test C# detection of Razor runtime compilation"""
    code = """
public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddRazorPages()
                .AddRazorRuntimeCompilation();
    }
}
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'csharp', 'Startup.cs')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect AddRazorRuntimeCompilation"
    assert any("Razor runtime compilation" in f.title for f in findings)
    print("[PASS] C#: Detects AddRazorRuntimeCompilation without dev check")


def test_csharp_configuration_assignment():
    """Test C# detection of runtime configuration assignment"""
    code = """
public class ConfigManager
{
    public void UpdateConfig(IConfiguration configuration)
    {
        configuration["ConnectionStrings:Default"] = "Server=localhost";
        configuration["Logging:LogLevel:Default"] = "Debug";
    }
}
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'csharp', 'ConfigManager.cs')
    findings = result.findings
    
    assert len(findings) >= 2, f"Should detect 2 config assignments, got {len(findings)}"
    config_findings = [f for f in findings if "Runtime configuration modification" in f.title]
    assert len(config_findings) >= 2, "Should detect Configuration[] assignments"
    print("[PASS] C#: Detects Configuration[] runtime assignments")


def test_java_spring_devtools():
    """Test Java detection of Spring DevTools"""
    code = """
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-devtools</artifactId>
    <scope>runtime</scope>
</dependency>
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'java', 'pom.xml')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect spring-boot-devtools"
    assert any("DevTools" in f.title for f in findings)
    print("[PASS] Java: Detects Spring DevTools dependency")


def test_java_system_setproperty():
    """Test Java detection of System.setProperty()"""
    code = """
public class ConfigManager {
    public void configure() {
        System.setProperty("spring.datasource.url", "jdbc:postgresql://localhost/db");
        System.setProperty("app.debug", "true");
    }
}
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'java', 'ConfigManager.java')
    findings = result.findings
    
    assert len(findings) >= 2, f"Should detect 2 System.setProperty calls, got {len(findings)}"
    prop_findings = [f for f in findings if "system property" in f.title.lower()]
    assert len(prop_findings) >= 2, "Should detect System.setProperty() calls"
    print("[PASS] Java: Detects System.setProperty() calls")


def test_typescript_hmr_detection():
    """Test TypeScript detection of Hot Module Replacement"""
    code = """
import express from 'express';

if (module.hot) {
    module.hot.accept();
}

const config = {
    hot: true,
    devServer: {
        hot: true
    }
};
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'typescript', 'app.ts')
    findings = result.findings
    
    assert len(findings) >= 2, f"Should detect HMR patterns, got {len(findings)}"
    hmr_findings = [f for f in findings if "Hot module replacement" in f.title]
    assert len(hmr_findings) >= 2, "Should detect module.hot and hot: true"
    print("[PASS] TypeScript: Detects Hot Module Replacement patterns")


def test_typescript_process_env_assignment():
    """Test TypeScript detection of process.env assignment"""
    code = """
export function configure() {
    process.env['DATABASE_URL'] = 'postgresql://localhost/db';
    process.env['API_KEY'] = 'secret-key';
}
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'typescript', 'config.ts')
    findings = result.findings
    
    assert len(findings) >= 2, f"Should detect 2 process.env assignments, got {len(findings)}"
    env_findings = [f for f in findings if "Runtime environment modification" in f.title]
    assert len(env_findings) >= 2, "Should detect process.env assignments"
    print("[PASS] TypeScript: Detects process.env[] assignments")


def test_bicep_vm_extension():
    """Test Bicep detection of VM extensions (mutable operations)"""
    code = """
resource vmExtension 'Microsoft.Compute/virtualMachines/extensions@2021-03-01' = {
  name: 'my-extension'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Extensions'
    type: 'CustomScript'
  }
}
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'bicep', 'vm.bicep')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect VM extension"
    assert any("VM extension" in f.title for f in findings)
    print("[PASS] Bicep: Detects VM extensions (mutable operations)")


def test_terraform_provisioner():
    """Test Terraform detection of remote-exec provisioner"""
    code = """
resource "azurerm_virtual_machine" "example" {
  name = "example-vm"
  
  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install -y nginx"
    ]
  }
}
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'terraform', 'vm.tf')
    findings = result.findings
    
    assert len(findings) >= 1, "Should detect remote-exec provisioner"
    assert any("provisioner" in f.title.lower() for f in findings)
    print("[PASS] Terraform: Detects remote-exec provisioner (anti-pattern)")


def test_python_regex_fallback():
    """Test Python regex fallback on syntax error"""
    code = """
# Invalid syntax to trigger fallback
app.run(debug=True
app.config['DEBUG'] = True
os.environ['KEY'] = 'value'
"""
    analyzer = KSI_CMT_02_Analyzer()
    result = analyzer.analyze(code, 'python', 'invalid.py')
    findings = result.findings
    
    # Should use regex fallback
    assert len(findings) >= 1, "Regex fallback should detect patterns"
    # Check if fallback was used (look for "Regex Fallback" in title)
    fallback_findings = [f for f in findings if "Regex Fallback" in f.title]
    assert len(fallback_findings) >= 1, "Should use regex fallback on syntax error"
    print("[PASS] Python: Regex fallback works on syntax error")


def run_all_tests():
    """Run all CMT-02 tests"""
    tests = [
        test_python_hot_reload_detection,
        test_python_use_reloader_detection,
        test_python_os_environ_assignment,
        test_python_setattr_config,
        test_python_config_dict_assignment,
        test_csharp_razor_runtime_compilation,
        test_csharp_configuration_assignment,
        test_java_spring_devtools,
        test_java_system_setproperty,
        test_typescript_hmr_detection,
        test_typescript_process_env_assignment,
        test_bicep_vm_extension,
        test_terraform_provisioner,
        test_python_regex_fallback,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__}: {e}")
            failed += 1
        except Exception as e:
            print(f"[ERROR] {test.__name__}: {e}")
            failed += 1
    
    print(f"\n{'='*60}")
    print(f"CMT-02 Test Results: {passed}/{len(tests)} passed")
    if failed == 0:
        print("ALL TESTS PASSED!")
    else:
        print(f"{failed} test(s) failed")
    print(f"{'='*60}")
    
    return failed == 0


if __name__ == '__main__':
    success = run_all_tests()
    sys.exit(0 if success else 1)
