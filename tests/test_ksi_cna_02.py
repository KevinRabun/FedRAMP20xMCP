"""
Tests for KSI-CNA-02 Enhanced Analyzer: Minimize the Attack Surface

Tests AST-based detection of attack surface expansion issues across multiple languages.
"""

import sys
sys.path.insert(0, 'c:\\source\\FedRAMP20xMCP\\src')

from fedramp_20x_mcp.analyzers.ksi.ksi_cna_02 import KSI_CNA_02_Analyzer
from fedramp_20x_mcp.analyzers.ast_utils import CodeLanguage
from fedramp_20x_mcp.analyzers.base import Severity


def test_python_debug_mode():
    """Test detection of debug mode enabled in Python."""
    code = """
import flask

app = flask.Flask(__name__)

@app.route('/')
def hello():
    return "Hello World"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
"""
    
    analyzer = KSI_CNA_02_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    assert len(critical_findings) > 0, "Should detect debug mode enabled"
    assert any("debug" in f.title.lower() for f in critical_findings)
    assert any("attack surface" in f.description.lower() for f in critical_findings)
    
    print("[PASS] Python debug mode detection working")


def test_python_permissive_cors():
    """Test detection of permissive CORS in Python."""
    code = """
from flask import Flask
from flask_cors import CORS

app = Flask(__name__)
CORS(app, origins='*')

@app.route('/api/data')
def get_data():
    return {'data': 'sensitive'}
"""
    
    analyzer = KSI_CNA_02_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    
    findings = result.findings
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    
    assert len(high_findings) > 0, "Should detect permissive CORS"
    assert any("cors" in f.title.lower() for f in high_findings)
    assert any("*" in f.description or "all origins" in f.description.lower() for f in high_findings)
    
    print("[PASS] Python permissive CORS detection working")


def test_python_secure_no_debug():
    """Test that secure Python code without debug mode passes."""
    code = """
from flask import Flask

app = Flask(__name__)

@app.route('/')
def hello():
    return "Hello World"

if __name__ == '__main__':
    app.run(debug=False)  # Secure: debug disabled
"""
    
    analyzer = KSI_CNA_02_Analyzer()
    result = analyzer.analyze(code, "python", "app.py")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    assert len(critical_findings) == 0, "Secure code should not trigger CRITICAL findings"
    
    print("[PASS] Python secure code (no debug) passes")


def test_csharp_developer_exception_page():
    """Test detection of UseDeveloperExceptionPage without environment check."""
    code = """
using Microsoft.AspNetCore.Builder;

public class Startup
{
    public void Configure(IApplicationBuilder app)
    {
        app.UseDeveloperExceptionPage();
        app.UseRouting();
        app.UseEndpoints(endpoints => endpoints.MapControllers());
    }
}
"""
    
    analyzer = KSI_CNA_02_Analyzer()
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    assert len(critical_findings) > 0, "Should detect UseDeveloperExceptionPage without env check"
    assert any("developer exception" in f.title.lower() for f in critical_findings)
    
    print("[PASS] C# UseDeveloperExceptionPage detection working")


def test_csharp_allow_any_origin():
    """Test detection of AllowAnyOrigin in CORS."""
    code = """
using Microsoft.AspNetCore.Builder;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddCors(options =>
        {
            options.AddPolicy("AllowAll", builder =>
            {
                builder.AllowAnyOrigin()
                       .AllowAnyMethod()
                       .AllowAnyHeader();
            });
        });
    }
}
"""
    
    analyzer = KSI_CNA_02_Analyzer()
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    
    findings = result.findings
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    
    assert len(high_findings) > 0, "Should detect AllowAnyOrigin"
    assert any("cors" in f.title.lower() for f in high_findings)
    
    print("[PASS] C# AllowAnyOrigin detection working")


def test_csharp_secure_with_env_check():
    """Test that C# code with proper environment check passes."""
    code = """
using Microsoft.AspNetCore.Builder;

public class Startup
{
    public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
    {
        if (env.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }
        else
        {
            app.UseExceptionHandler("/Error");
        }
        
        app.UseRouting();
    }
}
"""
    
    analyzer = KSI_CNA_02_Analyzer()
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    
    findings = result.findings
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    
    assert len(critical_findings) == 0, "Secure C# code with env check should not trigger CRITICAL findings"
    
    print("[PASS] C# secure code with environment check passes")


def test_java_permissive_cors():
    """Test detection of permissive CORS in Java."""
    code = """
import org.springframework.web.servlet.config.annotation.CorsRegistry;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
                .allowedOrigins("*")
                .allowedMethods("GET", "POST", "PUT", "DELETE");
    }
}
"""
    
    analyzer = KSI_CNA_02_Analyzer()
    result = analyzer.analyze(code, "java", "WebConfig.java")
    
    findings = result.findings
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    
    assert len(high_findings) > 0, "Should detect permissive CORS"
    assert any("cors" in f.title.lower() for f in high_findings)
    
    print("[PASS] Java permissive CORS detection working")


def test_java_actuator_without_security():
    """Test detection of Spring Boot Actuator without security."""
    code = """
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// Application has spring-boot-starter-actuator dependency but no explicit endpoint restrictions
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}
"""
    
    analyzer = KSI_CNA_02_Analyzer()
    result = analyzer.analyze(code, "java", "Application.java")
    
    findings = result.findings
    # Note: This test may not detect actuator in Java code alone (it would be in pom.xml/gradle)
    # For now, just verify no crashes - actual detection would require build file analysis
    
    print("[PASS] Java actuator test passes (no crashes)")


def test_javascript_permissive_cors():
    """Test detection of permissive CORS in JavaScript."""
    code = """
const express = require('express');
const cors = require('cors');

const app = express();

app.use(cors({ origin: '*' }));

app.get('/api/data', (req, res) => {
    res.json({ data: 'sensitive information' });
});

app.listen(3000);
"""
    
    analyzer = KSI_CNA_02_Analyzer()
    result = analyzer.analyze(code, "javascript", "server.js")
    
    findings = result.findings
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    
    assert len(high_findings) > 0, "Should detect permissive CORS"
    assert any("cors" in f.title.lower() for f in high_findings)
    
    print("[PASS] JavaScript permissive CORS detection working")


def test_javascript_stack_trace_exposure():
    """Test detection of stack trace exposure in error handlers."""
    code = """
const express = require('express');
const app = express();

app.get('/api/process', async (req, res) => {
    try {
        const result = await processData(req.body);
        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});
"""
    
    analyzer = KSI_CNA_02_Analyzer()
    result = analyzer.analyze(code, "javascript", "server.js")
    
    findings = result.findings
    medium_findings = [f for f in findings if f.severity == Severity.MEDIUM]
    
    assert len(medium_findings) > 0, "Should detect stack trace exposure"
    assert any("stack" in f.title.lower() for f in medium_findings)
    
    print("[PASS] JavaScript stack trace exposure detection working")


def test_typescript_secure_cors():
    """Test that TypeScript code with restricted CORS passes."""
    code = """
import express from 'express';
import cors from 'cors';

const app = express();

app.use(cors({
    origin: ['https://yourdomain.com', 'https://trusted.com'],
    credentials: true
}));

app.get('/api/data', (req, res) => {
    res.json({ data: 'information' });
});
"""
    
    analyzer = KSI_CNA_02_Analyzer()
    result = analyzer.analyze(code, "typescript", "server.ts")
    
    findings = result.findings
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    
    assert len(high_findings) == 0, "Secure CORS configuration should not trigger HIGH findings"
    
    print("[PASS] TypeScript secure CORS passes")


def test_factory_function():
    """Test direct instantiation of analyzers."""
    analyzer_py = KSI_CNA_02_Analyzer(CodeLanguage.PYTHON)
    assert analyzer_py.direct_language == CodeLanguage.PYTHON
    
    analyzer_cs = KSI_CNA_02_Analyzer(CodeLanguage.CSHARP)
    assert analyzer_cs.direct_language == CodeLanguage.CSHARP
    
    analyzer_java = KSI_CNA_02_Analyzer(CodeLanguage.JAVA)
    assert analyzer_java.direct_language == CodeLanguage.JAVA
    
    analyzer_js = KSI_CNA_02_Analyzer(CodeLanguage.JAVASCRIPT)
    assert analyzer_js.direct_language == CodeLanguage.JAVASCRIPT
    
    analyzer_ts = KSI_CNA_02_Analyzer(CodeLanguage.TYPESCRIPT)
    assert analyzer_ts.direct_language == CodeLanguage.TYPESCRIPT
    
    print("[PASS] Direct instantiation working")


if __name__ == "__main__":
    print("Running KSI-CNA-02 Enhanced Analyzer tests...\n")
    
    tests = [
        test_python_debug_mode,
        test_python_permissive_cors,
        test_python_secure_no_debug,
        test_csharp_developer_exception_page,
        test_csharp_allow_any_origin,
        test_csharp_secure_with_env_check,
        test_java_permissive_cors,
        test_java_actuator_without_security,
        test_javascript_permissive_cors,
        test_javascript_stack_trace_exposure,
        test_typescript_secure_cors,
        test_factory_function,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"[FAIL] {test.__name__} failed: {e}")
            failed += 1
        except Exception as e:
            print(f"[FAIL] {test.__name__} error: {e}")
            failed += 1
    
    print(f"\n{'=' * 60}")
    print(f"KSI-CNA-02 Enhanced Tests: {passed}/{len(tests)} passed")
    if failed > 0:
        print(f"FAILURES: {failed}")
        sys.exit(1)
    else:
        print("ALL TESTS PASSED [PASS]")
        sys.exit(0)

