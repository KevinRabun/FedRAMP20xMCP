"""
Test KSI-CNA-03 AST Conversion - Traffic Flow Controls

Tests AST-based analysis for C# and Java (Python already had AST).
Validates detection of:
- CORS allowing all origins
- Admin endpoints without IP filtering

Ref: KSI-CNA-03 (Enforce Traffic Flow)
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fedramp_20x_mcp.analyzers.ksi.ksi_cna_03 import KSI_CNA_03_Analyzer
from fedramp_20x_mcp.analyzers.base import Severity


def test_csharp_cors_wildcard():
    """Test C# AST detects CORS allowing all origins."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddCors(options =>
        {
            options.AddPolicy("AllowAll", policy =>
            {
                policy.AllowAnyOrigin()
                      .AllowAnyMethod()
                      .AllowAnyHeader();
            });
        });
    }
}
"""
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    assert result.total_issues >= 1, f"Expected at least 1 issue, got {result.total_issues}"
    
    cors_findings = [f for f in result.findings if "CORS" in f.title]
    assert len(cors_findings) == 1, f"Expected 1 CORS finding, got {len(cors_findings)}"
    assert cors_findings[0].severity == Severity.HIGH
    print("[PASS] C# CORS AllowAnyOrigin() detection works")


def test_csharp_cors_withorigins_wildcard():
    """Test C# AST detects WithOrigins("*")."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
using Microsoft.AspNetCore.Builder;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddCors(options =>
        {
            options.AddPolicy("AllowAll", policy =>
            {
                policy.WithOrigins("*")
                      .AllowCredentials();
            });
        });
    }
}
"""
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    cors_findings = [f for f in result.findings if "CORS" in f.title]
    assert len(cors_findings) == 1
    assert cors_findings[0].severity == Severity.HIGH
    print("[PASS] C# CORS WithOrigins(\"*\") detection works")


def test_csharp_cors_specific_origins_passes():
    """Test C# AST allows specific origins."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
using Microsoft.AspNetCore.Builder;

public class Startup
{
    public void ConfigureServices(IServiceCollection services)
    {
        services.AddCors(options =>
        {
            options.AddPolicy("AllowedOrigins", policy =>
            {
                policy.WithOrigins(
                    "https://app.example.com",
                    "https://admin.example.com"
                )
                .AllowCredentials();
            });
        });
    }
}
"""
    result = analyzer.analyze(code, "csharp", "Startup.cs")
    cors_findings = [f for f in result.findings if "CORS" in f.title]
    assert len(cors_findings) == 0, f"Expected 0 CORS findings, got {len(cors_findings)}"
    print("[PASS] C# specific CORS origins pass")


def test_csharp_admin_without_ip_filter():
    """Test C# AST detects admin controller without IP filtering."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("admin")]
public class AdminController : ControllerBase
{
    [HttpGet("dashboard")]
    public IActionResult Dashboard()
    {
        return Ok(new { message = "Admin dashboard" });
    }
}
"""
    result = analyzer.analyze(code, "csharp", "AdminController.cs")
    ip_findings = [f for f in result.findings if "IP" in f.title]
    assert len(ip_findings) == 1, f"Expected 1 IP filtering finding, got {len(ip_findings)}"
    assert ip_findings[0].severity == Severity.MEDIUM
    print("[PASS] C# admin controller without IP filter detection works")


def test_csharp_admin_with_ip_filter_passes():
    """Test C# AST allows admin controller with IP filtering."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
using Microsoft.AspNetCore.Mvc;
using System.Net;

[ApiController]
[Route("admin")]
[AllowedIP("10.0.0.0/8", "192.168.1.0/24")]
public class AdminController : ControllerBase
{
    [HttpGet("dashboard")]
    public IActionResult Dashboard()
    {
        var remoteIp = HttpContext.Connection.RemoteIpAddress;
        if (!IsAllowedIP(remoteIp))
        {
            return Forbid();
        }
        return Ok(new { message = "Admin dashboard" });
    }
}
"""
    result = analyzer.analyze(code, "csharp", "AdminController.cs")
    ip_findings = [f for f in result.findings if "IP" in f.title and "Admin" in f.title]
    assert len(ip_findings) == 0, f"Expected 0 IP filtering findings, got {len(ip_findings)}"
    print("[PASS] C# admin controller with IP filter passes")


def test_java_cors_wildcard():
    """Test Java AST detects CORS allowing all origins."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins("*")
            .allowedMethods("GET", "POST", "PUT", "DELETE")
            .allowCredentials(true);
    }
}
"""
    result = analyzer.analyze(code, "java", "WebConfig.java")
    cors_findings = [f for f in result.findings if "CORS" in f.title]
    assert len(cors_findings) == 1, f"Expected 1 CORS finding, got {len(cors_findings)}"
    assert cors_findings[0].severity == Severity.HIGH
    print("[PASS] Java CORS allowedOrigins(\"*\") detection works")


def test_java_cors_set_allowed_origins():
    """Test Java AST detects setAllowedOrigins with wildcard."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

public class CorsConfig {
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList("*"));
        config.setAllowedMethods(Arrays.asList("GET", "POST"));
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
"""
    result = analyzer.analyze(code, "java", "CorsConfig.java")
    cors_findings = [f for f in result.findings if "CORS" in f.title]
    assert len(cors_findings) == 1
    assert cors_findings[0].severity == Severity.HIGH
    print("[PASS] Java CORS setAllowedOrigins(\"*\") detection works")


def test_java_cors_specific_origins_passes():
    """Test Java AST allows specific origins."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/api/**")
            .allowedOrigins(
                "https://app.example.com",
                "https://admin.example.com"
            )
            .allowCredentials(true);
    }
}
"""
    result = analyzer.analyze(code, "java", "WebConfig.java")
    cors_findings = [f for f in result.findings if "CORS" in f.title]
    assert len(cors_findings) == 0, f"Expected 0 CORS findings, got {len(cors_findings)}"
    print("[PASS] Java specific CORS origins pass")


def test_java_admin_without_ip_filter():
    """Test Java AST detects admin controller without IP filtering."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
public class AdminController {
    
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, String>> dashboard() {
        Map<String, String> response = new HashMap<>();
        response.put("message", "Admin dashboard");
        return ResponseEntity.ok(response);
    }
}
"""
    result = analyzer.analyze(code, "java", "AdminController.java")
    ip_findings = [f for f in result.findings if "IP" in f.title]
    assert len(ip_findings) == 1, f"Expected 1 IP filtering finding, got {len(ip_findings)}"
    assert ip_findings[0].severity == Severity.MEDIUM
    print("[PASS] Java admin controller without IP filter detection works")


def test_java_admin_with_ip_filter_passes():
    """Test Java AST allows admin controller with IP filtering."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import inet.ipaddr.*;

@RestController
@RequestMapping("/admin")
public class AdminController {
    
    @GetMapping("/dashboard")
    public ResponseEntity<Map<String, String>> dashboard(HttpServletRequest request) {
        String remoteAddr = request.getRemoteAddr();
        IPAddress remoteIP = new IPAddressString(remoteAddr).getAddress();
        
        if (!isAllowedIP(remoteIP)) {
            return ResponseEntity.status(403).build();
        }
        
        Map<String, String> response = new HashMap<>();
        response.put("message", "Admin dashboard");
        return ResponseEntity.ok(response);
    }
}
"""
    result = analyzer.analyze(code, "java", "AdminController.java")
    ip_findings = [f for f in result.findings if "IP" in f.title and "Admin" in f.title]
    assert len(ip_findings) == 0, f"Expected 0 IP filtering findings, got {len(ip_findings)}"
    print("[PASS] Java admin controller with IP filter passes")


# ============================================================================
# TypeScript AST Tests (NEW - Reaching 88.2%)
# ============================================================================

def test_typescript_cors_wildcard():
    """Test TypeScript AST detects cors() allowing all origins."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
import express from 'express';
import cors from 'cors';

const app = express();

// INSECURE: Allows all origins
app.use(cors());

app.get('/api/data', (req, res) => {
    res.json({ data: 'sensitive' });
});
"""
    result = analyzer.analyze(code, "typescript", "server.ts")
    assert result.total_issues >= 1, f"Expected at least 1 issue, got {result.total_issues}"
    
    cors_findings = [f for f in result.findings if "CORS" in f.title]
    assert len(cors_findings) == 1, f"Expected 1 CORS finding, got {len(cors_findings)}"
    assert cors_findings[0].severity == Severity.HIGH
    print("[PASS] TypeScript cors() detected via AST")


def test_typescript_cors_origin_wildcard():
    """Test TypeScript AST detects origin: '*' configuration."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
import express from 'express';
import cors from 'cors';

const app = express();

// INSECURE: Wildcard origin
const corsOptions = {
    origin: '*',
    credentials: true
};
app.use(cors(corsOptions));
"""
    result = analyzer.analyze(code, "typescript", "server.ts")
    assert result.total_issues >= 1, f"Expected at least 1 issue, got {result.total_issues}"
    
    cors_findings = [f for f in result.findings if "CORS" in f.title]
    assert len(cors_findings) == 1, f"Expected 1 CORS finding, got {len(cors_findings)}"
    assert cors_findings[0].severity == Severity.HIGH
    print("[PASS] TypeScript origin: '*' detected via AST")


def test_typescript_cors_origin_true():
    """Test TypeScript AST detects origin: true configuration."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
import express from 'express';
import cors from 'cors';

const app = express();

// INSECURE: origin: true reflects requester
const corsOptions = {
    origin: true,
    credentials: true
};
app.use(cors(corsOptions));
"""
    result = analyzer.analyze(code, "typescript", "server.ts")
    assert result.total_issues >= 1, f"Expected at least 1 issue, got {result.total_issues}"
    
    cors_findings = [f for f in result.findings if "CORS" in f.title]
    assert len(cors_findings) == 1, f"Expected 1 CORS finding, got {len(cors_findings)}"
    assert cors_findings[0].severity == Severity.HIGH
    print("[PASS] TypeScript origin: true detected via AST")


def test_typescript_cors_specific_origins_passes():
    """Test TypeScript AST passes secure CORS with specific origins."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
import express from 'express';
import cors from 'cors';

const app = express();

// SECURE: Specific origins
const corsOptions = {
    origin: [
        'https://app.example.com',
        'https://admin.example.com'
    ],
    credentials: true,
    methods: ['GET', 'POST']
};
app.use(cors(corsOptions));
"""
    result = analyzer.analyze(code, "typescript", "server.ts")
    
    cors_findings = [f for f in result.findings if "CORS" in f.title]
    assert len(cors_findings) == 0, f"Expected 0 CORS findings, got {len(cors_findings)}"
    print("[PASS] TypeScript specific CORS origins pass via AST")


def test_typescript_admin_route_without_ip_filter():
    """Test TypeScript AST detects admin routes without IP filtering."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
import express from 'express';

const app = express();

// INSECURE: Admin route without IP filtering
app.get('/admin/dashboard', (req, res) => {
    res.json({ users: ['admin', 'user1'] });
});

app.post('/admin/users', (req, res) => {
    // Create user
    res.json({ success: true });
});
"""
    result = analyzer.analyze(code, "typescript", "server.ts")
    assert result.total_issues >= 1, f"Expected at least 1 issue, got {result.total_issues}"
    
    ip_findings = [f for f in result.findings if "IP" in f.title and "Admin" in f.title]
    assert len(ip_findings) >= 1, f"Expected at least 1 IP filtering finding, got {len(ip_findings)}"
    assert ip_findings[0].severity == Severity.MEDIUM
    print("[PASS] TypeScript admin route without IP filter detected via AST")


def test_typescript_admin_route_with_ip_filter_passes():
    """Test TypeScript AST passes admin routes with IP filtering."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
import express from 'express';

const app = express();

// SECURE: Admin route with IP filtering
const ALLOWED_IPS = ['10.0.0.1', '192.168.1.100'];

function ipWhitelist(req, res, next) {
    const clientIP = req.ip || req.connection.remoteAddress;
    if (ALLOWED_IPS.includes(clientIP)) {
        next();
    } else {
        res.status(403).send('Access denied');
    }
}

app.use('/admin', ipWhitelist);

app.get('/admin/dashboard', (req, res) => {
    res.json({ users: ['admin', 'user1'] });
});
"""
    result = analyzer.analyze(code, "typescript", "server.ts")
    
    ip_findings = [f for f in result.findings if "IP" in f.title and "Admin" in f.title]
    assert len(ip_findings) == 0, f"Expected 0 IP filtering findings, got {len(ip_findings)}"
    print("[PASS] TypeScript admin route with IP filter passes via AST")


def test_typescript_nestjs_cors_wildcard():
    """Test TypeScript AST detects NestJS enableCors() with wildcard."""
    analyzer = KSI_CNA_03_Analyzer()
    code = """
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
    const app = await NestFactory.create(AppModule);
    
    // INSECURE: Allows all origins
    app.enableCors({
        origin: '*',
        credentials: true
    });
    
    await app.listen(3000);
}
bootstrap();
"""
    result = analyzer.analyze(code, "typescript", "main.ts")
    assert result.total_issues >= 1, f"Expected at least 1 issue, got {result.total_issues}"
    
    cors_findings = [f for f in result.findings if "CORS" in f.title]
    assert len(cors_findings) == 1, f"Expected 1 CORS finding, got {len(cors_findings)}"
    assert cors_findings[0].severity == Severity.HIGH
    print("[PASS] TypeScript NestJS enableCors wildcard detected via AST")


if __name__ == "__main__":
    print("=== Testing KSI-CNA-03 AST Conversion ===\n")
    
    print("C# Tests:")
    test_csharp_cors_wildcard()
    test_csharp_cors_withorigins_wildcard()
    test_csharp_cors_specific_origins_passes()
    test_csharp_admin_without_ip_filter()
    test_csharp_admin_with_ip_filter_passes()
    
    print("\nJava Tests:")
    test_java_cors_wildcard()
    test_java_cors_set_allowed_origins()
    test_java_cors_specific_origins_passes()
    test_java_admin_without_ip_filter()
    test_java_admin_with_ip_filter_passes()
    
    print("\nTypeScript Tests:")
    test_typescript_cors_wildcard()
    test_typescript_cors_origin_wildcard()
    test_typescript_cors_origin_true()
    test_typescript_cors_specific_origins_passes()
    test_typescript_admin_route_without_ip_filter()
    test_typescript_admin_route_with_ip_filter_passes()
    test_typescript_nestjs_cors_wildcard()
    
    print("\n" + "="*70)
    print("ALL 17 CNA-03 TESTS PASSED [PASS]")
    print("Languages: C# (5), Java (5), TypeScript (7)")
    print("Progress: 15/17 analyzers complete (88.2%)")
    print("="*70)
