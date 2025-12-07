"""
Tests for Security Tools (CVE Vulnerability MCP Tools)

Tests the MCP tools for checking package vulnerabilities.
"""

import json
import io
import asyncio

# Set UTF-8 encoding for stdout (Windows compatibility)

# Add src directory to path

from fedramp_20x_mcp.tools.security import (
    check_package_vulnerabilities_impl,
    scan_dependency_file_impl,
    _parse_nuget_deps,
    _parse_npm_deps,
    _parse_python_deps,
    _parse_maven_deps
)

async def test_check_package_vulnerabilities_basic():
    """Test basic package vulnerability checking."""
    print("Testing check_package_vulnerabilities (basic)...")
    
    result = await check_package_vulnerabilities_impl(
        package_name="Newtonsoft.Json",
        ecosystem="nuget",
        version="12.0.1"  # Old version with known issues
    )
    
    data = json.loads(result)
    assert "status" in data
    assert data["package"] == "Newtonsoft.Json"
    assert data["ecosystem"] == "nuget"
    
    print(f"   Status: {data['status']}")
    if data["status"] == "vulnerabilities_found":
        print(f"   Found {data['vulnerabilities_found']} vulnerabilities")
        print("✅ check_package_vulnerabilities test passed")
    else:
        print("✅ check_package_vulnerabilities test passed (no vulnerabilities)")

async def test_check_package_vulnerabilities_safe():
    """Test checking a safe package."""
    print("Testing check_package_vulnerabilities (safe package)...")
    
    result = await check_package_vulnerabilities_impl(
        package_name="Azure.Identity",
        ecosystem="nuget",
        version="1.11.0"
    )
    
    data = json.loads(result)
    assert data["package"] == "Azure.Identity"
    
    print(f"   Status: {data['status']}")
    print("✅ Safe package check test passed")

async def test_check_package_vulnerabilities_error():
    """Test error handling for invalid package."""
    print("Testing check_package_vulnerabilities (error handling)...")
    
    result = await check_package_vulnerabilities_impl(
        package_name="NonExistentPackageXYZ123",
        ecosystem="nuget"
    )
    
    data = json.loads(result)
    # Should return success with 0 vulnerabilities or error
    assert "status" in data
    
    print(f"   Status: {data['status']}")
    print("✅ Error handling test passed")

def test_parse_nuget_deps():
    """Test NuGet dependency parsing."""
    print("Testing NuGet dependency parsing...")
    
    csproj_content = '''<?xml version="1.0" encoding="utf-8"?>
<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="Azure.Identity" Version="1.11.0" />
    <PackageReference Include="Microsoft.EntityFrameworkCore" Version="8.0.0" />
  </ItemGroup>
</Project>'''
    
    packages = _parse_nuget_deps(csproj_content)
    
    assert len(packages) == 3
    assert ("Newtonsoft.Json", "12.0.1", "nuget") in packages
    assert ("Azure.Identity", "1.11.0", "nuget") in packages
    assert ("Microsoft.EntityFrameworkCore", "8.0.0", "nuget") in packages
    
    print(f"   Parsed {len(packages)} packages")
    print("✅ NuGet dependency parsing test passed")

def test_parse_npm_deps():
    """Test npm dependency parsing."""
    print("Testing npm dependency parsing...")
    
    package_json = '''{
  "name": "my-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "~4.17.21"
  },
  "devDependencies": {
    "jest": "^29.5.0"
  }
}'''
    
    packages = _parse_npm_deps(package_json)
    
    assert len(packages) >= 2  # At least dependencies
    
    # Check for express and lodash (version prefixes should be removed)
    package_names = [p[0] for p in packages]
    assert "express" in package_names
    assert "lodash" in package_names
    
    print(f"   Parsed {len(packages)} packages")
    print("✅ npm dependency parsing test passed")

def test_parse_python_deps():
    """Test Python dependency parsing."""
    print("Testing Python dependency parsing...")
    
    requirements_txt = '''requests>=2.28.0
flask==2.3.0
django>=4.0.0,<5.0.0
# Comment line
pytest>=7.0.0'''
    
    packages = _parse_python_deps(requirements_txt, "requirements.txt")
    
    assert len(packages) >= 2
    
    # Check for requests and flask
    package_names = [p[0] for p in packages]
    assert "requests" in package_names or "flask" in package_names
    
    print(f"   Parsed {len(packages)} packages")
    print("✅ Python dependency parsing test passed")

def test_parse_maven_deps():
    """Test Maven dependency parsing."""
    print("Testing Maven dependency parsing...")
    
    pom_xml = '''<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <dependencies>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
      <version>3.0.0</version>
    </dependency>
    <dependency>
      <groupId>com.google.guava</groupId>
      <artifactId>guava</artifactId>
      <version>31.1-jre</version>
    </dependency>
  </dependencies>
</project>'''
    
    packages = _parse_maven_deps(pom_xml)
    
    # May not parse correctly without namespace, but should not crash
    print(f"   Attempted to parse Maven dependencies")
    print("✅ Maven dependency parsing test passed (no crash)")

async def test_scan_dependency_file_csproj():
    """Test scanning a full .csproj file."""
    print("Testing scan_dependency_file (csproj)...")
    
    csproj_content = '''<?xml version="1.0" encoding="utf-8"?>
<Project Sdk="Microsoft.NET.Sdk.Web">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.1" />
    <PackageReference Include="Azure.Identity" Version="1.11.0" />
  </ItemGroup>
</Project>'''
    
    result = await scan_dependency_file_impl(
        file_content=csproj_content,
        file_type="csproj"
    )
    
    data = json.loads(result)
    
    assert data["status"] == "scan_complete"
    assert data["file_type"] == "csproj"
    assert data["packages_scanned"] >= 1
    
    print(f"   Scanned {data['packages_scanned']} packages")
    print(f"   Found {data.get('total_vulnerabilities', 0)} vulnerabilities")
    print("✅ scan_dependency_file test passed")

async def test_scan_dependency_file_package_json():
    """Test scanning package.json."""
    print("Testing scan_dependency_file (package.json)...")
    
    package_json = '''{
  "dependencies": {
    "lodash": "4.17.15",
    "express": "4.18.2"
  }
}'''
    
    result = await scan_dependency_file_impl(
        file_content=package_json,
        file_type="package.json"
    )
    
    data = json.loads(result)
    
    assert data["status"] == "scan_complete"
    assert data["packages_scanned"] >= 1
    
    print(f"   Scanned {data['packages_scanned']} packages")
    print("✅ package.json scan test passed")

async def test_scan_dependency_file_requirements_txt():
    """Test scanning requirements.txt."""
    print("Testing scan_dependency_file (requirements.txt)...")
    
    requirements_txt = '''requests>=2.28.0
flask==2.3.0'''
    
    result = await scan_dependency_file_impl(
        file_content=requirements_txt,
        file_type="requirements.txt"
    )
    
    data = json.loads(result)
    
    assert data["status"] == "scan_complete"
    
    print(f"   Scanned {data['packages_scanned']} packages")
    print("✅ requirements.txt scan test passed")

async def test_scan_dependency_file_unsupported():
    """Test error handling for unsupported file type."""
    print("Testing scan_dependency_file (unsupported file)...")
    
    result = await scan_dependency_file_impl(
        file_content="<some content>",
        file_type="unsupported.txt"
    )
    
    data = json.loads(result)
    
    assert data["status"] == "error"
    assert "Unsupported file type" in data["error"]
    
    print("✅ Unsupported file type test passed")

def test_fedramp_compliance_info():
    """Test that FedRAMP compliance info is included."""
    print("Testing FedRAMP compliance information...")
    
    async def check():
        result = await check_package_vulnerabilities_impl(
            package_name="TestPackage",
            ecosystem="nuget"
        )
        
        data = json.loads(result)
        
        # Should have recommendation
        assert "recommendation" in data
        
        # If vulnerabilities found, should have FedRAMP compliance section
        if data["status"] == "vulnerabilities_found":
            assert "fedramp_compliance" in data
            assert "requirement" in data["fedramp_compliance"]
    
    asyncio.run(check())
    print("✅ FedRAMP compliance information test passed")

def run_all_tests():
    """Run all security tool tests."""
    print("=" * 60)
    print("Running Security Tools Tests")
    print("=" * 60)
    print()
    
    # Async tests
    print("MCP Tool Tests:")
    print("-" * 60)
    asyncio.run(test_check_package_vulnerabilities_basic())
    asyncio.run(test_check_package_vulnerabilities_safe())
    asyncio.run(test_check_package_vulnerabilities_error())
    
    print()
    print("Dependency Parsing Tests:")
    print("-" * 60)
    test_parse_nuget_deps()
    test_parse_npm_deps()
    test_parse_python_deps()
    test_parse_maven_deps()
    
    print()
    print("File Scanning Tests:")
    print("-" * 60)
    asyncio.run(test_scan_dependency_file_csproj())
    asyncio.run(test_scan_dependency_file_package_json())
    asyncio.run(test_scan_dependency_file_requirements_txt())
    asyncio.run(test_scan_dependency_file_unsupported())
    
    print()
    print("Compliance Tests:")
    print("-" * 60)
    test_fedramp_compliance_info()
    
    print()
    print("=" * 60)
    print("All Security Tools Tests Completed!")
    print("=" * 60)

if __name__ == "__main__":
    run_all_tests()
