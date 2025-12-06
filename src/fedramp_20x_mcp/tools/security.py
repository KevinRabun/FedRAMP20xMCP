"""
Security Tools - CVE Vulnerability Checking

Provides MCP tools for checking package vulnerabilities against
authoritative CVE databases (GitHub Advisory, NVD).
"""

from typing import Dict, List, Optional
import json

from ..cve_fetcher import CVEFetcher, Vulnerability


async def check_package_vulnerabilities_impl(
    package_name: str,
    ecosystem: str,
    version: Optional[str] = None,
    github_token: Optional[str] = None
) -> str:
    """
    Check a package for known CVE vulnerabilities.
    
    Queries GitHub Advisory Database for security vulnerabilities in the specified package.
    Returns detailed information about CVEs, affected versions, and remediation.
    
    Args:
        package_name: Package name (e.g., "Newtonsoft.Json", "lodash", "requests")
        ecosystem: Package ecosystem ("nuget", "npm", "pypi", "maven")
        version: Specific version to check (optional, checks all if omitted)
        github_token: GitHub PAT for higher rate limits (optional)
    
    Returns:
        JSON string with vulnerability details
    """
    fetcher = CVEFetcher(github_token=github_token)
    
    try:
        vulnerabilities = fetcher.get_package_vulnerabilities(
            package_name=package_name,
            ecosystem=ecosystem,
            version=version
        )
        
        if not vulnerabilities:
            return json.dumps({
                "status": "success",
                "package": package_name,
                "ecosystem": ecosystem,
                "version": version,
                "vulnerabilities_found": 0,
                "message": f"No known vulnerabilities found for {package_name}",
                "recommendation": "Package appears safe, but continue to monitor for new advisories."
            }, indent=2)
        
        # Group by severity
        critical = [v for v in vulnerabilities if v.severity == "CRITICAL"]
        high = [v for v in vulnerabilities if v.severity == "HIGH"]
        medium = [v for v in vulnerabilities if v.severity in ("MEDIUM", "MODERATE")]
        low = [v for v in vulnerabilities if v.severity == "LOW"]
        
        # Build response
        response = {
            "status": "vulnerabilities_found",
            "package": package_name,
            "ecosystem": ecosystem,
            "version": version,
            "vulnerabilities_found": len(vulnerabilities),
            "summary": {
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low": len(low)
            },
            "vulnerabilities": []
        }
        
        # Add vulnerability details
        for vuln in vulnerabilities:
            vuln_data = {
                "cve_id": vuln.cve_id,
                "severity": vuln.severity,
                "cvss_score": vuln.cvss_score,
                "description": vuln.description[:500] + "..." if len(vuln.description) > 500 else vuln.description,
                "affected_versions": vuln.affected_versions,
                "patched_versions": vuln.patched_versions,
                "published_date": vuln.published_date,
                "references": vuln.references[:3]  # Limit to 3 references
            }
            response["vulnerabilities"].append(vuln_data)
        
        # Add remediation
        if critical or high:
            response["recommendation"] = "⚠️ CRITICAL/HIGH severity vulnerabilities found. Upgrade immediately to a patched version."
            response["urgency"] = "IMMEDIATE"
        elif medium:
            response["recommendation"] = "Medium severity vulnerabilities found. Plan upgrade in next maintenance window."
            response["urgency"] = "HIGH"
        else:
            response["recommendation"] = "Low severity vulnerabilities found. Consider upgrading when convenient."
            response["urgency"] = "MEDIUM"
        
        # FedRAMP compliance note
        if critical or high:
            response["fedramp_compliance"] = {
                "requirement": "KSI-SVC-08 (Secure Dependencies), KSI-TPR-03 (Supply Chain Security)",
                "status": "NON_COMPLIANT",
                "note": "FedRAMP 20x requires remediation of HIGH/CRITICAL vulnerabilities within 30 days of disclosure.",
                "action": "Document vulnerability in POA&M and track remediation timeline."
            }
        else:
            response["fedramp_compliance"] = {
                "requirement": "KSI-SVC-08 (Secure Dependencies)",
                "status": "COMPLIANT",
                "note": "Continue monitoring for new vulnerabilities. Maintain inventory of dependencies."
            }
        
        return json.dumps(response, indent=2)
    
    except Exception as e:
        return json.dumps({
            "status": "error",
            "package": package_name,
            "ecosystem": ecosystem,
            "error": str(e),
            "recommendation": "Check package name spelling and ecosystem. Verify GitHub API is accessible."
        }, indent=2)


async def scan_dependency_file_impl(
    file_content: str,
    file_type: str,
    github_token: Optional[str] = None
) -> str:
    """
    Scan a dependency file for vulnerable packages.
    
    Supports:
    - NuGet: packages.config, *.csproj, Directory.Packages.props
    - npm: package.json, package-lock.json
    - Python: requirements.txt, Pipfile, pyproject.toml
    - Maven: pom.xml
    
    Args:
        file_content: Content of dependency file
        file_type: File type ("csproj", "packages.config", "package.json", "requirements.txt", "pom.xml")
        github_token: GitHub PAT for higher rate limits (optional)
    
    Returns:
        JSON string with scan results for all packages
    """
    fetcher = CVEFetcher(github_token=github_token)
    
    # Parse dependencies based on file type
    packages = []
    
    try:
        if file_type in ("csproj", "packages.config", "Directory.Packages.props"):
            packages = _parse_nuget_deps(file_content)
        elif file_type in ("package.json", "package-lock.json"):
            packages = _parse_npm_deps(file_content)
        elif file_type in ("requirements.txt", "Pipfile", "pyproject.toml"):
            packages = _parse_python_deps(file_content, file_type)
        elif file_type == "pom.xml":
            packages = _parse_maven_deps(file_content)
        else:
            return json.dumps({
                "status": "error",
                "error": f"Unsupported file type: {file_type}",
                "supported_types": ["csproj", "packages.config", "package.json", "requirements.txt", "pom.xml"]
            }, indent=2)
    except Exception as e:
        return json.dumps({
            "status": "error",
            "error": f"Failed to parse dependency file: {str(e)}"
        }, indent=2)
    
    if not packages:
        return json.dumps({
            "status": "success",
            "packages_scanned": 0,
            "message": "No dependencies found in file"
        }, indent=2)
    
    # Scan each package
    results = []
    total_vulns = 0
    critical_count = 0
    high_count = 0
    
    for pkg_name, pkg_version, ecosystem in packages:
        try:
            vulns = fetcher.get_package_vulnerabilities(pkg_name, ecosystem, pkg_version)
            
            if vulns:
                total_vulns += len(vulns)
                for v in vulns:
                    if v.severity == "CRITICAL":
                        critical_count += 1
                    elif v.severity == "HIGH":
                        high_count += 1
                
                results.append({
                    "package": pkg_name,
                    "version": pkg_version,
                    "ecosystem": ecosystem,
                    "vulnerabilities": len(vulns),
                    "highest_severity": max(v.severity for v in vulns),
                    "cve_ids": [v.cve_id for v in vulns]
                })
        except Exception as e:
            results.append({
                "package": pkg_name,
                "version": pkg_version,
                "ecosystem": ecosystem,
                "error": str(e)
            })
    
    response = {
        "status": "scan_complete",
        "file_type": file_type,
        "packages_scanned": len(packages),
        "vulnerable_packages": len(results),
        "total_vulnerabilities": total_vulns,
        "summary": {
            "critical": critical_count,
            "high": high_count
        },
        "vulnerable_packages_details": results
    }
    
    # Add recommendations
    if critical_count > 0:
        response["recommendation"] = f"🚨 {critical_count} CRITICAL vulnerabilities found. Immediate action required."
        response["urgency"] = "IMMEDIATE"
    elif high_count > 0:
        response["recommendation"] = f"⚠️ {high_count} HIGH vulnerabilities found. Upgrade within 30 days per FedRAMP 20x."
        response["urgency"] = "HIGH"
    elif total_vulns > 0:
        response["recommendation"] = f"{total_vulns} vulnerabilities found. Review and plan upgrades."
        response["urgency"] = "MEDIUM"
    else:
        response["recommendation"] = "✅ No vulnerabilities found in scanned dependencies."
        response["urgency"] = "NONE"
    
    return json.dumps(response, indent=2)


# Helper functions for parsing dependency files

import re
import xml.etree.ElementTree as ET


def _parse_nuget_deps(content: str) -> List[tuple]:
    """Parse NuGet dependencies from csproj or packages.config."""
    packages = []
    
    try:
        root = ET.fromstring(content)
        
        # Find PackageReference elements
        for pkg in root.findall(".//PackageReference"):
            name = pkg.get("Include")
            version = pkg.get("Version")
            if name and version:
                packages.append((name, version, "nuget"))
        
        # Find package elements (packages.config format)
        for pkg in root.findall(".//package"):
            name = pkg.get("id")
            version = pkg.get("version")
            if name and version:
                packages.append((name, version, "nuget"))
    except:
        # Fallback to regex parsing
        pattern = r'<PackageReference\s+Include="([^"]+)"\s+Version="([^"]+)"'
        matches = re.findall(pattern, content)
        for name, version in matches:
            packages.append((name, version, "nuget"))
    
    return packages


def _parse_npm_deps(content: str) -> List[tuple]:
    """Parse npm dependencies from package.json."""
    packages = []
    
    try:
        data = json.loads(content)
        
        # Get dependencies and devDependencies
        for dep_type in ("dependencies", "devDependencies"):
            deps = data.get(dep_type, {})
            for name, version in deps.items():
                # Remove version prefix (^, ~, etc.)
                clean_version = re.sub(r'^[\^~>=<]+', '', version)
                packages.append((name, clean_version, "npm"))
    except:
        pass
    
    return packages


def _parse_python_deps(content: str, file_type: str) -> List[tuple]:
    """Parse Python dependencies from requirements.txt or pyproject.toml."""
    packages = []
    
    if file_type == "requirements.txt":
        # Parse requirements.txt format
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Extract package name and version
            match = re.match(r'^([a-zA-Z0-9_-]+)([>=<]+)([0-9.]+)', line)
            if match:
                name, _, version = match.groups()
                packages.append((name, version, "pypi"))
    
    elif file_type == "pyproject.toml":
        # Parse pyproject.toml format (simplified)
        pattern = r'([a-zA-Z0-9_-]+)\s*=\s*"[\^~>=<]*([0-9.]+)"'
        matches = re.findall(pattern, content)
        for name, version in matches:
            packages.append((name, version, "pypi"))
    
    return packages


def _parse_maven_deps(content: str) -> List[tuple]:
    """Parse Maven dependencies from pom.xml."""
    packages = []
    
    try:
        root = ET.fromstring(content)
        
        # Find dependency elements
        for dep in root.findall(".//{http://maven.apache.org/POM/4.0.0}dependency"):
            group_id = dep.find("{http://maven.apache.org/POM/4.0.0}groupId")
            artifact_id = dep.find("{http://maven.apache.org/POM/4.0.0}artifactId")
            version = dep.find("{http://maven.apache.org/POM/4.0.0}version")
            
            if group_id is not None and artifact_id is not None and version is not None:
                name = f"{group_id.text}:{artifact_id.text}"
                packages.append((name, version.text, "maven"))
    except:
        pass
    
    return packages
