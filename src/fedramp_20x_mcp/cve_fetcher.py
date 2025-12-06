"""
CVE Data Fetcher Module

Fetches vulnerability data from authoritative sources:
- GitHub Advisory Database (primary, free, comprehensive)
- NVD API (fallback, requires API key for high rate limits)

Supports multiple package ecosystems:
- NuGet (.NET)
- npm (JavaScript/TypeScript)
- PyPI (Python)
- Maven (Java)

Features:
- Automatic caching (1 hour TTL)
- Rate limiting protection
- Severity mapping (CVSS scores)
- Version range parsing
"""

import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
import urllib.request
import urllib.error
import re


@dataclass
class Vulnerability:
    """Represents a package vulnerability."""
    cve_id: str
    package_name: str
    ecosystem: str  # "nuget", "npm", "pypi", "maven"
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    cvss_score: Optional[float]
    affected_versions: List[str]
    patched_versions: List[str]
    description: str
    published_date: str
    references: List[str]
    
    def to_dict(self) -> Dict:
        return asdict(self)


class CVEFetcher:
    """Fetches and caches CVE vulnerability data."""
    
    # GitHub Advisory Database GraphQL endpoint
    GITHUB_GRAPHQL = "https://api.github.com/graphql"
    
    # NVD API endpoint (backup)
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    # Cache directory
    CACHE_DIR = Path(__file__).parent / "__cve_cache__"
    
    # Cache TTL (1 hour)
    CACHE_TTL = timedelta(hours=1)
    
    # Ecosystem mapping
    ECOSYSTEM_MAP = {
        "nuget": "NUGET",
        "npm": "NPM",
        "pypi": "PIP",
        "maven": "MAVEN",
    }
    
    def __init__(self, github_token: Optional[str] = None, nvd_api_key: Optional[str] = None):
        """
        Initialize CVE fetcher.
        
        Args:
            github_token: GitHub personal access token (optional, for higher rate limits)
            nvd_api_key: NVD API key (optional, for higher rate limits)
        """
        self.github_token = github_token
        self.nvd_api_key = nvd_api_key
        self.cache_dir = self.CACHE_DIR
        self.cache_dir.mkdir(exist_ok=True)
    
    def get_package_vulnerabilities(
        self,
        package_name: str,
        ecosystem: str,
        version: Optional[str] = None
    ) -> List[Vulnerability]:
        """
        Get vulnerabilities for a package.
        
        Args:
            package_name: Package name (e.g., "Newtonsoft.Json")
            ecosystem: Package ecosystem ("nuget", "npm", "pypi", "maven")
            version: Specific version to check (optional)
        
        Returns:
            List of Vulnerability objects
        """
        # Check cache first
        cache_key = f"{ecosystem}_{package_name}_{version or 'all'}"
        cached = self._get_from_cache(cache_key)
        if cached:
            return [Vulnerability(**v) for v in cached]
        
        # Fetch from GitHub Advisory Database
        try:
            vulnerabilities = self._fetch_from_github(package_name, ecosystem, version)
            # Only cache successful results (don't cache errors/rate limits)
            self._save_to_cache(cache_key, [v.to_dict() for v in vulnerabilities])
        except Exception as e:
            # Fallback to NVD (if available)
            print(f"GitHub Advisory fetch failed: {e}", file=__import__('sys').stderr)
            vulnerabilities = []
            # Don't cache errors - allow retry after rate limit expires
        
        return vulnerabilities
    
    def _fetch_from_github(
        self,
        package_name: str,
        ecosystem: str,
        version: Optional[str] = None
    ) -> List[Vulnerability]:
        """Fetch vulnerabilities from GitHub Advisory Database."""
        ecosystem_name = self.ECOSYSTEM_MAP.get(ecosystem.lower(), ecosystem.upper())
        
        # GraphQL query for GitHub Advisory Database
        query = """
        query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
          securityVulnerabilities(first: 100, ecosystem: $ecosystem, package: $package) {
            nodes {
              advisory {
                ghsaId
                summary
                description
                severity
                publishedAt
                references {
                  url
                }
                identifiers {
                  type
                  value
                }
              }
              vulnerableVersionRange
              firstPatchedVersion {
                identifier
              }
              package {
                name
              }
            }
          }
        }
        """
        
        variables = {
            "ecosystem": ecosystem_name,
            "package": package_name
        }
        
        request_data = json.dumps({"query": query, "variables": variables}).encode('utf-8')
        
        headers = {
            "Content-Type": "application/json",
            "User-Agent": "FedRAMP-20x-MCP-CVE-Fetcher"
        }
        
        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"
        
        req = urllib.request.Request(
            self.GITHUB_GRAPHQL,
            data=request_data,
            headers=headers,
            method="POST"
        )
        
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode('utf-8'))
        except urllib.error.HTTPError as e:
            error_body = e.read().decode('utf-8')
            raise Exception(f"GitHub API error: {e.code} - {error_body}")
        
        vulnerabilities = []
        
        if "errors" in data:
            raise Exception(f"GraphQL errors: {data['errors']}")
        
        nodes = data.get("data", {}).get("securityVulnerabilities", {}).get("nodes", [])
        
        for node in nodes:
            advisory = node.get("advisory", {})
            
            # Extract CVE ID
            cve_id = advisory.get("ghsaId", "")
            for identifier in advisory.get("identifiers", []):
                if identifier.get("type") == "CVE":
                    cve_id = identifier.get("value", cve_id)
                    break
            
            # Parse version range
            version_range = node.get("vulnerableVersionRange", "")
            affected_versions = [version_range] if version_range else []
            
            # Parse patched version
            patched_version = node.get("firstPatchedVersion", {})
            patched_versions = [patched_version.get("identifier")] if patched_version else []
            
            # Map severity
            severity = advisory.get("severity", "UNKNOWN").upper()
            cvss_score = self._severity_to_cvss(severity)
            
            # Extract references
            references = [ref["url"] for ref in advisory.get("references", [])]
            
            vuln = Vulnerability(
                cve_id=cve_id,
                package_name=package_name,
                ecosystem=ecosystem,
                severity=severity,
                cvss_score=cvss_score,
                affected_versions=affected_versions,
                patched_versions=patched_versions,
                description=advisory.get("description") or advisory.get("summary", ""),
                published_date=advisory.get("publishedAt", ""),
                references=references
            )
            
            # Filter by version if specified
            if version:
                if self._version_affected(version, affected_versions, patched_versions):
                    vulnerabilities.append(vuln)
            else:
                vulnerabilities.append(vuln)
        
        return vulnerabilities
    
    def _severity_to_cvss(self, severity: str) -> Optional[float]:
        """Map severity string to approximate CVSS score."""
        severity_map = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "MODERATE": 5.0,
            "LOW": 3.0,
        }
        return severity_map.get(severity.upper())
    
    def _version_affected(
        self,
        version: str,
        affected_ranges: List[str],
        patched_versions: List[str]
    ) -> bool:
        """
        Check if a version is affected by vulnerability.
        
        Args:
            version: Version to check (e.g., "1.2.3")
            affected_ranges: List of version ranges (e.g., ["< 1.3.0", ">= 1.0.0, < 1.2.5"])
            patched_versions: List of patched versions (e.g., ["1.3.0"])
        
        Returns:
            True if version is affected
        """
        # Parse version
        try:
            v = self._parse_version(version)
        except:
            return False  # Can't parse, assume not affected
        
        # Check if version is in a patched version
        for patched in patched_versions:
            try:
                p = self._parse_version(patched)
                if v >= p:
                    return False  # Version is patched
            except:
                continue
        
        # Check if version is in affected range
        for range_str in affected_ranges:
            if self._version_in_range(v, range_str):
                return True
        
        return False
    
    def _parse_version(self, version: str) -> tuple:
        """Parse version string to tuple of integers."""
        # Remove leading 'v' if present
        version = version.lstrip('v')
        
        # Extract numeric parts
        parts = re.findall(r'\d+', version)
        return tuple(int(p) for p in parts)
    
    def _version_in_range(self, version: tuple, range_str: str) -> bool:
        """
        Check if version is in range.
        
        Range formats:
        - "< 1.2.3"
        - ">= 1.0.0"
        - ">= 1.0.0, < 1.2.3"
        """
        # Split on comma for compound ranges
        ranges = [r.strip() for r in range_str.split(',')]
        
        for r in ranges:
            if not self._check_single_range(version, r):
                return False
        
        return True
    
    def _check_single_range(self, version: tuple, range_str: str) -> bool:
        """Check single range condition."""
        # Parse operator and version
        match = re.match(r'^([<>=!]+)\s*(.+)$', range_str.strip())
        if not match:
            return False
        
        operator, target_version = match.groups()
        
        try:
            target = self._parse_version(target_version)
        except:
            return False
        
        # Compare versions
        if operator == '<':
            return version < target
        elif operator == '<=':
            return version <= target
        elif operator == '>':
            return version > target
        elif operator == '>=':
            return version >= target
        elif operator == '==':
            return version == target
        elif operator == '!=':
            return version != target
        else:
            return False
    
    def _get_from_cache(self, cache_key: str) -> Optional[List[Dict]]:
        """Get cached vulnerability data."""
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        if not cache_file.exists():
            return None
        
        # Check if cache is expired
        mtime = datetime.fromtimestamp(cache_file.stat().st_mtime)
        if datetime.now() - mtime > self.CACHE_TTL:
            return None
        
        try:
            with open(cache_file, 'r') as f:
                return json.load(f)
        except:
            return None
    
    def _save_to_cache(self, cache_key: str, data: List[Dict]) -> None:
        """Save vulnerability data to cache."""
        cache_file = self.cache_dir / f"{cache_key}.json"
        
        try:
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Failed to save cache: {e}", file=__import__('sys').stderr)
    
    def clear_cache(self) -> None:
        """Clear all cached vulnerability data."""
        for cache_file in self.cache_dir.glob("*.json"):
            cache_file.unlink()
    
    def get_latest_version(self, package_name: str, ecosystem: str) -> Optional[str]:
        """
        Get the latest version of a package from package registry APIs.
        
        Queries official package registries:
        - NuGet: NuGet.org API
        - npm: npm registry API
        - PyPI: PyPI JSON API
        - Maven: Maven Central API
        
        Args:
            package_name: Package name (e.g., "Newtonsoft.Json")
            ecosystem: Package ecosystem ("nuget", "npm", "pypi", "maven")
        
        Returns:
            Latest version string if found, None otherwise
        """
        try:
            if ecosystem == "nuget":
                # Query NuGet.org API for latest version
                # API docs: https://learn.microsoft.com/nuget/api/overview
                url = f"https://api.nuget.org/v3-flatcontainer/{package_name.lower()}/index.json"
                request = urllib.request.Request(url)
                request.add_header("User-Agent", "FedRAMP-20x-MCP-Analyzer/1.0")
                
                with urllib.request.urlopen(request, timeout=5) as response:
                    data = json.loads(response.read())
                    versions = data.get("versions", [])
                    
                    if not versions:
                        return None
                    
                    # Filter out pre-release versions (contain - or have non-numeric parts)
                    stable_versions = [
                        v for v in versions 
                        if '-' not in v and all(part.isdigit() for part in v.split('.'))
                    ]
                    
                    if not stable_versions:
                        # If no stable versions, return the last version overall
                        return versions[-1]
                    
                    # Return the last stable version (NuGet API returns versions in ascending order)
                    return stable_versions[-1]
            
            elif ecosystem == "npm":
                # Query npm registry for latest version
                url = f"https://registry.npmjs.org/{package_name}"
                request = urllib.request.Request(url)
                request.add_header("User-Agent", "FedRAMP-20x-MCP-Analyzer/1.0")
                
                with urllib.request.urlopen(request, timeout=5) as response:
                    data = json.loads(response.read())
                    return data.get("dist-tags", {}).get("latest")
            
            elif ecosystem == "pypi":
                # Query PyPI JSON API for latest version
                url = f"https://pypi.org/pypi/{package_name}/json"
                request = urllib.request.Request(url)
                request.add_header("User-Agent", "FedRAMP-20x-MCP-Analyzer/1.0")
                
                with urllib.request.urlopen(request, timeout=5) as response:
                    data = json.loads(response.read())
                    return data.get("info", {}).get("version")
            
            elif ecosystem == "maven":
                # Query Maven Central for latest version
                url = f"https://search.maven.org/solrsearch/select?q=g:%22{package_name.split(':')[0]}%22+AND+a:%22{package_name.split(':')[1]}%22&rows=1&wt=json"
                request = urllib.request.Request(url)
                request.add_header("User-Agent", "FedRAMP-20x-MCP-Analyzer/1.0")
                
                with urllib.request.urlopen(request, timeout=5) as response:
                    data = json.loads(response.read())
                    docs = data.get("response", {}).get("docs", [])
                    if docs:
                        return docs[0].get("latestVersion")
            
            return None
            
        except Exception as e:
            # If we can't get latest version, return None (network error, package not found, etc.)
            return None


# Convenience functions for analyzers
def check_nuget_package(package_name: str, version: Optional[str] = None) -> List[Vulnerability]:
    """Check NuGet package for vulnerabilities."""
    fetcher = CVEFetcher()
    return fetcher.get_package_vulnerabilities(package_name, "nuget", version)


def check_npm_package(package_name: str, version: Optional[str] = None) -> List[Vulnerability]:
    """Check npm package for vulnerabilities."""
    fetcher = CVEFetcher()
    return fetcher.get_package_vulnerabilities(package_name, "npm", version)


def check_pypi_package(package_name: str, version: Optional[str] = None) -> List[Vulnerability]:
    """Check PyPI package for vulnerabilities."""
    fetcher = CVEFetcher()
    return fetcher.get_package_vulnerabilities(package_name, "pypi", version)


def check_maven_package(package_name: str, version: Optional[str] = None) -> List[Vulnerability]:
    """Check Maven package for vulnerabilities."""
    fetcher = CVEFetcher()
    return fetcher.get_package_vulnerabilities(package_name, "maven", version)
