"""
Application Context for reducing false positives in compliance analysis.

Provides a capability-based model for describing what an application does,
so that analyzers can skip requirements that don't apply to the application's
architecture. For example, a CLI tool that reads YAML files has no need for
MFA, RBAC, HSTS, or database sanitization findings.

Usage:
    # Predefined profiles
    ctx = ApplicationContext.cli_tool()
    
    # Custom context
    ctx = ApplicationContext(
        has_authentication=False,
        has_http_server=False,
        has_database=True,
        has_pii=False,
        has_network_calls=False,
    )
    
    # From string descriptor
    ctx = ApplicationContext.from_string("cli-tool")
"""

from dataclasses import dataclass, field
from typing import Optional, Set, Dict, Any


# Maps capabilities to the pattern tag families they gate.
# If a pattern has one of these tags and the corresponding capability is False,
# the pattern is suppressed.
CAPABILITY_TAG_MAP: Dict[str, Set[str]] = {
    "has_authentication": {
        "mfa", "fido2", "authentication", "rbac", "access_control",
        "conditional-access", "account_lockout", "session", "sso",
        "identity", "authorization", "oauth", "oidc", "saml",
        "password", "credential",
    },
    "has_http_server": {
        "hsts", "tls", "https", "cors", "csp", "security_headers",
        "http", "web", "ssl", "certificate", "x-frame-options",
        "content-security-policy", "strict-transport-security",
    },
    "has_database": {
        "database", "sql", "nosql", "data_deletion", "data_sanitization",
        "data_retention", "backup", "encryption_at_rest", "storage",
        "cosmos", "postgresql", "mysql", "redis",
    },
    "has_pii": {
        "pii", "personal_data", "data_protection", "gdpr", "privacy",
        "data_classification", "data_masking", "anonymization",
        "pseudonymization",
    },
    "has_network_calls": {
        "network", "cross_border", "api_gateway", "firewall",
        "nsg", "vnet", "dns", "load_balancer", "waf",
        "egress", "ingress", "proxy",
    },
    "has_secrets": {
        "secrets", "key_vault", "key_management", "cmk",
        "secret_rotation", "certificate_management",
    },
    "has_containers": {
        "container", "container_security", "kubernetes", "k8s",
        "docker", "aks", "aci", "acr",
    },
    "has_ci_cd": {
        "ci-cd", "pipeline", "deployment", "release",
        "automated_testing", "code-review", "sast", "dast",
    },
}

# Maps capability names to the KSI/FRR families they gate.
# If a capability is False, findings from these families may be suppressed
# when the pattern doesn't have more specific tags.
CAPABILITY_FAMILY_MAP: Dict[str, Set[str]] = {
    "has_authentication": {"IAM"},
    "has_http_server": {"SVC"},     # Service Configuration (HSTS, TLS, headers)
    "has_database": set(),          # No full family suppression — too broad
    "has_pii": set(),               # No full family suppression
    "has_network_calls": {"CNA"},   # Cloud Native Architecture (network)
    "has_secrets": set(),           # Secrets can appear anywhere
    "has_containers": set(),
    "has_ci_cd": set(),
}


@dataclass
class ApplicationContext:
    """
    Describes the capabilities of an application being analyzed.
    
    Set capabilities to False to suppress findings that require those
    capabilities. When a capability is None, no filtering is applied
    for that capability (default behavior — assume everything applies).
    
    Attributes:
        has_authentication: App has user accounts/auth (MFA, RBAC, IAM)
        has_http_server: App exposes HTTP endpoints (HSTS, TLS, headers)
        has_database: App uses persistent storage (data deletion, backup)
        has_pii: App processes PII/personal data (data protection)
        has_network_calls: App makes outbound network calls (cross-border)
        has_secrets: App manages secrets/keys/certificates
        has_containers: App uses containers (K8s, Docker)
        has_ci_cd: App has CI/CD pipelines
        description: Free-text description of the application
        excluded_families: Explicitly excluded requirement families
        excluded_tags: Explicitly excluded tags (findings with these tags are suppressed)
    """
    has_authentication: Optional[bool] = None
    has_http_server: Optional[bool] = None
    has_database: Optional[bool] = None
    has_pii: Optional[bool] = None
    has_network_calls: Optional[bool] = None
    has_secrets: Optional[bool] = None
    has_containers: Optional[bool] = None
    has_ci_cd: Optional[bool] = None
    description: Optional[str] = None
    excluded_families: Set[str] = field(default_factory=set)
    excluded_tags: Set[str] = field(default_factory=set)

    def get_suppressed_tags(self) -> Set[str]:
        """
        Get the set of tags that should be suppressed based on disabled capabilities.
        
        Returns:
            Set of tag strings that should cause findings to be filtered out
        """
        suppressed = set(self.excluded_tags)
        
        for capability_name, tags in CAPABILITY_TAG_MAP.items():
            capability_value = getattr(self, capability_name, None)
            if capability_value is False:  # Explicitly disabled (None = unknown = allow)
                suppressed.update(tags)
        
        return suppressed

    def get_suppressed_families(self) -> Set[str]:
        """
        Get the set of requirement families that should be fully suppressed.
        
        Returns:
            Set of family codes (e.g., "IAM", "CNA") to suppress entirely
        """
        suppressed = set(self.excluded_families)
        
        for capability_name, families in CAPABILITY_FAMILY_MAP.items():
            capability_value = getattr(self, capability_name, None)
            if capability_value is False:
                suppressed.update(families)
        
        return suppressed

    def should_include_pattern(self, pattern_tags: list, pattern_family: str) -> bool:
        """
        Determine if a pattern should be included based on this context.
        
        A pattern is excluded if:
        1. Its family is in the suppressed families set, OR
        2. ANY of its tags overlap with the suppressed tags set
        
        Args:
            pattern_tags: List of tags on the pattern
            pattern_family: The pattern's family code (e.g., "IAM", "SVC")
            
        Returns:
            True if the pattern should be included, False if it should be filtered out
        """
        # Check family-level suppression
        suppressed_families = self.get_suppressed_families()
        if pattern_family.upper() in suppressed_families:
            return False
        
        # Check tag-level suppression
        suppressed_tags = self.get_suppressed_tags()
        if suppressed_tags and pattern_tags:
            # Normalize tags for comparison (handle hyphens, spaces, underscores)
            normalized_pattern_tags = {str(t).lower().replace(" ", "_").replace("-", "_") for t in pattern_tags}
            normalized_suppressed = {str(t).lower().replace(" ", "_").replace("-", "_") for t in suppressed_tags}
            if normalized_pattern_tags & normalized_suppressed:
                return False
        
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Serialize context to dict for JSON output."""
        return {
            "has_authentication": self.has_authentication,
            "has_http_server": self.has_http_server,
            "has_database": self.has_database,
            "has_pii": self.has_pii,
            "has_network_calls": self.has_network_calls,
            "has_secrets": self.has_secrets,
            "has_containers": self.has_containers,
            "has_ci_cd": self.has_ci_cd,
            "description": self.description,
            "excluded_families": sorted(self.excluded_families) if self.excluded_families else [],
            "excluded_tags": sorted(self.excluded_tags) if self.excluded_tags else [],
            "suppressed_tags": sorted(self.get_suppressed_tags()),
            "suppressed_families": sorted(self.get_suppressed_families()),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApplicationContext":
        """Create ApplicationContext from a dictionary."""
        return cls(
            has_authentication=data.get("has_authentication"),
            has_http_server=data.get("has_http_server"),
            has_database=data.get("has_database"),
            has_pii=data.get("has_pii"),
            has_network_calls=data.get("has_network_calls"),
            has_secrets=data.get("has_secrets"),
            has_containers=data.get("has_containers"),
            has_ci_cd=data.get("has_ci_cd"),
            description=data.get("description"),
            excluded_families=set(data.get("excluded_families", [])),
            excluded_tags=set(data.get("excluded_tags", [])),
        )

    @classmethod
    def from_string(cls, profile: str) -> "ApplicationContext":
        """
        Create ApplicationContext from a predefined profile name.
        
        Supported profiles:
            - "cli-tool" / "cli": Local CLI tool, no server/auth/database
            - "mcp-server": MCP server using stdio transport
            - "web-app" / "web": Web application with full stack
            - "api-service" / "api": REST/GraphQL API service
            - "iac-only" / "infrastructure": Infrastructure-as-Code only
            - "library" / "sdk": Shared library/SDK
            - "batch-job" / "worker": Background processing job
            - "full": All capabilities enabled (default analysis behavior)
            
        Args:
            profile: Profile name string
            
        Returns:
            ApplicationContext with appropriate capability settings
        """
        profile_lower = profile.lower().strip()
        profiles = {
            "cli-tool": cls.cli_tool,
            "cli": cls.cli_tool,
            "mcp-server": cls.mcp_server,
            "mcp": cls.mcp_server,
            "web-app": cls.web_app,
            "web": cls.web_app,
            "api-service": cls.api_service,
            "api": cls.api_service,
            "iac-only": cls.iac_only,
            "infrastructure": cls.iac_only,
            "library": cls.library,
            "sdk": cls.library,
            "batch-job": cls.batch_job,
            "worker": cls.batch_job,
            "full": cls.full,
        }
        
        factory = profiles.get(profile_lower)
        if factory:
            return factory()
        
        # Unknown profile — return full context (no filtering)
        return cls.full()

    # ---- Predefined profiles ----

    @classmethod
    def cli_tool(cls) -> "ApplicationContext":
        """Local CLI tool — no server, no auth, no database, no PII, no network."""
        return cls(
            has_authentication=False,
            has_http_server=False,
            has_database=False,
            has_pii=False,
            has_network_calls=False,
            has_secrets=False,
            has_containers=False,
            has_ci_cd=False,
            description="Local CLI tool (no server, no auth, no persistent storage)",
        )

    @classmethod
    def mcp_server(cls) -> "ApplicationContext":
        """MCP server using stdio — no HTTP server, no auth, no PII typically."""
        return cls(
            has_authentication=False,
            has_http_server=False,
            has_database=False,
            has_pii=False,
            has_network_calls=False,
            has_secrets=False,
            has_containers=False,
            has_ci_cd=False,
            description="MCP server using stdio transport (no HTTP, no auth)",
        )

    @classmethod
    def web_app(cls) -> "ApplicationContext":
        """Full web application — all capabilities enabled."""
        return cls(
            has_authentication=True,
            has_http_server=True,
            has_database=True,
            has_pii=True,
            has_network_calls=True,
            has_secrets=True,
            has_containers=None,  # Unknown
            has_ci_cd=None,       # Unknown
            description="Web application with authentication, database, HTTP server",
        )

    @classmethod
    def api_service(cls) -> "ApplicationContext":
        """REST/GraphQL API service."""
        return cls(
            has_authentication=True,
            has_http_server=True,
            has_database=True,
            has_pii=None,          # Unknown
            has_network_calls=True,
            has_secrets=True,
            has_containers=None,
            has_ci_cd=None,
            description="API service with authentication and HTTP endpoints",
        )

    @classmethod
    def iac_only(cls) -> "ApplicationContext":
        """Infrastructure-as-Code templates only."""
        return cls(
            has_authentication=None,  # IaC may define auth infra
            has_http_server=None,     # IaC may define HTTP infra
            has_database=None,        # IaC may define databases
            has_pii=False,
            has_network_calls=None,
            has_secrets=True,         # IaC often involves secrets
            has_containers=None,
            has_ci_cd=False,
            description="Infrastructure-as-Code templates (Bicep/Terraform)",
        )

    @classmethod
    def library(cls) -> "ApplicationContext":
        """Shared library / SDK — typically no server, no direct auth."""
        return cls(
            has_authentication=False,
            has_http_server=False,
            has_database=False,
            has_pii=False,
            has_network_calls=False,
            has_secrets=False,
            has_containers=False,
            has_ci_cd=False,
            description="Shared library or SDK",
        )

    @classmethod
    def batch_job(cls) -> "ApplicationContext":
        """Background processing / batch job."""
        return cls(
            has_authentication=False,
            has_http_server=False,
            has_database=True,
            has_pii=None,
            has_network_calls=None,
            has_secrets=True,
            has_containers=None,
            has_ci_cd=None,
            description="Background batch processing job",
        )

    @classmethod
    def full(cls) -> "ApplicationContext":
        """Full context — all capabilities assumed present (no filtering)."""
        return cls(
            has_authentication=None,
            has_http_server=None,
            has_database=None,
            has_pii=None,
            has_network_calls=None,
            has_secrets=None,
            has_containers=None,
            has_ci_cd=None,
            description="All capabilities assumed (no filtering applied)",
        )
