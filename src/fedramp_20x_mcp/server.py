"""
FedRAMP 20x MCP Server

This module implements an MCP server that provides access to the FedRAMP
Consolidated Rules for 2026 (CR26): FedRAMP Requirements and Recommendations
(FRR), Key Security Indicators (KSI), FedRAMP Definitions (FRD) and the FedRAMP
parameter values for NIST controls (CTL).
"""

import asyncio
import csv
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from .data_loader import get_data_loader
from .templates import get_infrastructure_template, get_code_template
from .tools import register_tools

# Configure logging to stderr only (MCP requirement)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    stream=sys.stderr,
)

logger = logging.getLogger(__name__)

SERVER_INSTRUCTIONS = """\
FedRAMP 20x Requirements Server, backed by the FedRAMP Consolidated Rules for 2026 (CR26).

Source of truth: the FedRAMP/rules repository (fedramp-consolidated-rules.json) with a bundled
snapshot as offline fallback. Documentation comes from the FedRAMP/2026 repository (content/).
Tool outputs name the rules version in use; use get_control or list_ksi to see it.

What CR26 contains:
- FRR rules grouped into families (for example VDR, VER, SCN, CCM, CDS, SCG, MAS, IEC, AFC, IVV, CMU).
  Each rule has an ID like VDR-CSO-DET, a force (MUST, SHOULD or MAY), who it affects, mapped NIST
  controls and, for some rules, level- or class-specific variants.
- KSI rules in categories (CED, CMT, CNA, IAM, INR, MLA, PIY, RPL, SCR, SVC) with IDs like KSI-IAM-APM.
- FRD definitions, and FedRAMP parameter values for NIST controls (get_control_parameters).

Things to know before answering:
- Legacy IDs (for example KSI-IAM-01 or FRR-VDR-01) are resolved through a crosswalk. The tool says
  which CR26 ID it resolved to, with basis and confidence. Basis "related" means CR26 has no single
  successor, so treat the target as the nearest rule, not a rename.
- Retired families map to successors: ADS to CDS, FSI to AFC, UCM to CMU, PVA to IVV, ICP to IEC,
  RSC to SCG. KSI-TPR became KSI-SCR; KSI-AFR was removed. There is no KSI-VDR family.
- CR26 sets no numeric log retention period and does not require a POA&M, SAR or OSCAL SSP package.
  Vulnerability remediation timeframes (VDR-TFR-PVR) depend on the Potential Agency Impact N-rating
  and internet reachability, not on fixed 7/15/30/90 day severity buckets. Do not state otherwise
  unless a tool result quotes it.
- Code analysis and Azure templates are development-time guardrails, not an assessment or authorization.
"""

# Initialize FastMCP server
mcp = FastMCP("FedRAMP 20x Requirements Server", instructions=SERVER_INSTRUCTIONS)

# Initialize data loader
data_loader = get_data_loader()

# Register all tools
register_tools(mcp, data_loader)


# Add prompts for common compliance workflows
@mcp.prompt()
async def gap_analysis() -> str:
    """
    Guide a FedRAMP gap analysis by helping identify which requirements apply 
    to your system and what evidence you need to provide.
    
    Use this prompt to:
    - Understand which FedRAMP requirements are relevant to your authorization level
    - Identify Key Security Indicators (KSI) you need to track
    - Determine what evidence and documentation is needed
    """
    from .prompts import load_prompt
    return load_prompt('gap_analysis')


@mcp.prompt()
async def ato_package_checklist() -> str:
    """
    Generate a comprehensive checklist for preparing your FedRAMP Authorization 
    to Operate (ATO) package based on FedRAMP 20x requirements.
    
    Use this prompt to:
    - Ensure all required documentation is included
    - Verify compliance with all applicable standards
    - Prepare for assessment and authorization
    """
    from .prompts import load_prompt
    return load_prompt('ato_package_checklist')


@mcp.prompt()
async def significant_change_assessment() -> str:
    """
    Assess whether a planned change to your cloud service offering requires 
    FedRAMP notification and help determine the change classification.
    
    Use this prompt to:
    - Determine if your change is routine, adaptive, or transformative
    - Understand notification requirements
    - Prepare change documentation
    """
    from .prompts import load_prompt
    return load_prompt('significant_change_assessment')


@mcp.prompt()
async def vulnerability_remediation_timeline() -> str:
    """
    Determine the vulnerability mitigation and remediation timeframes in CR26 (VDR-TFR-PVR),
    which depend on the Potential Agency Impact N-rating, internet reachability and
    likely exploitability.

    Use this prompt to:
    - Understand VDR timeframe requirements
    - Plan vulnerability remediation
    - Align remediation with the CR26 timeframes
    """
    from .prompts import load_prompt
    return load_prompt('vulnerability_remediation_timeline')


@mcp.prompt()
async def continuous_monitoring_setup() -> str:
    """
    Set up a FedRAMP-compliant continuous monitoring program with proper 
    reporting and assessment schedules.
    
    Use this prompt to:
    - Understand continuous monitoring requirements
    - Set up reporting schedules
    - Plan assessments and reviews
    """
    from .prompts import load_prompt
    return load_prompt('continuous_monitoring_setup')


@mcp.prompt()
async def authorization_boundary_review() -> str:
    """
    Review and validate your FedRAMP authorization boundary to ensure all 
    required information resources are included.
    
    Use this prompt to:
    - Verify authorization boundary completeness
    - Identify missing components
    - Ensure MAS compliance
    """
    from .prompts import load_prompt
    return load_prompt('authorization_boundary_review')


@mcp.prompt()
async def initial_assessment_roadmap() -> str:
    """
    Step-by-step guide for organizations starting FedRAMP 20x authorization from scratch.
    
    Use this prompt to:
    - Understand the complete FedRAMP 20x authorization process
    - Get a phased implementation roadmap
    - Identify key milestones and dependencies
    """
    from .prompts import load_prompt
    return load_prompt('initial_assessment_roadmap')


@mcp.prompt()
async def quarterly_review_checklist() -> str:
    """
    Structured checklist for FedRAMP 20x Collaborative Continuous Monitoring quarterly reviews.
    
    Use this prompt to:
    - Conduct quarterly reviews per the CCM-QTR rules (Collaborative Continuous Monitoring)
    - Ensure all required activities are completed
    - Prepare quarterly deliverables
    """
    from .prompts import load_prompt
    return load_prompt('quarterly_review_checklist')


@mcp.prompt()
async def api_design_guide() -> str:
    """
    Guide for designing certification data sharing (CDS family, formerly ADS) APIs.

    Use this prompt to:
    - Design human and machine-readable data sharing (CDS-TRC-HMR, CDS-TRC-PAC)
    - Plan agency access management and access logging
    - Set up proper authentication and authorization
    """
    from .prompts import load_prompt
    return load_prompt('api_design_guide')


@mcp.prompt()
async def ksi_implementation_priorities() -> str:
    """
    Help prioritize which Key Security Indicators to implement first based on impact and dependencies.
    
    Use this prompt to:
    - Understand KSI implementation order
    - Identify quick wins vs. long-term investments
    - Plan phased KSI rollout
    """
    from .prompts import load_prompt
    return load_prompt('ksi_implementation_priorities')


@mcp.prompt()
async def vendor_evaluation() -> str:
    """
    Questions to ask vendors and tools to ensure FedRAMP 20x compatibility.
    
    Use this prompt to:
    - Evaluate security tools for FedRAMP 20x compliance
    - Assess third-party service providers
    - Identify gaps in vendor capabilities
    """
    from .prompts import load_prompt
    return load_prompt('vendor_evaluation')


@mcp.prompt()
async def documentation_generator() -> str:
    """
    Generate documentation templates based on FedRAMP 20x requirements.

    Use this prompt to:
    - Create documentation structure for certification materials
    - Draft Secure Configuration Guide (SCG) and notification content
    - Understand which documentation rules apply
    """
    from .prompts import load_prompt
    return load_prompt('documentation_generator')


@mcp.prompt()
async def migration_from_rev5() -> str:
    """
    Detailed migration plan from FedRAMP Rev 5 to FedRAMP 20x.
    
    Use this prompt to:
    - Understand what changes between Rev 5 and 20x
    - Create a transition plan for existing authorizations
    - Identify gaps in current implementation
    """
    from .prompts import load_prompt
    return load_prompt('migration_from_rev5')


@mcp.prompt()
async def azure_ksi_automation() -> str:
    """
    Guide for implementing FedRAMP 20x KSI automation using Microsoft, Azure, and M365 capabilities.

    Azure hardening defaults used by this server's templates (customer-managed keys, Key Vault
    Premium, private endpoints, diagnostic settings) are recommended practices that support the
    KSIs. They are not values mandated by CR26, which defines no numeric log retention period.
    Verify rule text with get_ksi or get_control instead of guessing.

    Use this prompt to:
    - Map each KSI to specific Microsoft/Azure/M365 services
    - Automate evidence collection for every KSI in the loaded CR26 rules
    - Integrate with Microsoft security stack
    - Build automation using PowerShell, Azure CLI, and Graph API
    """
    from .prompts import load_prompt
    return load_prompt('azure_ksi_automation')


@mcp.prompt()
async def audit_preparation() -> str:
    """
    Comprehensive guide for preparing for FedRAMP 20x assessment and audit.
    
    Use this prompt to:
    - Prepare for independent assessment
    - Organize evidence and documentation
    - Understand common audit findings
    - Create testing procedures
    """
    from .prompts import load_prompt
    return load_prompt('audit_preparation')


@mcp.prompt()
async def frr_code_review() -> str:
    """
    Guide for reviewing code against FedRAMP Requirements (FRR) using AST-powered semantic analysis.
    
    Use this prompt to:
    - Review code for FRR compliance (VDR, SCG, CMU, CCM, SCN, MAS, IEC, AFC, CDS, IVV)
    - Integrate FRR checks into pull request workflows
    - Understand FRR findings and remediation strategies
    - Validate vulnerability management, data sharing, and secure configuration
    """
    from .prompts import load_prompt
    return load_prompt('frr_code_review')


@mcp.prompt()
async def frr_family_assessment() -> str:
    """
    Comprehensive guide for assessing compliance against specific FRR families.
    
    Use this prompt to:
    - Conduct family-specific assessments (VDR, SCG, CMU, CCM, SCN, MAS, IEC, AFC, CDS, IVV)
    - Understand the FRR requirements in each CR26 family
    - Plan evidence collection for FRR compliance
    - Validate implementations using FRR analysis tools
    """
    from .prompts import load_prompt
    return load_prompt('frr_family_assessment')


@mcp.prompt()
async def frr_implementation_roadmap() -> str:
    """
    Strategic roadmap for implementing the FedRAMP Requirements (FRR) of CR26 across your system.
    
    Use this prompt to:
    - Plan phased FRR implementation (4 phases over 16 weeks)
    - Prioritize high-impact FRR families (VDR, SCN, CDS, SCG first)
    - Integrate FRR compliance into DevOps workflows
    - Track implementation progress and metrics
    - Combine FRR and KSI implementation strategies
    """
    from .prompts import load_prompt
    return load_prompt('frr_implementation_roadmap')



def main():
    """Run the FedRAMP 20x MCP server."""
    logger.info("Starting FedRAMP 20x MCP Server")
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
