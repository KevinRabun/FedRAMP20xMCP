"""
FedRAMP 20x MCP Server

This module implements an MCP server that provides access to FedRAMP 20x
security requirements and controls.
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

# Initialize FastMCP server
mcp = FastMCP("FedRAMP 20x Requirements Server")

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
    Determine the required remediation timeframes for vulnerabilities based on 
    severity and FedRAMP impact level.
    
    Use this prompt to:
    - Understand VDR timeframe requirements
    - Plan vulnerability remediation
    - Ensure compliance with FedRAMP deadlines
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
    - Conduct quarterly reviews per FRR-CCM-QR requirements
    - Ensure all required activities are completed
    - Prepare quarterly deliverables
    """
    from .prompts import load_prompt
    return load_prompt('quarterly_review_checklist')


@mcp.prompt()
async def api_design_guide() -> str:
    """
    Guide for designing your Authorization Data Sharing API per FRR-ADS requirements.
    
    Use this prompt to:
    - Design compliant data sharing APIs
    - Implement OSCAL format support
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
    Generate OSCAL/documentation templates based on FedRAMP 20x requirements.
    
    Use this prompt to:
    - Create documentation structure for ATO package
    - Generate OSCAL format templates
    - Understand required documentation sections
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
    🚨 CRITICAL: MANDATORY FedRAMP 20x compliance values - NOT suggestions. 🚨
    
    BEFORE generating ANY code, VERIFY these NON-NEGOTIABLE requirements:
    - Log Analytics retention: EXACTLY 730 days (NOT 90/180/365)
    - Customer-Managed Keys: MANDATORY for Storage, SQL, Cosmos DB, Disks
    - Key Vault SKU: EXACTLY 'premium' (NOT 'standard')
    - Public access: DISABLED with Private Endpoints
    - Diagnostic settings: CONFIGURED for ALL resources
    
    ❌ FORBIDDEN: "I'll document it for post-deployment" - Implement compliance NOW.
    ❌ FORBIDDEN: "90 days is common in Azure" - FedRAMP requires 730 days.
    ❌ FORBIDDEN: "Basic tier is sufficient" - Premium SKU required for FIPS 140-2.
    
    ✅ REQUIRED: Declare compliance BEFORE generating code. If you cannot verify
    all requirements, query the KSI tools instead of guessing.
    
    Comprehensive guide for implementing FedRAMP 20x KSI automation using Microsoft, Azure, and M365 capabilities.
    
    Use this prompt to:
    - Map each KSI to specific Microsoft/Azure/M365 services
    - Automate evidence collection for all 72 KSIs
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
    - Prepare for 3PAO assessment
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
    - Review code for FRR compliance (VDR, ADS, RSC, UCM, CCM, SCN, MAS, ICP, FSI, PVA)
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
    - Conduct family-specific assessments (VDR, ADS, RSC, UCM, CCM, SCN, MAS, ICP, FSI, PVA)
    - Understand all 199 FRR requirements across 10 families
    - Plan evidence collection for FRR compliance
    - Validate implementations using FRR analysis tools
    """
    from .prompts import load_prompt
    return load_prompt('frr_family_assessment')


@mcp.prompt()
async def frr_implementation_roadmap() -> str:
    """
    Strategic roadmap for implementing all 199 FedRAMP Requirements (FRR) across your system.
    
    Use this prompt to:
    - Plan phased FRR implementation (4 phases over 16 weeks)
    - Prioritize high-impact FRR families (VDR, ADS, RSC, UCM first)
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
