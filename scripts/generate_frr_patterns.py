#!/usr/bin/env python3
"""
FRR Pattern Generator

Creates V2 schema patterns for all 199 FedRAMP Requirements (FRR-*).
FRRs are primarily process-based requirements that focus on documentation,
policies, and procedures rather than code detection.

Usage:
    # Generate all FRR patterns
    python scripts/generate_frr_patterns.py --all
    
    # Generate single family
    python scripts/generate_frr_patterns.py --family ADS
    
    # Dry run
    python scripts/generate_frr_patterns.py --family ADS --dry-run
"""

import sys
import json
import yaml
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass


@dataclass
class FRRGenerationResult:
    """Result of FRR pattern generation."""
    family: str
    patterns_generated: int
    patterns_failed: int
    errors: List[str]
    warnings: List[str]


class FRRPatternGenerator:
    """Generates V2 patterns for FRR requirements."""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.patterns_dir = project_root / "data" / "patterns"
        self.metadata_file = project_root / "data" / "requirements" / "frr_metadata.json"
        
        # Load FRR metadata
        with open(self.metadata_file, 'r', encoding='utf-8') as f:
            self.metadata = json.load(f)
        
        # Group FRRs by family
        self.frrs_by_family = self._group_by_family()
    
    def _group_by_family(self) -> Dict[str, List[str]]:
        """Group FRR IDs by family."""
        families = {}
        for frr_id, frr_data in self.metadata.items():
            family = frr_data.get('family', 'UNKNOWN')
            if family not in families:
                families[family] = []
            families[family].append(frr_id)
        return families
    
    def generate_family_patterns(
        self,
        family: str,
        dry_run: bool = False
    ) -> FRRGenerationResult:
        """Generate patterns for all FRRs in a family."""
        errors = []
        warnings = []
        patterns_generated = 0
        patterns_failed = 0
        
        if family not in self.frrs_by_family:
            errors.append(f"Family '{family}' not found in metadata")
            return FRRGenerationResult(family, 0, 0, errors, warnings)
        
        frr_ids = self.frrs_by_family[family]
        
        print(f"\n{'='*80}")
        print(f"Generating {family} FRR patterns (V2 schema)")
        print(f"{'='*80}\n")
        print(f"Found {len(frr_ids)} FRRs in {family} family")
        
        patterns = []
        for i, frr_id in enumerate(frr_ids):
            print(f"\n[{i+1}/{len(frr_ids)}] Generating pattern: {frr_id}")
            
            try:
                pattern = self._generate_frr_pattern(frr_id)
                patterns.append(pattern)
                patterns_generated += 1
                print(f"  ✅ Generation successful")
            except Exception as e:
                errors.append(f"Failed to generate {frr_id}: {e}")
                patterns_failed += 1
                print(f"  ❌ Generation failed: {e}")
        
        # Write patterns to file
        if not dry_run and patterns:
            output_file = self.patterns_dir / f"frr_{family.lower()}_patterns.yaml"
            self._write_patterns(patterns, output_file, family)
            print(f"\n✅ Wrote {len(patterns)} FRR patterns to {output_file.name}")
        elif dry_run:
            print(f"\n🔍 DRY RUN: Would write {len(patterns)} patterns to frr_{family.lower()}_patterns.yaml")
        
        return FRRGenerationResult(family, patterns_generated, patterns_failed, errors, warnings)
    
    def _generate_frr_pattern(self, frr_id: str) -> Dict[str, Any]:
        """Generate a V2 pattern for a single FRR."""
        frr_data = self.metadata[frr_id]
        
        # Convert FRR-ADS-01 to frr.ads.01
        family = frr_data['family'].lower()
        number = frr_id.split('-')[-1]
        pattern_id = f"frr.{family}.{number.lower()}"
        
        pattern = {
            'pattern_id': pattern_id,
            'name': frr_data['name'],
            'description': frr_data['statement'],
            'family': frr_data['family'],
            'severity': self._determine_severity(frr_data),
            'pattern_type': 'process_based',
            
            # FRRs are primarily process-based, not code-detectable
            'languages': self._generate_language_hints(frr_data),
            
            'finding': {
                'title_template': f"{frr_data['name']} - {frr_id}",
                'description_template': frr_data['statement'],
                'remediation_template': self._generate_remediation(frr_data),
                'evidence_collection': frr_data['guidance'].get('evidence_collection', []),
                'azure_services': frr_data['guidance'].get('azure_services', [])
            },
            
            'tags': self._generate_tags(frr_data),
            'nist_controls': [ctrl['id'] for ctrl in frr_data.get('nist_controls', [])],
            'related_ksis': frr_data.get('related_ksis', []),
            'related_frrs': frr_data.get('related_frrs', []),
            
            # V2 schema fields
            'evidence_collection': self._generate_evidence_collection(frr_data),
            'evidence_artifacts': self._generate_evidence_artifacts(frr_data),
            'automation': self._generate_automation(frr_data),
            'implementation': self._generate_implementation(frr_data),
            'ssp_mapping': self._generate_ssp_mapping(frr_data),
            'azure_guidance': self._generate_azure_guidance(frr_data),
            'compliance_frameworks': self._generate_compliance_frameworks(frr_data),
            'testing': self._generate_testing(frr_data)
        }
        
        return pattern
    
    def _determine_severity(self, frr_data: Dict) -> str:
        """Determine pattern severity from FRR data."""
        keyword = frr_data.get('primary_keyword', 'SHOULD')
        if keyword == 'MUST':
            return 'HIGH'
        elif keyword == 'SHOULD':
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _generate_language_hints(self, frr_data: Dict) -> Dict[str, Any]:
        """Generate language detection hints (minimal for process-based)."""
        # FRRs are process-based, but we can add documentation file hints
        return {
            'markdown': {
                'file_patterns': ['*.md', 'README.md', 'SECURITY.md'],
                'keywords': self._extract_keywords(frr_data['statement'])
            },
            'yaml': {
                'file_patterns': ['*.yaml', '*.yml', '.github/**/*.yml'],
                'keywords': ['fedramp', 'compliance', 'security']
            }
        }
    
    def _extract_keywords(self, statement: str) -> List[str]:
        """Extract keywords from FRR statement."""
        keywords = []
        important_words = [
            'security', 'compliance', 'fedramp', 'authorization',
            'monitoring', 'logging', 'audit', 'incident', 'vulnerability',
            'encryption', 'authentication', 'access control'
        ]
        
        statement_lower = statement.lower()
        for word in important_words:
            if word in statement_lower:
                keywords.append(word)
        
        return keywords[:5]  # Limit to 5 keywords
    
    def _generate_remediation(self, frr_data: Dict) -> str:
        """Generate remediation guidance."""
        keyword = frr_data.get('primary_keyword', 'SHOULD')
        name = frr_data['name']
        
        remediation = f"To comply with {frr_data['id']} ({name}), you {keyword} "
        
        if keyword == 'MUST':
            remediation += "implement the following mandatory requirements:\n\n"
        else:
            remediation += "consider implementing the following recommended practices:\n\n"
        
        # Add implementation checklist items as remediation steps
        checklist = frr_data['guidance'].get('implementation_checklist', [])
        for i, item in enumerate(checklist[:5], 1):  # First 5 items
            remediation += f"{i}. {item}\n"
        
        if len(checklist) > 5:
            remediation += f"\n(See full implementation checklist for {len(checklist)} total steps)"
        
        return remediation
    
    def _generate_tags(self, frr_data: Dict) -> List[str]:
        """Generate tags from FRR data."""
        tags = [
            frr_data['family'].lower(),
            frr_data['primary_keyword'].lower(),
            'process_based'
        ]
        
        # Add impact level tags
        for level in frr_data.get('impact_levels', []):
            tags.append(f"impact_{level.lower()}")
        
        # Add code_detectable status
        if frr_data.get('code_detectable') == 'Yes':
            tags.append('code_detectable')
        else:
            tags.append('documentation_required')
        
        return tags
    
    def _generate_evidence_collection(self, frr_data: Dict) -> Dict[str, List[Dict]]:
        """Generate evidence collection section."""
        evidence = {
            'azure_monitor_kql': [],
            'azure_cli': [],
            'powershell': [],
            'rest_api': [],
            'manual_procedures': []
        }
        
        # Most FRRs require manual evidence collection
        evidence_items = frr_data['guidance'].get('evidence_collection', [])
        for item in evidence_items:
            evidence['manual_procedures'].append({
                'procedure': item,
                'frequency': 'quarterly',
                'responsible_party': 'Security team',
                'documentation': 'Required for FedRAMP authorization package'
            })
        
        # Add Azure-specific collection if Azure services are involved
        azure_services = frr_data['guidance'].get('azure_services', [])
        if azure_services:
            evidence['azure_cli'].append({
                'command': f"# TODO: Add Azure CLI command for {frr_data['id']}",
                'description': f"Collect evidence for {frr_data['name']}",
                'output_format': 'json',
                'frequency': 'monthly'
            })
        
        return evidence
    
    def _generate_evidence_artifacts(self, frr_data: Dict) -> List[Dict[str, Any]]:
        """Generate evidence artifacts section."""
        artifacts = []
        
        # All FRRs require documentation
        artifacts.append({
            'artifact_type': 'documentation',
            'name': f"{frr_data['id']} - {frr_data['name']} Policy",
            'source': 'Organization security documentation',
            'frequency': 'annual_review',
            'retention_months': 36,
            'format': 'PDF/Markdown'
        })
        
        # Add configuration artifacts if applicable
        if frr_data['guidance'].get('azure_services'):
            artifacts.append({
                'artifact_type': 'configuration',
                'name': f"{frr_data['id']} - Azure Service Configuration",
                'source': 'Azure Portal export',
                'frequency': 'quarterly',
                'retention_months': 36,
                'format': 'JSON'
            })
        
        # Add compliance report
        artifacts.append({
            'artifact_type': 'report',
            'name': f"{frr_data['id']} - Compliance Status Report",
            'source': 'Compliance tracking system',
            'frequency': 'monthly',
            'retention_months': 36,
            'format': 'PDF/Excel'
        })
        
        return artifacts
    
    def _generate_automation(self, frr_data: Dict) -> Dict[str, Dict[str, Any]]:
        """Generate automation guidance section."""
        automation = {}
        
        opportunities = frr_data['guidance'].get('automation_opportunities', [])
        for i, opportunity in enumerate(opportunities[:3], 1):
            automation[f"automation_{i}"] = {
                'description': opportunity,
                'implementation': f"# TODO: Add implementation for {opportunity}",
                'azure_services': frr_data['guidance'].get('azure_services', []),
                'effort_hours': 8  # Higher estimate for process automation
            }
        
        return automation
    
    def _generate_implementation(self, frr_data: Dict) -> Dict[str, Any]:
        """Generate implementation section."""
        checklist = frr_data['guidance'].get('implementation_checklist', [])
        
        steps = []
        for i, item in enumerate(checklist, 1):
            steps.append({
                'step': i,
                'action': item,
                'azure_service': None,
                'estimated_hours': 2,  # Default estimate for process steps
                'validation': 'Document completion and obtain approval'
            })
        
        return {
            'prerequisites': [
                'FedRAMP authorization package template',
                'Organization security policies',
                'Azure subscription (if applicable)',
                'Security team approval process'
            ],
            'steps': steps,
            'total_effort_hours': len(steps) * 2
        }
    
    def _generate_ssp_mapping(self, frr_data: Dict) -> Dict[str, Any]:
        """Generate SSP mapping section."""
        nist_controls = frr_data.get('nist_controls', [])
        
        # Determine control family from first control
        control_family = "Unknown"
        if nist_controls:
            family_code = nist_controls[0]['id'].split('-')[0].upper()
            control_family = f"{family_code} - {nist_controls[0]['name']}"
        
        ssp_sections = []
        for ctrl in nist_controls[:3]:  # First 3 controls
            ssp_sections.append({
                'section': f"{ctrl['id']}: {ctrl['name']}",
                'description_template': f"Implementation of {frr_data['id']} - {frr_data['name']}:\n\n{frr_data['statement']}",
                'implementation_details': "# TODO: Add specific implementation details",
                'evidence_references': [
                    f"{frr_data['id']} Policy Documentation",
                    f"{frr_data['id']} Compliance Report"
                ]
            })
        
        return {
            'control_family': control_family,
            'control_numbers': [c['id'] for c in nist_controls],
            'ssp_sections': ssp_sections,
            'required_for_fedramp': True,
            'authorization_package_section': self._determine_package_section(frr_data)
        }
    
    def _determine_package_section(self, frr_data: Dict) -> str:
        """Determine which authorization package section this FRR belongs to."""
        family = frr_data['family']
        
        section_mapping = {
            'ADS': 'Appendix A - Authorization Data Sharing',
            'CCM': 'Section 10 - Configuration Management',
            'FSI': 'Section 15 - Incident Response',
            'ICP': 'Section 9 - Incident Response',
            'MAS': 'Section 11 - Maintenance',
            'PVA': 'Section 18 - Vulnerability Assessment',
            'RSC': 'Section 12 - System and Communications Protection',
            'SCN': 'Section 18 - Vulnerability Scanning',
            'UCM': 'Section 3 - Access Control',
            'VDR': 'Section 18 - Vulnerability Detection and Remediation'
        }
        
        return section_mapping.get(family, 'System Security Plan')
    
    def _generate_azure_guidance(self, frr_data: Dict) -> Dict[str, Any]:
        """Generate Azure guidance section."""
        azure_services = frr_data['guidance'].get('azure_services', [])
        
        recommended_services = []
        for service in azure_services[:5]:
            recommended_services.append({
                'service': service,
                'tier': 'Standard',
                'purpose': f"Required for {frr_data['name']} compliance",
                'monthly_cost_estimate': 'Varies by usage',
                'alternatives': []
            })
        
        return {
            'recommended_services': recommended_services,
            'well_architected_framework': {
                'pillar': 'Security',
                'design_area': self._determine_waf_area(frr_data['family']),
                'reference_url': 'https://learn.microsoft.com/azure/well-architected/security/'
            },
            'cloud_adoption_framework': {
                'stage': 'Govern',
                'guidance': f"Implement {frr_data['name']} as part of governance baseline",
                'reference_url': 'https://learn.microsoft.com/azure/cloud-adoption-framework/govern/'
            }
        }
    
    def _determine_waf_area(self, family: str) -> str:
        """Determine Well-Architected Framework design area."""
        area_mapping = {
            'ADS': 'Data Protection',
            'CCM': 'Configuration Management',
            'FSI': 'Incident Response',
            'ICP': 'Incident Response',
            'MAS': 'Maintenance',
            'PVA': 'Vulnerability Management',
            'RSC': 'Resource Management',
            'SCN': 'Security Testing',
            'UCM': 'Identity and Access Management',
            'VDR': 'Vulnerability Management'
        }
        return area_mapping.get(family, 'General Security')
    
    def _generate_compliance_frameworks(self, frr_data: Dict) -> Dict[str, Any]:
        """Generate compliance frameworks mapping."""
        frameworks = {
            'fedramp_20x': {
                'requirement_id': frr_data['id'],
                'requirement_name': frr_data['name'],
                'requirement_type': 'FRR',
                'primary_keyword': frr_data['primary_keyword'],
                'impact_levels': frr_data.get('impact_levels', [])
            }
        }
        
        # Add NIST 800-53 mapping
        nist_controls = frr_data.get('nist_controls', [])
        if nist_controls:
            frameworks['nist_800_53_rev5'] = {
                'controls': [
                    {
                        'control_id': ctrl['id'],
                        'control_name': ctrl['name']
                    }
                    for ctrl in nist_controls
                ]
            }
        
        return frameworks
    
    def _generate_testing(self, frr_data: Dict) -> Dict[str, Any]:
        """Generate testing section."""
        return {
            'validation_procedures': [
                {
                    'procedure': 'Review policy documentation',
                    'expected_outcome': 'Policy exists and is current (within 1 year)',
                    'frequency': 'annual'
                },
                {
                    'procedure': 'Verify implementation evidence',
                    'expected_outcome': 'Evidence artifacts collected and retained',
                    'frequency': 'quarterly'
                },
                {
                    'procedure': 'Test automated controls (if applicable)',
                    'expected_outcome': 'Automated controls functioning as designed',
                    'frequency': 'monthly'
                }
            ],
            'acceptance_criteria': [
                f"Policy documented for {frr_data['id']}",
                f"Implementation evidence collected and retained for 3 years",
                f"Annual review completed and documented",
                f"NIST controls {', '.join([c['id'] for c in frr_data.get('nist_controls', [])[:3]])} satisfied"
            ]
        }
    
    def _write_patterns(
        self,
        patterns: List[Dict],
        output_file: Path,
        family: str
    ) -> None:
        """Write FRR patterns to YAML file."""
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write(f"# FRR {family} Patterns - FedRAMP 20x Requirements\n")
            f.write(f"# Family: {family}\n")
            f.write(f"# Pattern Type: Process-Based Requirements\n")
            f.write("# Schema: V2\n")
            f.write("#\n")
            f.write("# These patterns represent FedRAMP Requirements (FRR) which are\n")
            f.write("# primarily process-based and require documentation, policies,\n")
            f.write("# and procedures rather than code-level detection.\n")
            f.write("#\n")
            f.write("# NOTE: Manual completion required for:\n")
            f.write("# - Automation implementation code\n")
            f.write("# - Organization-specific policy details\n")
            f.write("# - Evidence collection procedures\n\n")
            
            # Write patterns
            for i, pattern in enumerate(patterns):
                if i > 0:
                    f.write("\n---\n")
                yaml.dump(pattern, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Generate FRR patterns with V2 schema')
    parser.add_argument('--family', help='Family to generate (e.g., ADS, CCM)')
    parser.add_argument('--all', action='store_true', help='Generate all families')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be generated')
    
    args = parser.parse_args()
    
    if not args.family and not args.all:
        print("Error: Must specify --family or --all")
        parser.print_help()
        sys.exit(1)
    
    # Find project root
    script_path = Path(__file__).resolve()
    project_root = script_path.parent.parent
    
    generator = FRRPatternGenerator(project_root)
    
    # Determine families to generate
    families = []
    if args.all:
        families = sorted(generator.frrs_by_family.keys())
    else:
        families = [args.family.upper()]
    
    print(f"\n{'='*80}")
    print(f"FRR Pattern Generator (V2 Schema)")
    print(f"{'='*80}")
    print(f"Families to generate: {', '.join(families)}")
    print(f"Dry run: {args.dry_run}")
    
    # Generate patterns for each family
    results = []
    for family in families:
        result = generator.generate_family_patterns(family, dry_run=args.dry_run)
        results.append(result)
    
    # Print summary
    print(f"\n{'='*80}")
    print("Generation Summary")
    print(f"{'='*80}\n")
    
    total_generated = sum(r.patterns_generated for r in results)
    total_failed = sum(r.patterns_failed for r in results)
    
    for result in results:
        status = "✅" if result.patterns_failed == 0 else "⚠️"
        print(f"{status} {result.family}: {result.patterns_generated} generated, {result.patterns_failed} failed")
        
        if result.errors:
            for error in result.errors:
                print(f"   ❌ {error}")
        
        if result.warnings:
            for warning in result.warnings:
                print(f"   ⚠️  {warning}")
    
    print(f"\nTotal: {total_generated} patterns generated, {total_failed} failed")
    
    sys.exit(0 if total_failed == 0 else 1)


if __name__ == '__main__':
    main()
