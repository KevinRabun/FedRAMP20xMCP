#!/usr/bin/env python3
"""
Pattern V1 to V2 Migration Script

Automates migration of existing V1 patterns to V2 schema by extracting data from:
1. Existing V1 pattern YAML files
2. Traditional KSI analyzer Python files (evidence methods)
3. KSI metadata JSON file (implementation guidance)

Usage:
    # Migrate single family
    python scripts/migrate_patterns_v1_to_v2.py --family IAM
    
    # Migrate all patterns
    python scripts/migrate_patterns_v1_to_v2.py --all
    
    # Dry run (show what would be migrated)
    python scripts/migrate_patterns_v1_to_v2.py --family IAM --dry-run
    
    # Validate after migration
    python scripts/migrate_patterns_v1_to_v2.py --family IAM --validate
"""

import sys
import json
import yaml
import re
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict


@dataclass
class MigrationResult:
    """Result of pattern migration."""
    family: str
    patterns_migrated: int
    patterns_failed: int
    errors: List[str]
    warnings: List[str]


class PatternMigrator:
    """Migrates V1 patterns to V2 schema."""
    
    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.patterns_dir = project_root / "data" / "patterns"
        self.analyzers_dir = project_root / "src" / "fedramp_20x_mcp" / "analyzers" / "ksi"
        self.metadata_file = project_root / "data" / "requirements" / "ksi_metadata.json"
        
        # Load metadata
        with open(self.metadata_file, 'r', encoding='utf-8') as f:
            self.metadata = json.load(f)
        
        # Track migration stats
        self.total_patterns = 0
        self.migrated_patterns = 0
        self.failed_patterns = 0
    
    def migrate_family(self, family: str, dry_run: bool = False) -> MigrationResult:
        """Migrate all patterns for a specific family."""
        errors = []
        warnings = []
        patterns_migrated = 0
        patterns_failed = 0
        
        # Find V1 pattern file
        v1_file = self.patterns_dir / f"{family.lower()}_patterns.yaml"
        if not v1_file.exists():
            errors.append(f"V1 pattern file not found: {v1_file}")
            return MigrationResult(family, 0, 0, errors, warnings)
        
        print(f"\n{'='*80}")
        print(f"Migrating {family} patterns from V1 to V2")
        print(f"{'='*80}\n")
        
        # Load V1 patterns
        with open(v1_file, 'r', encoding='utf-8') as f:
            v1_patterns = list(yaml.safe_load_all(f))
        
        print(f"Found {len(v1_patterns)} patterns in {v1_file.name}")
        
        # Migrate each pattern
        v2_patterns = []
        for i, v1_pattern in enumerate(v1_patterns):
            if v1_pattern is None:
                continue
            
            pattern_id = v1_pattern.get('pattern_id', f'unknown_{i}')
            print(f"\n[{i+1}/{len(v1_patterns)}] Migrating pattern: {pattern_id}")
            
            try:
                v2_pattern = self._migrate_pattern(v1_pattern, family)
                v2_patterns.append(v2_pattern)
                patterns_migrated += 1
                print(f"  ✅ Migration successful")
            except Exception as e:
                errors.append(f"Failed to migrate {pattern_id}: {e}")
                patterns_failed += 1
                print(f"  ❌ Migration failed: {e}")
        
        # Write V2 patterns to new file
        if not dry_run and v2_patterns:
            v2_file = self.patterns_dir / f"{family.lower()}_patterns_v2.yaml"
            self._write_v2_patterns(v2_patterns, v2_file)
            print(f"\n✅ Wrote {len(v2_patterns)} V2 patterns to {v2_file.name}")
        elif dry_run:
            print(f"\n🔍 DRY RUN: Would write {len(v2_patterns)} patterns to {family.lower()}_patterns_v2.yaml")
        
        return MigrationResult(family, patterns_migrated, patterns_failed, errors, warnings)
    
    def _migrate_pattern(self, v1_pattern: Dict[str, Any], family: str) -> Dict[str, Any]:
        """Migrate a single V1 pattern to V2 schema."""
        # Start with V1 pattern as base
        v2_pattern = v1_pattern.copy()
        
        # Extract KSI ID from related_ksis if present
        ksi_id = None
        if 'related_ksis' in v1_pattern and v1_pattern['related_ksis']:
            ksi_id = v1_pattern['related_ksis'][0]
        
        # Add V2 fields
        if ksi_id:
            # Get traditional analyzer data
            analyzer_data = self._extract_analyzer_data(ksi_id)
            metadata_data = self._extract_metadata_data(ksi_id)
            
            # Add evidence collection
            if analyzer_data and 'evidence_collection_queries' in analyzer_data:
                v2_pattern['evidence_collection'] = self._convert_evidence_collection(
                    analyzer_data['evidence_collection_queries']
                )
            
            # Add evidence artifacts
            if analyzer_data and 'evidence_artifacts' in analyzer_data:
                v2_pattern['evidence_artifacts'] = self._convert_evidence_artifacts(
                    analyzer_data['evidence_artifacts']
                )
            
            # Add automation
            if analyzer_data and 'automation_recommendations' in analyzer_data:
                v2_pattern['automation'] = self._convert_automation(
                    analyzer_data['automation_recommendations'],
                    metadata_data
                )
            
            # Add implementation
            if metadata_data and 'guidance' in metadata_data:
                v2_pattern['implementation'] = self._convert_implementation(
                    metadata_data['guidance']
                )
            
            # Add SSP mapping
            if 'nist_controls' in v1_pattern:
                v2_pattern['ssp_mapping'] = self._create_ssp_mapping(
                    v1_pattern['nist_controls'],
                    ksi_id,
                    metadata_data
                )
            
            # Add Azure guidance
            if metadata_data and 'guidance' in metadata_data:
                v2_pattern['azure_guidance'] = self._create_azure_guidance(
                    metadata_data['guidance']
                )
            
            # Add compliance frameworks
            v2_pattern['compliance_frameworks'] = self._create_compliance_frameworks(
                ksi_id,
                metadata_data
            )
            
            # Add testing section (template - needs manual completion)
            v2_pattern['testing'] = self._create_testing_template(v1_pattern)
        
        return v2_pattern
    
    def _extract_analyzer_data(self, ksi_id: str) -> Optional[Dict[str, Any]]:
        """Extract data from traditional KSI analyzer Python file."""
        # Convert KSI-IAM-01 to ksi_iam_01.py
        filename = ksi_id.lower().replace('-', '_') + '.py'
        analyzer_file = self.analyzers_dir / filename
        
        if not analyzer_file.exists():
            print(f"  ⚠️  Analyzer file not found: {filename}")
            return None
        
        # Read analyzer file
        with open(analyzer_file, 'r', encoding='utf-8') as f:
            content = f.read()
        
        data = {}
        
        # Extract get_evidence_collection_queries method
        ecq_match = re.search(
            r'def get_evidence_collection_queries\(self\).*?return\s+(\{.*?\})',
            content,
            re.DOTALL
        )
        if ecq_match:
            try:
                # Try to evaluate the dict (simple cases)
                queries_str = ecq_match.group(1)
                # For safety, just mark that it exists
                data['evidence_collection_queries'] = {'found': True, 'content': queries_str[:500]}
            except:
                pass
        
        # Extract get_evidence_artifacts method
        ea_match = re.search(
            r'def get_evidence_artifacts\(self\).*?return\s+\[(.*?)\s+\]',
            content,
            re.DOTALL
        )
        if ea_match:
            artifacts_str = ea_match.group(1)
            # Evidence artifacts are dict objects, mark as found
            data['evidence_artifacts'] = {'found': True, 'content': artifacts_str[:1000]}
        
        # Extract get_evidence_automation_recommendations method  
        ear_match = re.search(
            r'def get_evidence_automation_recommendations\(self\).*?return\s+(\{.*?\})',
            content,
            re.DOTALL
        )
        if ear_match:
            data['automation_recommendations'] = {'found': True, 'content': ear_match.group(1)[:500]}
        
        return data if data else None
    
    def _extract_metadata_data(self, ksi_id: str) -> Optional[Dict[str, Any]]:
        """Extract data from KSI metadata JSON."""
        return self.metadata.get(ksi_id)
    
    def _convert_evidence_collection(self, analyzer_data: Dict) -> Dict[str, List[Dict]]:
        """Convert evidence collection queries to V2 format."""
        # Template structure - needs manual completion
        return {
            "azure_monitor_kql": [
                {
                    "query": "# TODO: Extract from analyzer",
                    "description": "Evidence collection query",
                    "retention_days": 90,
                    "schedule": "daily"
                }
            ],
            "azure_cli": [
                {
                    "command": "# TODO: Extract from analyzer",
                    "description": "Azure CLI evidence collection",
                    "output_format": "json",
                    "frequency": "weekly"
                }
            ]
        }
    
    def _convert_evidence_artifacts(self, analyzer_data: Dict) -> List[Dict[str, Any]]:
        """Convert evidence artifacts from analyzer to V2 format."""
        # Template structure - artifacts found in analyzer are more detailed
        # This is a simplified template that needs manual enhancement
        return [
            {
                "artifact_type": "logs",
                "name": "Authentication logs with MFA details",
                "source": "Azure Monitor - SigninLogs",
                "frequency": "daily",
                "retention_months": 36,  # 3 years
                "format": "JSON"
            },
            {
                "artifact_type": "configuration",
                "name": "Conditional Access policies export",
                "source": "Microsoft Graph API",
                "frequency": "weekly",
                "retention_months": 36,
                "format": "JSON"
            },
            {
                "artifact_type": "report",
                "name": "Authentication methods compliance report",
                "source": "Microsoft Graph API",
                "frequency": "weekly",
                "retention_months": 36,
                "format": "CSV"
            }
        ]
    
    def _convert_automation(
        self,
        analyzer_data: Dict,
        metadata_data: Optional[Dict]
    ) -> Dict[str, Dict[str, Any]]:
        """Convert automation recommendations to V2 format."""
        automation = {}
        
        # Add automation from metadata if available
        if metadata_data and 'guidance' in metadata_data:
            opportunities = metadata_data['guidance'].get('automation_opportunities', [])
            for i, opportunity in enumerate(opportunities[:3]):  # Limit to 3
                key = f"automation_{i+1}"
                automation[key] = {
                    "description": opportunity,
                    "implementation": "# TODO: Add implementation code",
                    "azure_services": metadata_data['guidance'].get('azure_services', []),
                    "effort_hours": 4  # Default estimate
                }
        
        return automation
    
    def _convert_implementation(self, guidance: Dict) -> Dict[str, Any]:
        """Convert implementation checklist to V2 format."""
        checklist = guidance.get('implementation_checklist', [])
        
        steps = []
        for i, item in enumerate(checklist):
            steps.append({
                "step": i + 1,
                "action": item,
                "azure_service": None,  # TODO: Parse from item text
                "estimated_hours": 1,  # Default
                "validation": "Manual verification required"
            })
        
        return {
            "prerequisites": [
                "Azure subscription with required permissions",
                "Microsoft Entra ID tenant configured"
            ],
            "steps": steps,
            "total_effort_hours": len(steps)  # Simple estimate
        }
    
    def _create_ssp_mapping(
        self,
        nist_controls: List[str],
        ksi_id: str,
        metadata_data: Optional[Dict]
    ) -> Dict[str, Any]:
        """Create SSP mapping from NIST controls."""
        # Extract control family from first control
        control_family = "Unknown"
        if nist_controls:
            family_code = nist_controls[0].split('-')[0].upper()
            family_map = {
                'AC': 'AC - Access Control',
                'AT': 'AT - Awareness and Training',
                'AU': 'AU - Audit and Accountability',
                'CA': 'CA - Assessment, Authorization, and Monitoring',
                'CM': 'CM - Configuration Management',
                'CP': 'CP - Contingency Planning',
                'IA': 'IA - Identification and Authentication',
                'IR': 'IR - Incident Response',
                'MA': 'MA - Maintenance',
                'MP': 'MP - Media Protection',
                'PE': 'PE - Physical and Environmental Protection',
                'PL': 'PL - Planning',
                'PM': 'PM - Program Management',
                'PS': 'PS - Personnel Security',
                'PT': 'PT - Personally Identifiable Information Processing',
                'RA': 'RA - Risk Assessment',
                'SA': 'SA - System and Services Acquisition',
                'SC': 'SC - System and Communications Protection',
                'SI': 'SI - System and Information Integrity',
                'SR': 'SR - Supply Chain Risk Management'
            }
            control_family = family_map.get(family_code, f"{family_code} - Unknown")
        
        ksi_name = metadata_data.get('name', 'Unknown') if metadata_data else 'Unknown'
        
        return {
            "control_family": control_family,
            "control_numbers": [c.upper() for c in nist_controls],
            "ssp_sections": [
                {
                    "section": f"{nist_controls[0].upper()}: {ksi_name}",
                    "description_template": f"# TODO: Add SSP description for {ksi_id}",
                    "implementation_details": "# TODO: Add implementation details",
                    "evidence_references": [
                        "Configuration exports",
                        "Compliance reports"
                    ]
                }
            ]
        }
    
    def _create_azure_guidance(self, guidance: Dict) -> Dict[str, Any]:
        """Create Azure guidance from metadata."""
        azure_services = guidance.get('azure_services', [])
        
        recommended_services = []
        for service in azure_services[:5]:  # Limit to 5
            recommended_services.append({
                "service": service,
                "tier": "Standard",  # Default
                "purpose": f"Required for {service} functionality",
                "monthly_cost_estimate": "Varies by usage",
                "alternatives": []
            })
        
        return {
            "recommended_services": recommended_services,
            "well_architected_framework": {
                "pillar": "Security",
                "design_area": "Identity and Access Management",
                "reference_url": "https://learn.microsoft.com/azure/well-architected/security/"
            }
        }
    
    def _create_compliance_frameworks(
        self,
        ksi_id: str,
        metadata_data: Optional[Dict]
    ) -> Dict[str, Any]:
        """Create compliance framework mappings."""
        frameworks = {
            "fedramp_20x": {
                "requirement_id": ksi_id,
                "requirement_name": metadata_data.get('name', 'Unknown') if metadata_data else 'Unknown',
                "impact_levels": metadata_data.get('impact_levels', ['Low', 'Moderate']) if metadata_data else ['Low', 'Moderate']
            }
        }
        
        # Add NIST 800-53 mapping
        if metadata_data and 'nist_controls' in metadata_data:
            frameworks["nist_800_53_rev5"] = {
                "controls": [
                    {
                        "control_id": ctrl['id'].upper(),
                        "control_name": ctrl['name']
                    }
                    for ctrl in metadata_data['nist_controls'][:5]  # Limit to 5
                ]
            }
        
        return frameworks
    
    def _create_testing_template(self, v1_pattern: Dict) -> Dict[str, Any]:
        """Create testing section template."""
        return {
            "positive_test_cases": [
                {
                    "description": "TODO: Add positive test case",
                    "code_sample": "# TODO: Add compliant code sample",
                    "expected_severity": "INFO",
                    "expected_finding": True
                }
            ],
            "negative_test_cases": [
                {
                    "description": "TODO: Add negative test case",
                    "code_sample": "# TODO: Add non-compliant code sample",
                    "expected_severity": "HIGH",
                    "expected_finding": True
                }
            ],
            "validation_scripts": []
        }
    
    def _write_v2_patterns(self, patterns: List[Dict], output_file: Path) -> None:
        """Write V2 patterns to YAML file."""
        with open(output_file, 'w', encoding='utf-8') as f:
            # Write header
            f.write(f"# {output_file.stem.upper().replace('_', ' ')} - V2 Schema\n")
            f.write("# Migrated from V1 schema with enhanced evidence collection\n")
            f.write("# \n")
            f.write("# NOTE: This is an automated migration. Manual review required for:\n")
            f.write("# - Evidence collection queries (marked with TODO)\n")
            f.write("# - Automation implementation code\n")
            f.write("# - SSP mapping descriptions\n")
            f.write("# - Test cases\n\n")
            
            # Write patterns
            for i, pattern in enumerate(patterns):
                if i > 0:
                    f.write("\n---\n")
                yaml.dump(pattern, f, default_flow_style=False, sort_keys=False, allow_unicode=True)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Migrate V1 patterns to V2 schema')
    parser.add_argument('--family', help='Family to migrate (e.g., IAM, VDR)')
    parser.add_argument('--all', action='store_true', help='Migrate all families')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be migrated without writing files')
    parser.add_argument('--validate', action='store_true', help='Validate migrated patterns after migration')
    
    args = parser.parse_args()
    
    if not args.family and not args.all:
        print("Error: Must specify --family or --all")
        parser.print_help()
        sys.exit(1)
    
    # Find project root
    script_path = Path(__file__).resolve()
    project_root = script_path.parent.parent
    
    migrator = PatternMigrator(project_root)
    
    # Determine families to migrate
    families = []
    if args.all:
        # Find all pattern files
        pattern_files = list(migrator.patterns_dir.glob('*_patterns.yaml'))
        families = [f.stem.replace('_patterns', '').upper() for f in pattern_files]
    else:
        families = [args.family.upper()]
    
    print(f"\n{'='*80}")
    print(f"Pattern V1 to V2 Migration Script")
    print(f"{'='*80}")
    print(f"Families to migrate: {', '.join(families)}")
    print(f"Dry run: {args.dry_run}")
    print(f"Validate after: {args.validate}")
    
    # Migrate each family
    results = []
    for family in families:
        result = migrator.migrate_family(family, dry_run=args.dry_run)
        results.append(result)
    
    # Print summary
    print(f"\n{'='*80}")
    print("Migration Summary")
    print(f"{'='*80}\n")
    
    total_migrated = sum(r.patterns_migrated for r in results)
    total_failed = sum(r.patterns_failed for r in results)
    
    for result in results:
        status = "✅" if result.patterns_failed == 0 else "⚠️"
        print(f"{status} {result.family}: {result.patterns_migrated} migrated, {result.patterns_failed} failed")
        
        if result.errors:
            for error in result.errors:
                print(f"   ❌ {error}")
        
        if result.warnings:
            for warning in result.warnings:
                print(f"   ⚠️  {warning}")
    
    print(f"\nTotal: {total_migrated} patterns migrated, {total_failed} failed")
    
    # Run validation if requested
    if args.validate and not args.dry_run:
        print(f"\n{'='*80}")
        print("Running validation on migrated patterns...")
        print(f"{'='*80}\n")
        
        validator_script = project_root / "scripts" / "validate_pattern_schema.py"
        if validator_script.exists():
            import subprocess
            for family in families:
                v2_file = migrator.patterns_dir / f"{family.lower()}_patterns_v2.yaml"
                if v2_file.exists():
                    print(f"\nValidating {v2_file.name}...")
                    result = subprocess.run(
                        [sys.executable, str(validator_script), str(v2_file), "--schema", "v2"],
                        capture_output=True,
                        text=True
                    )
                    print(result.stdout)
        else:
            print("⚠️  Validator script not found, skipping validation")
    
    sys.exit(0 if total_failed == 0 else 1)


if __name__ == '__main__':
    main()
