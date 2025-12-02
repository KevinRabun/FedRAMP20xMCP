# Copilot Instructions for FedRAMP 20x MCP Server

This project is an MCP server that loads FedRAMP 20x requirements from JSON files and official documentation markdown files from https://github.com/FedRAMP/docs and answers user questions about those requirements.

## References
- [MCP Python SDK Documentation](https://github.com/modelcontextprotocol/python-sdk)
- [MCP Server Build Guide](https://modelcontextprotocol.io/docs/develop/build-server)
- [FedRAMP Data Source](https://github.com/FedRAMP/docs/tree/main/data)
- [FedRAMP Documentation](https://github.com/FedRAMP/docs/tree/main/docs)

## Project Completion Status

### Completed Features
✅ Scaffold MCP server using Python SDK
✅ Implement tools to query FedRAMP requirements by control, family, or keyword
✅ Load JSON data from remote source
✅ Provide endpoints for querying requirements
✅ Follow MCP server best practices
✅ Add tools for querying FedRAMP Definitions (50 terms)
✅ Add tools for querying Key Security Indicators (72 indicators)
✅ Add 6 enhancement tools (comparison, examples, dependencies, effort estimation, cloud-native guidance, architecture validation)
✅ Add 8 comprehensive prompts (roadmap, quarterly review, API design, KSI priorities, vendor evaluation, documentation, migration, audit prep)
✅ 1-hour data caching with automatic refresh

### Current Capabilities
The server provides 20 MCP tools:

**Core Tools:**
1. **get_control** - Get specific FedRAMP requirement by ID
2. **list_family_controls** - List requirements by family
3. **search_requirements** - Search requirements by keywords
4. **get_definition** - Look up FedRAMP term definitions
5. **list_definitions** - List all FedRAMP definitions
6. **search_definitions** - Search within definitions
7. **get_ksi** - Get specific Key Security Indicator
8. **list_ksi** - List all Key Security Indicators

**Documentation Tools:**
9. **search_documentation** - Search official FedRAMP markdown documentation
10. **get_documentation_file** - Get full content of specific documentation file
11. **list_documentation_files** - List all available documentation files

**Enhancement Tools:**
12. **compare_with_rev4** - Compare FedRAMP 20x with Rev 4/5 for 6 areas
13. **get_implementation_examples** - Practical code examples for requirements
14. **check_requirement_dependencies** - Map dependencies between requirements
15. **estimate_implementation_effort** - Timeline and cost estimates
16. **get_cloud_native_guidance** - Cloud-native implementation guidance
17. **validate_architecture** - Architecture review against requirements

**Export Tools:**
18. **export_to_excel** - Export data to Excel files
19. **export_to_csv** - Export data to CSV files
20. **generate_ksi_specification** - Generate detailed KSI product specifications

**Comprehensive Prompts:**
1. **initial_assessment_roadmap** - 9-11 month roadmap with budget/team guidance
2. **quarterly_review_checklist** - FRR-CCM-QR checklist for all 72 KSIs
3. **api_design_guide** - Complete FRR-ADS API design with OSCAL formats
4. **ksi_implementation_priorities** - Prioritized 8-phase KSI rollout over 12 months
5. **vendor_evaluation** - Vendor assessment framework with scorecard
6. **documentation_generator** - OSCAL SSP templates and procedure templates
7. **migration_from_rev5** - 7-phase Rev 5 to 20x migration guide
8. **audit_preparation** - 12-week audit preparation timeline and checklist
9. **azure_ksi_automation** - Complete Azure/M365 automation guide for all 72 KSIs with PowerShell, Azure CLI, Graph API, KQL queries, and evidence collection framework

### Data Loaded
- 329 total requirements from 12 documents (100% coverage)
- 50 FedRAMP Definitions (FRD family)
- 72 Key Security Indicators (KSI family)
- All FedRAMP 20x standards: ADS, CCM, FSI, ICP, MAS, PVA, RSC, SCN, UCM, VDR
- Official documentation markdown files (dynamically discovered)
- 1-hour caching with automatic refresh

## Development Rules
- Use Python 3.10+
- Use MCP Python SDK 1.2.0+
- Do not print to stdout (use logging to stderr)
- Use STDIO transport for MCP server
- Document all tools and endpoints
- Update this file as features are added
