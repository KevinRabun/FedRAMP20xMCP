# OSCAL Format Clarification for FedRAMP 20x

## Executive Summary

**TL;DR:** FedRAMP 20x requires **machine-readable** formats (JSON, XML, or structured data) for Authorization Data Sharing. **OSCAL is NOT mentioned in FedRAMP 20x requirements** - it's a NIST standard that can be used as one potential implementation approach.

## What the Requirements Actually Say

### FRR-ADS-01: Public Information

The actual requirement states:

> Providers MUST publicly share up-to-date information about the cloud service offering in both **human-readable** and **_machine-readable_** formats...

### Definition of Machine-Readable (FRD-ALL-17)

> "machine-readable", when used with respect to data, means **data in a format that can be easily processed by a computer without human intervention while ensuring no semantic meaning is lost**

## What This Means

### ✅ Required
- Machine-readable formats (JSON, XML, or other structured data)
- Automated/programmatic access to authorization data
- Consistent data structures
- Computer-processable without human intervention

### 💡 Optional Implementation Approach
- OSCAL (Open Security Controls Assessment Language) format
- NIST standard for machine-readable security documentation (not mentioned in FedRAMP 20x)
- One potential approach for structured security data
- Standardized schema for SSP, POA&M, SAR, and assessment results
- May provide interoperability benefits with some FedRAMP ecosystem tools

## Why Consider OSCAL as an Implementation Approach

**Important:** OSCAL is not mentioned in FedRAMP 20x requirements. However, it may offer benefits:

1. **NIST Standard**: Established NIST standard for machine-readable security documentation
2. **Standardization**: Common schema that some government agencies may recognize
3. **Tooling**: Growing ecosystem of OSCAL validation and processing tools
4. **Interoperability**: May facilitate data exchange in environments using OSCAL
5. **Rev 5 Context**: OSCAL was discussed in FedRAMP Rev 5 contexts (but is not specified in 20x)

## What Formats Are Acceptable?

### All Acceptable (Equal Standing)
- **Custom JSON schema** - Must meet machine-readable requirements
- **Custom XML schema** - Must meet machine-readable requirements
- **OSCAL (JSON or XML)** - NIST standard approach, not mentioned in FedRAMP 20x
- **Other structured data formats** - As long as they're computer-processable

### Not Acceptable
- Word documents (.docx)
- PDF files
- Excel spreadsheets (unless structured as API output)
- Plain text files
- HTML web pages (unless serving structured data)

## Implementation Guidance

### Approach 1: Custom JSON/XML (Direct Implementation)
```json
{
  "system": {
    "name": "My Cloud Service",
    "fedramp_id": "FR12345678",
    "impact_level": "Moderate",
    "last_updated": "2025-12-03T10:00:00Z"
  },
  "vulnerabilities": [...],
  "ksi_metrics": [...]
}
```

**Pros:**
- Direct control over schema design
- Can align perfectly with existing systems
- Potentially simpler implementation
- No dependencies on external standards

**Cons:**
- Consumers need to learn your schema
- Less standardization across CSPs

### Approach 2: OSCAL Format (NIST Standard Option)
```json
{
  "system-security-plan": {
    "uuid": "12345678-1234-1234-1234-123456789abc",
    "metadata": {
      "title": "My Cloud Service SSP",
      "oscal-version": "1.1.2"
    },
    "system-characteristics": { ... },
    "system-implementation": { ... }
  }
}
```

**Pros:**
- NIST standard schema
- Validation tools available
- May facilitate interoperability in OSCAL-aware environments
- Standard approach used in some government contexts

**Cons:**
- Learning curve for OSCAL schema
- More complex than custom formats
- Not mentioned or required by FedRAMP 20x
- May be unnecessary overhead for simple implementations

## Decision Framework

**Use Custom JSON/XML if:**
- ✅ You want direct control and simplicity
- ✅ You have existing structured data systems
- ✅ You want to minimize external dependencies
- ✅ Your implementation can be straightforward
- ✅ You're building for your specific agency/consumer needs

**Consider OSCAL if:**
- 💡 You're already using OSCAL in other contexts (e.g., Rev 5)
- 💡 You have existing OSCAL tooling/expertise
- 💡 Agencies you work with specifically request OSCAL
- 💡 You want to align with NIST standards
- 💡 You expect consumers may benefit from OSCAL familiarity

**Important:** FedRAMP 20x does not mention or require OSCAL. Choose the approach that best fits your implementation needs.

## Where This Clarification Came From

This clarification is based on careful review of the actual FedRAMP 20x requirements:

1. **FRR-ADS-01** requires "machine-readable" formats
2. **FRD-ALL-17** defines machine-readable as computer-processable data
3. **OSCAL is NOT mentioned anywhere** in FedRAMP 20x Phase Two documentation
4. **OSCAL is a NIST standard** (NIST SP 800-53) that can be one implementation approach
5. **Previous references to OSCAL** in this MCP server were implementation suggestions, not FedRAMP requirements

## Recommendation

**Implement machine-readable formats that meet your needs.** FedRAMP 20x does not specify a particular format:
- Custom JSON/XML schemas can be simpler and more direct
- OSCAL is a NIST standard option if you have existing familiarity or specific agency requests
- Choose based on your implementation context, not perceived FedRAMP preference
- The requirement is "machine-readable" - focus on that requirement first

**No migration path needed:** There is no expectation to adopt OSCAL unless your specific circumstances benefit from it.

## Questions?

For authoritative guidance, consult:
- FedRAMP official documentation: https://fedramp.gov
- NIST OSCAL documentation: https://pages.nist.gov/OSCAL/
- FedRAMP PMO: info@fedramp.gov

## Last Updated

December 3, 2025 - Based on FedRAMP 20x Phase Two documentation (Version 25.11C)
