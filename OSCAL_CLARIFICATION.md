# OSCAL Format Clarification for FedRAMP 20x

## Executive Summary

**TL;DR:** FedRAMP 20x requires **machine-readable** formats (JSON, XML, or structured data) for Authorization Data Sharing. **OSCAL is the preferred format but NOT strictly required.**

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

### ⭐ Preferred (Not Required)
- OSCAL (Open Security Controls Assessment Language) format
- NIST standard for machine-readable security documentation
- Maximum interoperability with FedRAMP ecosystem
- Standardized schema for SSP, POA&M, SAR, and assessment results

## Why OSCAL is Preferred

1. **FedRAMP Ecosystem Compatibility**: FedRAMP systems and tools are optimized for OSCAL
2. **Standardization**: Common schema understood across government agencies
3. **Tooling**: Growing ecosystem of OSCAL validation and processing tools
4. **Interoperability**: Easier data exchange between CSPs, agencies, and FedRAMP
5. **Future-Proofing**: OSCAL is the direction of federal compliance automation

## What Formats Are Acceptable?

### Fully Acceptable
- **OSCAL (JSON or XML)** - Preferred, maximum compatibility
- **Custom JSON schema** - Must meet machine-readable requirements
- **Custom XML schema** - Must meet machine-readable requirements
- **Structured data formats** - As long as they're computer-processable

### Not Acceptable
- Word documents (.docx)
- PDF files
- Excel spreadsheets (unless structured as API output)
- Plain text files
- HTML web pages (unless serving structured data)

## Implementation Guidance

### Approach 1: OSCAL (Recommended)
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
- Maximum FedRAMP compatibility
- Standard schema, validation tools available
- Better for ecosystem interoperability

**Cons:**
- Learning curve for OSCAL schema
- May require tool investment
- More complex than custom formats

### Approach 2: Custom JSON (Acceptable)
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
- Flexibility in schema design
- Can align with existing systems
- Potentially simpler implementation

**Cons:**
- May require custom tooling by consumers
- Less standardization across CSPs
- Future compatibility concerns

## Decision Framework

**Use OSCAL if:**
- ✅ You want maximum FedRAMP ecosystem compatibility
- ✅ You're building for long-term FedRAMP participation
- ✅ You have budget for OSCAL tooling/expertise
- ✅ You want to minimize consumer friction
- ✅ You're already using OSCAL-compatible tools

**Use Custom Format if:**
- ⚠️ You have existing structured data systems
- ⚠️ OSCAL investment isn't feasible immediately
- ⚠️ You're prototyping or testing FedRAMP 20x
- ⚠️ You plan to migrate to OSCAL later

**Important:** Even if starting with custom formats, plan for eventual OSCAL adoption for maximum ecosystem benefit.

## Where This Clarification Came From

This clarification is based on careful review of the actual FedRAMP 20x requirements:

1. **FRR-ADS-01** requires "machine-readable" formats
2. **FRD-ALL-17** defines machine-readable as computer-processable data
3. **No requirement explicitly mandates OSCAL**
4. **Multiple references** use language like "OSCAL format preferred" and "Use OSCAL format where applicable"

## Recommendation

**Start with OSCAL if feasible.** While not strictly required, OSCAL provides:
- Proven compatibility with FedRAMP systems
- Standardization across the federal government
- Growing tooling ecosystem
- Lower friction for agencies consuming your data

If OSCAL isn't immediately feasible, implement machine-readable APIs in JSON/XML with a roadmap to OSCAL adoption.

## Questions?

For authoritative guidance, consult:
- FedRAMP official documentation: https://fedramp.gov
- NIST OSCAL documentation: https://pages.nist.gov/OSCAL/
- FedRAMP PMO: info@fedramp.gov

## Last Updated

December 3, 2025 - Based on FedRAMP 20x Phase Two documentation (Version 25.11C)
