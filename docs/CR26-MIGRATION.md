# Migration to the FedRAMP Consolidated Rules for 2026 (CR26)

Release 1.4.0 moves the server from the pre-2026 FedRAMP 20x data
(`FRMR.documentation.json`, v0.9.43-beta, in `FedRAMP/docs`) to the **FedRAMP Consolidated
Rules for 2026**, version `2026.10.13.01` (`FedRAMP/rules`, `fedramp-consolidated-rules.json`).

## Why it was needed

- **The data source was gone.** FedRAMP deleted `FRMR.documentation.json` in the CR26 transition
  (FedRAMP/docs commit `2bc4bdbff3`, 2026-06-19) and later renamed the repo to `FedRAMP/docs-legacy`.
  The loader got a `301` on the old API path, did not follow redirects, found no JSON, and with an
  empty cache every rules tool and test collection failed.
- **The content was stale.** 320 distinct rule/KSI IDs cited across patterns, prompts, templates
  and tools (about 6,300 occurrences) did not exist in CR26. Prompts asserted 72 KSIs, families
  that no longer exist, fixed log-retention periods and severity-bucket remediation deadlines that
  CR26 does not contain.

## What changed in the data model

| | Pre-CR26 (v0.9.43-beta) | CR26 (2026.10.13.01) |
|---|---|---|
| FRR families | ADS CCM FSI ICP KSI MAS PVA SCG SCN UCM VDR | AFC AGU CCM CDS CMU CPO FRC IEC IVV MAS MKT REC SCG SCN SDR VDR VER |
| FRR rules | 163 | 245 |
| KSI families / indicators | 11 / 60 (incl. AFR) | 10 / 46 (no AFR) |
| Definitions (FRD) | 49 | 80 |
| Control parameters (CTL) | none | 79 FedRAMP NIST parameter/guidance entries |
| `fka` fields | yes | none |

Family moves: ADS to CDS, FSI to AFC, UCM to CMU, PVA to IVV (and VDR-TFR-MVX/NMV), ICP to IEC,
VDR evaluation and reporting rules to VER, CCM agency rules to AGU, KSI-CSX process rules to
FRC/SDR. The KSI-AFR family was removed: each "follow the X process" indicator is now the FRR
family X itself. The four CED training KSIs merged into KSI-CED-RAT; KSI-IAM-MFA merged into
KSI-IAM-APM; KSI-SVC-SNT into KSI-SVC-SIN.

## The legacy-ID crosswalk

`src/fedramp_20x_mcp/rules_data/legacy-crosswalk.json` (372 entries), built by
`scripts/build_rules_crosswalk.py`, lets old IDs still resolve (`get_control("KSI-IAM-01")` returns
KSI-IAM-APM) and drove the repo-wide rewrite (`scripts/migrate_rule_ids.py`).

**FedRAMP publishes no crosswalk to CR26.** Each entry therefore records how it was derived:

| basis | count | confidence | meaning |
|---|---|---|---|
| `fka` | 108 | high | Legacy numbered ID to a 2025 named ID that survives unchanged in CR26; the first hop is FedRAMP's own `fka` field |
| `renamed` | 180 | high | Same rule under a new family/subgroup with the same code and matching text, or a reviewed rename |
| `merged` | 12 | high | Several old indicators folded into one CR26 indicator whose statement covers them |
| `family-successor` | 20 | medium | KSI-AFR-* indicator mapped to the FRR family that replaced it; `current_family` names it |
| `renamed-by-text` | 4 | medium | No code match; statement text similarity 0.6 or higher |
| `related` | 48 | low | **No single successor.** Target is the nearest CR26 rule. Do not treat as a rename |

The `related` set is where an assessor should look first. It covers the ICP incident-reporting
rules (now restructured as IEC-CSO-IIR/OIR/FIR), the PVA third-party assessment procedure rules
(now IVV-IAS-*), and a few ADS/VDR agency rules that CR26 dropped or folded into AGU.

## Where the rules come from at runtime

1. In-memory and on-disk cache (the cache carries a format version; older caches are ignored)
2. `FEDRAMP_RULES_FILE`, or a live fetch of `FEDRAMP_RULES_URL` (default FedRAMP/rules `main`)
3. Stale cache
4. The bundled snapshot in `rules_data/`

Every load records `source`, `version`, `last_updated` and `sha256`, which the scanner writes to
`run.json` so stored evidence names the exact rules release it was evaluated against. Set
`FEDRAMP_RULES_OFFLINE=1` for reproducible, network-free runs against the bundled snapshot.

Documentation tools now read the CR26 site content from `FedRAMP/2026` (`content/`, 82 files),
keyed by relative path (`providers/20x/index.md`); a bare unique filename still works.

## Guardrails

`tests/test_rules_alignment.py` fails when:

- a pattern, prompt, template, example or pipeline cites a rule/KSI ID that is not in the bundled CR26 snapshot;
- a crosswalk target does not exist, or a crosswalk key is a current ID;
- the evidence upload template can overwrite, use keys/SAS, or stops being blocking by default;
- the scanner stops recording the rules version and sha256.

When FedRAMP publishes a new version, follow the "Keeping the rules current" steps in
[CI-CD-INTEGRATION.md](CI-CD-INTEGRATION.md).
