# CI/CD Integration and Evidence Storage

The server has two usage models over the same rules data and pattern engine:

1. **Interactive** (an MCP client such as Claude Code or VS Code): guidance, rule lookups, code review.
2. **Automated** (pipelines): the `fedramp-20x-scan` command, no MCP client needed.

Both evaluate against the **FedRAMP Consolidated Rules for 2026** (CR26), loaded from
[`FedRAMP/rules`](https://github.com/FedRAMP/rules) with a pinned snapshot bundled in the package
(`src/fedramp_20x_mcp/rules_data/`) as the offline fallback.

## `fedramp-20x-scan`

```bash
pip install -e .                      # editable: the pattern library lives in data/patterns
fedramp-20x-scan . --output-dir fedramp-scan --fail-on high --exclude 'tests/*'
```

| Option | Default | Purpose |
|---|---|---|
| `--fail-on` | `high` | Exit 1 if any issue is at or above `critical`/`high`/`medium`/`low`; `none` never fails |
| `--families` | all | Comma-separated pattern families, e.g. `IAM,SVC,MLA` |
| `--profile` | none | Application profile that removes inapplicable findings (`web-app`, `api-service`, `cli-tool`, ...) |
| `--exclude` | build/vendor dirs | Extra relative-path globs; repeatable |
| `--patterns-dir` | `data/patterns` | Alternate pattern library (also `FEDRAMP_PATTERNS_DIR`) |

Exit codes: `0` pass, `1` gate tripped, `2` tool error.

Outputs in `--output-dir`:

| File | Contents |
|---|---|
| `findings.json` | Findings, summary by severity and requirement, gate result, provenance |
| `report.md` | Human-readable report (also posted to the Azure DevOps build summary) |
| `run.json` | Provenance: tool version, **rules version and sha256**, pattern count, inputs, CI context, timestamps, sha256 of the two outputs |

Some patterns are catch-alls (`regex_fallback: ".*"`): they mark a rule that applies to the
scanned resources but that code cannot show either way, such as the AFC inbox rules or the CED
training indicator. The scanner lists those rules once under `summary.review_reminders` and in the
report's "Rules to review outside code" section; they are not issues and do not trip the gate.
`--include-review-reminders` counts them anyway.

Every finding carries the CR26 rule or KSI ID it informs. `summary.invalid_requirement_ids`
lists any ID that is not in the loaded rules release, which is how rules drift shows up in CI.
Pattern findings are review signals, not a compliance determination.

### Rules source

| Variable | Effect |
|---|---|
| `FEDRAMP_RULES_OFFLINE=1` | Use the bundled snapshot; no network. Reproducible runs. |
| `FEDRAMP_RULES_FILE=path` | Use a local rules JSON (air-gapped mirror). |
| `FEDRAMP_RULES_URL=url` | Use another URL (internal mirror). |
| `GITHUB_TOKEN` | Raises GitHub API limits for documentation fetches. |

## Azure DevOps

Templates in `.azuredevops/templates/`:

| Template | Runs on | Does |
|---|---|---|
| `fedramp-scan-steps.yml` | Microsoft-hosted or self-hosted Linux | Installs the scanner, runs it, publishes the output, then enforces the gate as a separate last step |
| `evidence-upload-steps.yml` | Agent with private-network reach to the evidence account | Stages a directory, writes `run.json`/`pipeline-run.json`/`sha256-manifest.txt`, uploads without overwrite, verifies by listing back |

The gate step runs after the publish step, so a failing scan still produces its report, and the
evidence stage stores failing results as well as passing ones.

Pipelines:

| File | Purpose |
|---|---|
| `.azuredevops/fedramp-compliance-pipeline.yml` | Scans this repo on push, PR and weekly; stores evidence for non-PR runs |
| `examples/azure-devops/scan-and-store-evidence.yml` | Same, for an application repo consuming this repo's templates via `resources.repositories` |
| `examples/azure-devops/ksi-evidence-collection.yml` | Daily read-only Azure Resource Graph collection for selected KSIs (`collect_ksi_evidence.py`), stored as evidence |

### Evidence storage

`evidence-upload-steps.yml` defaults to IntelliGRC's compliance evidence account (managed in
`infra-azure-storage`, `evidence-storage.tf`):

| Setting | Value |
|---|---|
| Account | `intellievidence`: private endpoint only, shared keys disabled, CMK, TLS 1.2 |
| Container | `vdr-reports` (the writer also holds `sbom`, `grype-reports`, `scap-reports`) |
| Immutability | Container-level time-based retention, 1095 days; versioning off, so an existing blob name can never be overwritten |
| Writer | `evidence-writer` WIF service connection: Storage Blob Data Contributor on those containers only |
| Readers | Entra group "Compliance Evidence Read-Only": Storage Blob Data Reader |
| Agent | `intelli-pool-1` (Microsoft-hosted agents cannot reach the private endpoint) |

Blob layout, shared with the IntelliGRC.CRM reports:

```
vdr-reports/<reportName>/<yyyy-MM-dd>/<buildId>-<jobAttempt>/
  findings.json  report.md          # producer output
  run.json                          # producer provenance (rules version + sha256)
  pipeline-run.json                 # pipeline identity: build, commit, branch, requester
  sha256-manifest.txt               # sha256 of every other file
```

Report names in use: `fedramp20x-scan/<repo>`, `fedramp20x-ksi-evidence`.

Rules the template enforces:

- **Entra only.** `az storage blob upload-batch --auth-mode login`; there is no key or SAS path.
- **No overwrite.** `--overwrite` is never passed. A re-run gets a new `<buildId>-<attempt>` folder; a real collision fails the step.
- **Verify the write.** The step lists the prefix back and fails if the blob count differs from what was staged.
- **Blocking by default.** A failed upload fails the job, because evidence that silently failed to store is a gap. `blocking: false` exists only for trialing a new stream.
- **No evidence from PR builds.** PR scans are review feedback.

Prerequisites before the first run with `uploadEvidence: true`:

1. The pipeline is in the **IntelliGRC** Azure DevOps project. Pipelines in the Charles project
   must not reference IntelliGRC service connections, pools or storage; run them with upload off
   or with their own parameters.
2. The pipeline is authorized for `evidence-writer` and `intelli-pool-1`. An unauthorized
   pipeline fails at queue time, not at the upload step.
3. Use `evidenceDryRun: true` (or the template's `dryRun`) on the first run to see the staged
   files and destination without writing.

Outside a pipeline, `examples/azure_evidence_store.py` applies the same layout, manifest,
no-overwrite and verify rules with `DefaultAzureCredential`.

## GitHub Actions

`.github/workflows/fedramp-compliance-check.yml` runs the scanner and publishes the output as an
artifact and job summary. GitHub-hosted runners cannot reach the private evidence account; store
evidence from Azure DevOps.

## Keeping the rules current

FedRAMP updates CR26 in place (`info.version`, e.g. `2026.10.13.01`). The scanner fetches the
live file by default and records the version it used. To move the bundled snapshot forward:

```bash
python scripts/update_rules_snapshot.py            # download, report version and ID changes
python scripts/build_rules_crosswalk.py            # rebuild legacy-ID crosswalk against it
python scripts/migrate_rule_ids.py                 # list stale IDs in the repo (add --apply to fix)
pytest tests/test_rules_alignment.py
```
