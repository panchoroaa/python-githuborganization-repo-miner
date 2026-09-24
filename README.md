# Python Miner

A GitHub organization vulnerability miner that uses CodeQL to perform automated security analysis on all repositories of a GitHub organization, and [Syft](https://github.com/anchore/syft) to generate a Software Bill of Materials (SBOM) for each repository.

## Overview

This tool automates the process of:

1. Fetching all repositories from a GitHub organization via the GitHub REST API
2. Cloning each repository locally
3. Running CodeQL security analysis
4. Generating a CycloneDX JSON SBOM per repository with Syft (either during a scan or standalone, reusing existing clones)
5. Consolidating all results into a single, structured JSON report

## Prerequisites

- Python 3.10 or higher
- [CodeQL CLI](https://codeql.github.com/docs/codeql-cli/) installed and available in your PATH
- [Syft](https://github.com/anchore/syft) installed and available in your PATH (see [Installing Syft](#installing-syft)); only needed for SBOM generation
- Git installed
- A GitHub personal access token

## Installation

```powershell
# Clone the repository
git clone <repository-url>
cd python-miner

# Create and activate virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows PowerShell
# source .venv/bin/activate   # macOS/Linux

# Install the project in development mode
pip install -e ".[dev]"
```

## Installing Syft

Syft is an external CLI (Go binary) from [Anchore](https://github.com/anchore/syft). The miner calls it through `subprocess`, exactly like CodeQL, so it must be installed and available in your `PATH`.

**Windows (winget):**

```powershell
winget install anchore.syft
```

**Windows/macOS/Linux (Scoop):**

```powershell
scoop install syft
```

**macOS (Homebrew):**

```bash
brew install syft
```

**Linux/macOS (official install script, see the [Syft docs](https://github.com/anchore/syft#installation)):**

```bash
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
```

Verify the installation:

```powershell
syft version
```

> **Note:** Only needed for SBOM generation. `miner scan` still runs CodeQL analysis if Syft is missing, but skips SBOMs with a warning.

## Configuration

### GitHub Token

The miner requires a GitHub personal access token to authenticate API requests.

Create a `.env` file in the project root (do not commit this file):

```
GITHUB_TOKEN=ghp_your_token_here
```

The token is **loaded automatically** from the `.env` file — no need to set environment variables manually. You can also set it as an environment variable if you prefer:

```powershell
# Windows PowerShell
$env:GITHUB_TOKEN = "ghp_your_token_here"

# macOS/Linux
export GITHUB_TOKEN="ghp_your_token_here"
```

> **Required scopes for the token:** `public_repo` (public repos only) or `repo` (public + private repos).

**Important:** Never commit your token to version control. The `.gitignore` already excludes `.env` files.

### CodeQL Query Packs

The miner needs CodeQL query packs to run security analyses. There are two ways to provide them:

**Option A — Local query repository (recommended):**

Clone the [codeql/queries](https://github.com/github/codeql) repository:

```powershell
git clone https://github.com/github/codeql ~/codeql-repo
```

The miner **auto-detects** the packs at these locations (in order):

1. `CODEQL_PACK_ROOT` environment variable
2. `~/cybersec/codeql-repo`
3. `~/codeql-repo`
4. `./codeql-repo` (current directory)

You can also pass the path explicitly with `--packs-root`:

```powershell
miner scan --organization example-org -O results.json --packs-root C:\path\to\codeql-repo
```

**Option B — Registry packs:**

Download packs from the GitHub Container Registry (requires a token with `read:packages` scope):

```powershell
codeql pack download codeql/python-security-extended
codeql pack download codeql/java-security-extended
codeql pack download codeql/javascript-security-extended
# ... and other languages as needed
```

## Usage

The CLI has two commands:

- `miner scan ...` — CodeQL security analysis (and SBOM generation, if Syft is installed)
- `miner sbom ...` — SBOM-only generation over already-cloned repositories (no CodeQL)

> **Note:** With more than one command registered, Typer requires the subcommand name (`miner scan ...`, `miner sbom ...`). Earlier versions of this project flattened the single command as `miner --organization ...`; that invocation no longer works.

### Scan an entire organization

```powershell
miner scan --organization <org-name> -O results.json
```

### Scan a single repository

```powershell
miner scan --repo <org>/<repo> -O results.json
```

### Generate SBOMs only (reuse cloned repositories)

`miner sbom` runs Syft over repositories that are **already cloned** in a working directory, without repeating the CodeQL analysis. It writes one CycloneDX JSON file per repository plus a general JSON report:

```powershell
miner sbom --organization <org-name> --workdir repos --output-dir sbom-output
```

To reuse the clones produced by `miner scan`, run `scan` with a persistent `--workdir` (clones are kept there and not deleted after the scan). Then:

```powershell
# 1) Scan + CodeQL + SBOMs; clones kept in ./repos
miner scan --organization <org-name> --workdir repos -O results.json

# 2) Later, regenerate SBOMs only, reusing the clones
miner sbom --organization <org-name> --workdir repos --output-dir sbom-output
```

A single repository can also be processed with `--repo`:

```powershell
miner sbom --repo OWASP/NodeGoat --workdir repos --output-dir sbom-output
```

Repositories that were not cloned (missing in `--workdir`) are reported with status `failed` ("Repository not cloned ...") and processing continues with the rest.

> **Note:** Re-running `scan` against the same `--workdir` works fine — each repository is re-cloned from scratch before analysis.

### Options — `miner scan`

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--organization` | `-o` | GitHub organization name | - |
| `--repo` | `-r` | Single repository to scan (e.g. `OWASP/NodeGoat`) | - |
| `--output` | `-O` | Output JSON file path | `results.json` |
| `--workdir` | `-w` | Working directory for clones and databases. Clones are **kept** when provided, deleted when omitted (temp dir) | System temp directory |
| `--packs-root` | `-p` | Path to local CodeQL query packs | Auto-detected |
| `--sbom-dir` | | Directory where per-repo SBOM files are written | `sboms` |

### Options — `miner sbom`

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--organization` | `-o` | GitHub organization name | - |
| `--repo` | `-r` | Single repository (e.g. `OWASP/NodeGoat`) | - |
| `--workdir` | `-w` | Directory containing already-cloned repositories | `repos` |
| `--output-dir` | `-O` | Output directory for SBOM files and the report | `sbom-output` |

> At least one of `--organization` or `--repo` is required for both commands.

### Examples

```powershell
# (1) Scan all repos in an organization (CodeQL + SBOMs)
miner scan --organization pallets -O results.json

# (2) Scan a single repository
miner scan --repo OWASP/NodeGoat -O nodegoat.json

# (3) Single repo with explicit organization, keeping clones for later reuse
miner scan --organization OWASP --repo NodeGoat -O nodegoat.json -w repos --sbom-dir sboms

# (4) SBOM-only generation, reusing the clones from (3)
miner sbom --organization OWASP --repo NodeGoat --workdir repos --output-dir sbom-output

# (5) SBOM-only generation for a whole organization, reusing existing clones
miner sbom --organization pallets --workdir repos --output-dir sbom-output

# (6) With a specific working directory and packs root
miner scan --organization expressjs -O results.json -w C:\work\miner-temp --packs-root C:\codeql-repo
```

> **Windows paths with spaces:** Quote paths that contain spaces:
> ```powershell
> miner scan --organization pallets -O results.json -w "C:\Users\John Doe\work"
> ```

The tool will display progress in the terminal, showing which repository is being processed and its analysis status.

### Example terminal output

**Organization scan (`miner scan`):**
```
Using CodeQL packs from: C:\Users\you\codeql-repo
SBOMs will be written to: sboms
Found 17 repositories.
  flask: analyzed
  flask-sqlalchemy: analyzed
  jinja: analyzed
  click: analyzed
  ...
Results written to results.json
```

**Single repo scan:**
```
Using CodeQL packs from: C:\Users\you\codeql-repo
SBOMs will be written to: sboms
Scanning single repository: OWASP/NodeGoat
  NodeGoat: analyzed
Results written to nodegoat.json
```

**SBOM-only run (`miner sbom`):**
```
Generating SBOM for repository: OWASP/NodeGoat
  OWASP/NodeGoat: success
SBOM report written to sbom-output\sbom-report.json
```

## Output Format

### Scan results (`miner scan`)

The output JSON (`-O results.json`) contains:

- **organization**: The analyzed organization name
- **summary**: Aggregate statistics (total repos, analyzed, failed, findings count)
- **repositories**: Array of repository results, each containing:
  - `name`, `url`, `status`, `languages`
  - `findings`: Array of vulnerabilities with `rule_id`, `severity`, `message`, `file`, `start_line`
  - `sbom`: SBOM metadata for the repository (when Syft is installed), with `full_name`, `commit`, `generated_at`, `syft_version`, `status`, `components`, `sbom_path`
  - `error_message`: Present when status indicates failure

Repositories are sorted alphabetically. Findings within each repository are sorted by file, line, and rule ID.

### Example JSON structure (scan)

```json
{
  "organization": "pallets",
  "summary": {
    "repositories": 17,
    "analyzed": 13,
    "clone_failed": 0,
    "unsupported": 4,
    "database_failed": 0,
    "analysis_failed": 0,
    "findings": 42
  },
  "repositories": [
    {
      "name": "flask",
      "url": "https://github.com/pallets/flask",
      "status": "analyzed",
      "languages": ["Python"],
      "findings": [
        {
          "rule_id": "py/sql-injection",
          "severity": "warning",
          "message": "Constructed SQL query from user input",
          "file": "src/flask/app.py",
          "start_line": 123,
          "end_line": null,
          "code_snippet": "cursor.execute(query)"
        }
      ],
      "sbom": {
        "full_name": "pallets/flask",
        "commit": "d73fa1cdcbd8b1465c151db8924ba58b1dd14e35",
        "generated_at": "2026-09-24T14:45:26.096207Z",
        "syft_version": "1.51.0",
        "status": "success",
        "components": 122,
        "sbom_path": "C:\\path\\to\\sboms\\flask.cdx.json",
        "error_message": null
      }
    }
  ]
}
```

### Repository statuses (scan)

| Status | Meaning |
|--------|---------|
| `analyzed` | Successfully analyzed with CodeQL |
| `clone_failed` | Could not clone the repository (network error, auth required, etc.) |
| `unsupported_language` | No CodeQL-supported languages found in the repository |
| `database_failed` | CodeQL could not create a database for this repository |
| `analysis_failed` | CodeQL analysis crashed or produced an error |

### SBOM output files (`miner scan --sbom-dir` / `miner sbom --output-dir`)

Every repository with a working clone gets one independent CycloneDX JSON file:

```
sbom-output/
├── sbom-report.json            # General (aggregated) SBOM report
└── sboms/
    ├── NodeGoat.cdx.json       # CycloneDX JSON SBOM, one per repository
    └── flask.cdx.json
```

- **`<name>.cdx.json`** — the original Syft SBOM in CycloneDX JSON format (spec `1.5+`). It contains `metadata.component` (the repository itself) and a `components` array with the identified packages (name, version, `purl`, licenses when resolvable).
- **`sbom-report.json`** — the general results JSON. Per repository it records: `full_name` (org/repo), `commit` analyzed (HEAD of the clone), `generated_at`, `syft_version`, `status`, `components` (count), and `sbom_path`. The original SBOM file is kept independent; only the metadata is embedded in the report.

### Example JSON structure (SBOM report)

```json
{
  "organization": "OWASP",
  "generated_at": "2026-09-24T14:43:55.787222+00:00",
  "syft_version": "1.51.0",
  "summary": {
    "repositories": 1,
    "success": 1,
    "no_components": 0,
    "failed": 0,
    "components": 419
  },
  "repositories": [
    {
      "full_name": "OWASP/NodeGoat",
      "commit": "c5cb68a7084e4ae7dcc60e6a98768720a81841e8",
      "generated_at": "2026-09-24T14:43:54.188461Z",
      "syft_version": "1.51.0",
      "status": "success",
      "components": 419,
      "sbom_path": "C:\\Users\\you\\sbom-output\\sboms\\NodeGoat.cdx.json",
      "error_message": null
    }
  ]
}
```

### SBOM statuses

| Status | Meaning |
|--------|---------|
| `success` | Syft ran successfully and identified at least one component |
| `no_components` | Syft ran successfully but no components were identified (a valid result, **not** a failure) |
| `failed` | The repository was not cloned, Syft is not available, or Syft crashed; details in `error_message` |

> A repository whose clone is missing is reported as `failed` with `"Repository not cloned at ..."` and the run continues with the remaining repositories.

## Complete usage example

```powershell
# 1. Verify prerequisites
syft version          # e.g. 1.51.0
codeql version        # e.g. 2.26.4
git version

# 2. Scan an organization: CodeQL + SBOMs, clones kept in ./repos
miner scan --organization OWASP --repo NodeGoat -w repos -O nodegoat.json --sbom-dir sboms

# 3. Inspect the outputs
#    - nodegoat.json                 : CodeQL findings + SBOM metadata
#    - sboms\NodeGoat.cdx.json       : CycloneDX JSON SBOM (independent file)
#    - (grep "components" for the component count)

# 4. Later, regenerate the SBOMs only — no CodeQL, reusing ./repos
miner sbom --organization OWASP --repo NodeGoat --workdir repos --output-dir sbom-output

# 5. Inspect the SBOM-only report
#    - sbom-output\sbom-report.json  : aggregated report (commit, syft version, status, count, path)
#    - sbom-output\sboms\NodeGoat.cdx.json : the new CycloneDX JSON SBOM
```

## Verification notes (observed differences)

The inventory depends on the files available in the repository and on what Syft can identify. We verified the tool against:

- **OWASP/NodeGoat** (JavaScript, has `package.json` + `package-lock.json`): the SBOM listed **419 components** and **all 16 direct dependencies** from `package.json` (e.g. `express@4.16.4`, `mongodb@2.2.36`) with versions matching the lockfile. Syft also cataloged the GitHub Actions references from `.github/workflows/*` (e.g. `actions/checkout@v2`). Of the 658 top-level entries in the lockfile, 301 ended up as npm components; most omitted entries are dev/test tooling (e.g. `@types/*`, cypress-related packages, `ajv`/`lodash` transitive entries). The count does not match the raw lockfile entry count: Syft catalogs what its npm cataloger can resolve and deduplicates.
- **pallets/flask** (Python, `pyproject.toml`, no lockfile): the SBOM listed **122 components** (105 PyPI) and **all 6 direct dependencies** (`blinker`, `click`, `itsdangerous`, `jinja2`, `markupsafe`, `werkzeug`). Because there is no lockfile, versions come from declared constraints across different files, which can produce **multiple version entries per package** (e.g. `werkzeug` appeared as 2.3.3 and 3.1.8) rather than a single resolved version.

In short: with lockfiles the SBOM is precise for what the cataloger resolves; without them, versions reflect the declared constraints and may be duplicated or non-specific. Files such as vendored binaries, or dependencies declared only in documentation/CI, may not be included.

## Why it won't work out of the box

Installing the dependencies alone (`pip install -e ".[dev]"`) is **not enough**. The miner only orchestrates external tools, so a fresh clone will fail until you set up all prerequisites.

| Missing piece | Symptom |
|---------------|---------|
| `GITHUB_TOKEN` not set (no `.env` file) | `RuntimeError: GITHUB_TOKEN environment variable is not set.` |
| CodeQL CLI not installed or not in `PATH` | `FileNotFoundError` or `codeql: command not found` |
| No query packs available | `Query suite not found at .../codeql-suites/python-security-extended.qls` |
| Syft not installed or not in `PATH` | `miner sbom` exits with `Syft not found in PATH`; `miner scan` skips SBOMs with a warning |
| Git not installed | Every repo is reported as `clone_failed` |

**Full checklist before running a scan:**

1. `.env` file exists with `GITHUB_TOKEN=ghp_...` (see [GitHub Token](#github-token)).
2. `codeql version` works from your terminal.
3. Query packs are available — either a local `codeql-repo` clone (auto-detected) or packs downloaded from the registry.
4. `syft version` works from your terminal (only if you want SBOMs).
5. `git version` works from your terminal.

If all are met, `miner scan --organization <org-name> -O results.json` or `miner scan --repo <org>/<repo> -O results.json` should produce a valid JSON report, and `miner sbom --organization <org-name> --workdir repos --output-dir sbom-output` should produce the SBOM report.

## Running Tests

```powershell
pytest
```

## Project Structure

```
python-miner/
├── pyproject.toml
├── .gitignore
├── .env.example
├── README.md
├── src/
│   └── miner/
│       ├── __init__.py
│       ├── cli.py          # Typer CLI interface (scan + sbom commands)
│       ├── models.py        # Pydantic data models
│       ├── github.py        # GitHub API interaction
│       ├── git_ops.py       # Git clone operations
│       ├── codeql.py        # CodeQL CLI wrapper
│       ├── syft.py          # Syft CLI wrapper (SBOM generation)
│       └── sarif.py         # SARIF file parsing
└── tests/
    ├── test_models.py
    ├── test_sarif.py
    ├── test_syft.py
    ├── test_sbom_helpers.py
    └── test_github.py
```

## License

MIT
