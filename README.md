# Python Miner

A GitHub organization vulnerability miner that uses CodeQL to perform automated security analysis on all repositories of a GitHub organization.

## Overview

This tool automates the process of:

1. Fetching all repositories from a GitHub organization via the GitHub REST API
2. Cloning each repository locally
3. Running CodeQL security analysis
4. Consolidating all results into a single, structured JSON report

## Prerequisites

- Python 3.10 or higher
- [CodeQL CLI](https://codeql.github.com/docs/codeql-cli/) installed and available in your PATH
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
miner --organization example-org -O results.json --packs-root C:\path\to\codeql-repo
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

```powershell
miner --organization <org-name> -O results.json
```

> **Note:** There is no `scan` subcommand — the options go directly after `miner`.

### Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--organization` | `-o` | GitHub organization name (required) | - |
| `--output` | `-O` | Output JSON file path | `results.json` |
| `--workdir` | `-w` | Working directory for clones and databases | System temp directory |
| `--packs-root` | `-p` | Path to local CodeQL query packs | Auto-detected |

### Examples

```powershell
# Basic usage (reads token from .env, detects packs automatically)
miner --organization pallets -O results.json

# With a specific working directory and packs root
miner --organization expressjs -O results.json -w C:\work\miner-temp --packs-root C:\codeql-repo
```

> **Windows paths with spaces:** Quote paths that contain spaces:
> ```powershell
> miner --organization pallets -O results.json -w "C:\Users\John Doe\work"
> ```

The tool will display progress in the terminal, showing which repository is being processed and its analysis status.

### Example terminal output

```
Using CodeQL packs from: C:\Users\you\codeql-repo
Found 17 repositories.
  flask: analyzed
  flask-sqlalchemy: analyzed
  jinja: analyzed
  click: analyzed
  ...
Results written to results.json
```

## Output Format

The output JSON contains:

- **organization**: The analyzed organization name
- **summary**: Aggregate statistics (total repos, analyzed, failed, findings count)
- **repositories**: Array of repository results, each containing:
  - `name`, `url`, `status`, `languages`
  - `findings`: Array of vulnerabilities with `rule_id`, `severity`, `message`, `file`, `start_line`
  - `error_message`: Present when status indicates failure

Repositories are sorted alphabetically. Findings within each repository are sorted by file, line, and rule ID.

### Example JSON structure

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
      ]
    }
  ]
}
```

### Repository statuses

| Status | Meaning |
|--------|---------|
| `analyzed` | Successfully analyzed with CodeQL |
| `clone_failed` | Could not clone the repository (network error, auth required, etc.) |
| `unsupported_language` | No CodeQL-supported languages found in the repository |
| `database_failed` | CodeQL could not create a database for this repository |
| `analysis_failed` | CodeQL analysis crashed or produced an error |

## Why it won't work out of the box

Installing the dependencies alone (`pip install -e ".[dev]"`) is **not enough**. The miner only orchestrates external tools, so a fresh clone will fail until you set up all prerequisites.

| Missing piece | Symptom |
|---------------|---------|
| `GITHUB_TOKEN` not set (no `.env` file) | `RuntimeError: GITHUB_TOKEN environment variable is not set.` |
| CodeQL CLI not installed or not in `PATH` | `FileNotFoundError` or `codeql: command not found` |
| No query packs available | `Query suite not found at .../codeql-suites/python-security-extended.qls` |
| Git not installed | Every repo is reported as `clone_failed` |

**Full checklist before running a scan:**

1. `.env` file exists with `GITHUB_TOKEN=ghp_...` (see [GitHub Token](#github-token)).
2. `codeql version` works from your terminal.
3. Query packs are available — either a local `codeql-repo` clone (auto-detected) or packs downloaded from the registry.
4. `git version` works from your terminal.

If all four are met, `miner --organization <org-name> -O results.json` should produce a valid JSON report.

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
│       ├── cli.py          # Typer CLI interface
│       ├── models.py        # Pydantic data models
│       ├── github.py        # GitHub API interaction
│       ├── git_ops.py       # Git clone operations
│       ├── codeql.py        # CodeQL CLI wrapper
│       └── sarif.py         # SARIF file parsing
└── tests/
    ├── test_models.py
    ├── test_sarif.py
    └── test_github.py
```

## License

MIT
