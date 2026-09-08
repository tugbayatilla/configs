# trivyignore-cli

Build Docker images, scan them with [Trivy](https://trivy.dev), and append new
findings to a Trivy ignore file — deduplicated, comment preserving, idempotent.

This is the reusable version of the "scan every Dockerfile and top up
`.trivyignore.yaml`" shell script most projects end up copy-pasting. Dockerfile
locations differ per repo, so the CLI discovers them automatically and lets you
override when discovery guesses wrong.

## Install

Run without installing:

```bash
uvx --from git+https://github.com/YOU/trivyignore-cli trivyignore
```

Install as a persistent tool:

```bash
uv tool install git+https://github.com/YOU/trivyignore-cli
```

From a local checkout:

```bash
uv tool install .        # or: uv sync --extra dev  for development
```

Requires Python 3.11+, plus `docker` and `trivy` on `PATH`.

## Usage

```bash
# Discover every Dockerfile in the repo, scan for HIGH, update .trivyignore.yaml
trivyignore

# See what would be scanned, without building
trivyignore --list

# Pick Dockerfiles explicitly
trivyignore -f deploy/open-webui/manifests/Dockerfile \
            -f deploy/postgres/manifests/Dockerfile

# Build context defaults to the Dockerfile's directory; override per file
trivyignore -f services/api/Dockerfile:.

# ...or for all targets at once
trivyignore --context .

# Scan an image that is already built
trivyignore --image ghcr.io/acme/api:1.4.2

# Widen severity
trivyignore --severity HIGH,CRITICAL
trivyignore --severity ALL

# Preview without writing
trivyignore --dry-run
```

### Discovery

By default the CLI walks the repository root (the git top level, else the
current directory) looking for `Dockerfile`, `Dockerfile.*`, `*.Dockerfile` and
`Containerfile`. It skips `.git`, `node_modules`, `vendor`, `dist`, `.venv` and
friends, skips `testdata/`, `fixtures/` and `examples/`, and skips anything
git ignores.

Adjust it:

```bash
trivyignore --pattern 'Dockerfile.prod'     # only these names
trivyignore --exclude 'legacy/**'           # skip a subtree
trivyignore --no-gitignore                  # include git-ignored Dockerfiles
```

Passing `-f/--file` disables discovery entirely.

## CI

`--check` never writes; it exits `2` when a scan turns up something not already
in the ignore file, so a pipeline fails when new vulnerabilities appear:

```yaml
- run: trivyignore --check --severity HIGH,CRITICAL
```

Exit codes: `0` clean, `1` error, `2` new findings (with `--check`).

## Ignore file handling

Entries are merged line by line rather than through a YAML round trip, so
existing comments, ordering, `statement:` and `expired_at:` fields survive
untouched. New IDs are appended to the end of their section:

```yaml
# reviewed 2024-01-01 by security
vulnerabilities:
  - id: CVE-2021-1111
    statement: not reachable in our config
    expired_at: 2030-01-01
  - id: CVE-2024-4444 # HIGH   <- appended by the CLI
```

Findings are routed to the right section — `vulnerabilities`,
`misconfigurations`, `secrets` or `licenses` — depending on which Trivy scanner
produced them. The legacy flat `.trivyignore` format (one ID per line) is
detected from the filename and supported too.

Re-running is a no-op when nothing new is found.

## Configuration

Optional. Put `.trivyignore-cli.toml` in the repo root, or a
`[tool.trivyignore]` table in `pyproject.toml`. Keys mirror the flags; command
line arguments always win.

```toml
files = [
  "deploy/open-webui/manifests/Dockerfile",
  "deploy/postgres/manifests/Dockerfile",
]
severity = "HIGH,CRITICAL"
ignore_file = ".trivyignore.yaml"
ignore_unfixed = true
scanners = "vuln,secret"
```

## Options

| Flag | Description |
| --- | --- |
| `-f, --file DOCKERFILE[:CONTEXT]` | Dockerfile to build; repeatable. Disables discovery. |
| `--image IMAGE` | Scan an existing image instead of building; repeatable. |
| `-C, --context DIR` | Build context for all targets. |
| `--root DIR` | Repository root. Defaults to the git top level. |
| `--pattern GLOB` / `--exclude GLOB` | Tune discovery. |
| `--no-gitignore` | Include Dockerfiles that git ignores. |
| `-s, --severity LEVELS` | Severities to record, or `ALL`. Default `HIGH`. |
| `--scanners LIST` | Trivy scanners, e.g. `vuln,secret,misconfig`. |
| `--ignore-unfixed` | Only record findings that have a fix. |
| `--timeout DURATION` | Trivy timeout, e.g. `10m`. |
| `--trivy-arg ARG` | Pass an extra argument through to trivy; repeatable. |
| `-o, --ignore-file PATH` | Ignore file to update. |
| `--format yaml\|plain\|auto` | Ignore file format. |
| `--no-comment` | Omit the trailing `# SEVERITY` comment. |
| `-n, --dry-run` | Print the result without writing. |
| `--check` | Never write; exit 2 on new findings. |
| `--list` | Show resolved targets and exit. |
| `--config PATH` / `--no-config` | Control config loading. |
| `--pull` / `--no-cache` | Passed through to `docker build`. |
| `--keep-images` | Keep the temporary `trivyscan/*` images. |
| `--build-output` | Stream docker build output. |
| `--keep-going` | Continue after a target fails. |
| `-q, --quiet` | Only report errors. |

## Development

```bash
uv sync --extra dev
uv run pytest
```
