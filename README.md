# VulnFinder

`vulnfinder` is a **defensive** Rust tool for authorized network inventory and vulnerability awareness.

## Build / install

```bash
cargo build --release
# or
cargo install --path crates/vulnfinder-cli
```

## Usage

```bash
vulnfinder scan 192.168.1.10
vulnfinder scan 10.0.0.0/30 --ports "22,80,443" --timeout-ms 1000 --concurrency 100
vulnfinder scan example.com --ports-file ./ports.txt --json --no-ui
```

### Command and flags

`vulnfinder scan <target>`

- `--ports "80,443,22"`
- `--ports-file ./ports.txt`
- `--timeout-ms 800`
- `--concurrency 200`
- `--json`
- `--evidence`
- `--cve-db ./data/cve_db.json`
- `--no-ui`

If `--ports` and `--ports-file` are both omitted, the safe default is:
`22,53,80,443,445,3389`.


## Error handling

The CLI now emits additional guidance for common input errors:

- Unknown flags show a hint to run `vulnfinder scan --help`.
- Invalid values (such as `--timeout-ms 0`) include range hints.
- Missing command/arguments print usage guidance and help text.

## CVE DB format

Default path: `./data/cve_db.json`.

Schema for each entry:

```json
{
  "product": "OpenSSH",
  "version_range": ">=8.0.0,<8.9.0",
  "cve_id": "CVE-2021-41617",
  "cvss": 7.0,
  "summary": "...",
  "references": ["https://..."],
  "remediation": "Upgrade to a patched vendor release"
}
```

Version matching uses semver when possible. For non-semver versions, VulnFinder falls back to simple lexical comparisons with known limitations.

## UI behavior

- TTY + default mode: terminal dashboard with progress, counters, and activity log.
- Non-TTY or `--no-ui`: plain progress lines are printed.

## Test and lint

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --all-targets
```
