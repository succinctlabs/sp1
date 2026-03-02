---
name: ci-clippy
description: Run the CI clippy and fmt checks (matching the GitHub Actions lint job) and fix any issues found.
allowed-tools: Read, Grep, Glob, Bash, Edit
---

# Run CI Clippy & Fix Issues

Run the same clippy and formatting checks as the CI lint job in `.github/workflows/pr.yml`, then fix any errors.

## Steps

1. Run formatting check:
```
cargo fmt --all -- --check
```

2. Run clippy with the CI flags:
```
cargo clippy --all-features --all-targets -- -D warnings -A incomplete-features
```

3. If either command reports errors, fix them:
   - For fmt issues: run `cargo fmt --all` or manually fix formatting
   - For clippy errors: read the relevant source files, understand the issue, and apply the minimal fix
   - Re-run the failing check to confirm the fix

4. Repeat until both commands pass cleanly.

## Notes

- Warnings from `clippy.toml` about unreachable types (e.g. `slop_koala_bear::*`) are informational and not errors.
- `test-artifacts` build script warnings ("Skipping build due to clippy invocation") are expected.
- The clippy command can take 4-5 minutes on a full rebuild. Use `--timeout 600000` when running via Bash.
