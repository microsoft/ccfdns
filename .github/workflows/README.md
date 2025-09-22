Documents the various GitHub Actions workflows, the role they fulfil and 3rd party dependencies if any.

# Continuous Integration

Main continuous integration job. Builds CCF DNS for all target platforms, runs unit and end to end tests. Run on every commit, including PRs from forks, gates merging. Also runs once a week, regardless of commits.

File: `ci.yml`
3rd party dependencies: None

# CodeQL analysis

Builds CCF with CodeQL, and runs the security-extended checks. Triggered on PRs that affect ".github/workflows/codeql-analysis.yml", and once a week on main.

File: `codeql-analysis.yml`
3rd party dependencies:

- `github/codeql-action/init@v3`
- `github/codeql-action/analyze@v3`
