# Detection as Code

This repository contains Sigma detection rules and validation tests for Windows security monitoring.

## Purpose

The goal is to keep detection logic in version-controlled YAML files, validate it automatically, and convert it for downstream SIEM platforms such as Splunk.

## Repository structure

- [rules](rules): Sigma rule files grouped by ATT&CK tactic and technique.
- [tests](tests): validation and conversion smoke tests.
- [.github/workflows/ci.yml](.github/workflows/ci.yml): GitHub Actions workflow for linting, validation, and test execution.

## Included detections

- PowerShell encoded command execution
- New local user creation
- Scheduled task creation via schtasks
- Certutil file download behavior
- Security log clearing

## Quick start

1. Install dependencies:
   pip install -r requirements.txt

2. Validate all Sigma rules:
   sigma check rules/

3. Run tests:
   pytest -v

4. Convert to Splunk:
   sigma convert -t splunk -p splunk_windows rules/ -o out/rules.txt

## CI

GitHub Actions runs on every push and pull request to validate the Sigma syntax, lint YAML, execute the test suite, and generate converted output.

## Notes

This project follows a simple detection-engineering workflow:

- write a rule
- validate schema and metadata
- test behavior in code
- convert for SIEM consumption
- merge only when CI is green
