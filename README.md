# Detection as Code

[![CI](https://github.com/NShumate/detection-as-code/actions/workflows/ci.yml/badge.svg)](https://github.com/NShumate/detection-as-code/actions/workflows/ci.yml)

This repository contains Sigma detection rules and validation tests for Windows security monitoring.

## Why this repo exists

Security detections should be treated like code: versioned, reviewed, tested, and validated before they are used in production. This project keeps detection content in YAML files, enforces required metadata, runs automated tests, and converts the rules to a SIEM-friendly format for use in Splunk.

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
   ```bash
   pip install -r requirements.txt
   ```

2. Validate all Sigma rules:
   ```bash
   sigma check rules/
   ```

3. Run tests:
   ```bash
   pytest -v
   ```

4. Convert to Splunk:
   ```bash
   sigma convert -t splunk -p splunk_windows rules/ -o out/rules.txt
   ```

## Screenshot section

The project is designed around a simple red-to-green workflow common in detection engineering:

- a rule is introduced or modified
- CI runs validation and tests
- a PR is reviewed and merged only when checks pass
- the converted output is generated for downstream detection use

![GitHub repository view](https://github.com/NShumate/detection-as-code/raw/master/.github/images/repo-preview.png)

## Sample Splunk conversion output

Example output produced by the conversion step:

```text
"select * from process_creation where image_path endswith 'powershell.exe' and command_line contains 'EncodedCommand'" 
```

## CI

GitHub Actions runs on every push and pull request to validate the Sigma syntax, lint YAML, execute the test suite, and generate converted output.

## Notes

This project follows a simple detection-engineering workflow:

- write a rule
- validate schema and metadata
- test behavior in code
- convert for SIEM consumption
- merge only when CI is green
