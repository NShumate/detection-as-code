import subprocess

import pytest

TARGET = "splunk"
PIPELINE = "splunk_windows"  # change to match `sigma list pipelines`

# rule file -> text that MUST appear in the converted query
EXPECTED = {
    "rules/execution/powershell_encoded_command.yml": "EncodedCommand",
    "rules/persistence/new_local_user_created.yml": "4720",
    "rules/persistence/scheduled_task_created_via_schtasks.yml": "schtasks",
    "rules/defense_evasion/certutil_used_to_download_file.yml": "urlcache",
    "rules/defense_evasion/security_log_cleared.yml": "1102",
}


@pytest.mark.parametrize("rule,needle", EXPECTED.items())
def test_converts_and_contains(rule, needle):
    result = subprocess.run(
        ["sigma", "convert", "-t", TARGET, "-p", PIPELINE, rule],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert needle.lower() in result.stdout.lower()
