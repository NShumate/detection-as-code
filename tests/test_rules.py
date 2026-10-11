from pathlib import Path

import pytest
import yaml

RULES = sorted(Path("rules").rglob("*.yml"))
REQUIRED = [
    "title",
    "id",
    "status",
    "description",
    "logsource",
    "detection",
    "falsepositives",
    "level",
    "tags",
]


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.name)
def test_required_fields(path):
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    for field in REQUIRED:
        assert field in rule, f"{path.name} missing '{field}'"


@pytest.mark.parametrize("path", RULES, ids=lambda p: p.name)
def test_has_attack_tag(path):
    rule = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert any(t.startswith("attack.t") for t in rule["tags"]), (
        f"{path.name} has no ATT&CK technique tag"
    )


def test_unique_ids():
    ids = [yaml.safe_load(p.read_text(encoding="utf-8"))["id"] for p in RULES]
    assert len(ids) == len(set(ids)), "Duplicate rule IDs found"
