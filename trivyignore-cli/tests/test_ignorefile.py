from pathlib import Path

from trivyignore_cli.ignorefile import IgnoreFile, detect_format
from trivyignore_cli.models import Finding


def vuln(id_: str, severity: str = "HIGH") -> Finding:
    return Finding(id=id_, severity=severity)


def test_detect_format():
    assert detect_format(Path(".trivyignore.yaml")) == "yaml"
    assert detect_format(Path(".trivyignore.yml")) == "yaml"
    assert detect_format(Path(".trivyignore")) == "plain"


def test_load_missing_file_starts_empty(tmp_path):
    ig = IgnoreFile.load(tmp_path / ".trivyignore.yaml")
    assert ig.all_ids() == set()
    assert ig.lines == []


def test_parses_existing_ids(tmp_path):
    path = tmp_path / ".trivyignore.yaml"
    path.write_text(
        "vulnerabilities:\n"
        "  - id: CVE-2021-1111 # HIGH\n"
        "  - id: CVE-2022-2222\n"
    )
    ig = IgnoreFile.load(path)
    assert ig.ids["vulnerabilities"] == {"CVE-2021-1111", "CVE-2022-2222"}


def test_parses_bare_entries(tmp_path):
    path = tmp_path / ".trivyignore.yaml"
    path.write_text("vulnerabilities:\n  - CVE-2021-1111\n")
    ig = IgnoreFile.load(path)
    assert ig.ids["vulnerabilities"] == {"CVE-2021-1111"}


def test_add_is_deduplicated(tmp_path):
    path = tmp_path / ".trivyignore.yaml"
    path.write_text("vulnerabilities:\n  - id: CVE-2021-1111 # HIGH\n")
    ig = IgnoreFile.load(path)
    assert ig.add(vuln("CVE-2021-1111")) is False
    assert ig.add(vuln("CVE-2023-3333")) is True
    assert len(ig.added) == 1


def test_add_creates_section_when_missing(tmp_path):
    path = tmp_path / ".trivyignore.yaml"
    ig = IgnoreFile.load(path)
    ig.add(vuln("CVE-2023-3333"))
    assert ig.render() == "vulnerabilities:\n  - id: CVE-2023-3333 # HIGH\n"


def test_preserves_comments_and_extra_fields(tmp_path):
    path = tmp_path / ".trivyignore.yaml"
    original = (
        "# reviewed 2024-01-01 by security\n"
        "vulnerabilities:\n"
        "  - id: CVE-2021-1111\n"
        "    statement: false positive, not reachable\n"
        "    expired_at: 2030-01-01\n"
    )
    path.write_text(original)
    ig = IgnoreFile.load(path)
    ig.add(vuln("CVE-2024-4444"))
    out = ig.render()

    assert out.startswith("# reviewed 2024-01-01 by security\n")
    assert "statement: false positive, not reachable" in out
    assert "expired_at: 2030-01-01" in out
    # new entry lands at the end of its section, after the extra fields
    assert out.splitlines()[-1] == "  - id: CVE-2024-4444 # HIGH"


def test_entry_goes_into_correct_section(tmp_path):
    path = tmp_path / ".trivyignore.yaml"
    path.write_text(
        "vulnerabilities:\n"
        "  - id: CVE-2021-1111\n"
        "misconfigurations:\n"
        "  - id: AVD-AWS-0001\n"
    )
    ig = IgnoreFile.load(path)
    ig.add(Finding(id="AVD-AWS-0002", severity="HIGH", kind="misconfigurations"))
    ig.add(vuln("CVE-2022-2222"))
    lines = ig.render().splitlines()

    assert lines == [
        "vulnerabilities:",
        "  - id: CVE-2021-1111",
        "  - id: CVE-2022-2222 # HIGH",
        "misconfigurations:",
        "  - id: AVD-AWS-0001",
        "  - id: AVD-AWS-0002 # HIGH",
    ]


def test_same_id_in_two_sections_is_not_confused(tmp_path):
    path = tmp_path / ".trivyignore.yaml"
    ig = IgnoreFile.load(path)
    assert ig.add(Finding(id="X-1", severity="HIGH", kind="vulnerabilities")) is True
    assert ig.add(Finding(id="X-1", severity="HIGH", kind="secrets")) is True


def test_indentation_is_preserved(tmp_path):
    path = tmp_path / ".trivyignore.yaml"
    path.write_text("vulnerabilities:\n    - id: CVE-2021-1111\n")
    ig = IgnoreFile.load(path)
    ig.add(vuln("CVE-2022-2222"))
    assert ig.render().splitlines()[-1] == "    - id: CVE-2022-2222 # HIGH"


def test_no_comment_option(tmp_path):
    ig = IgnoreFile.load(tmp_path / ".trivyignore.yaml")
    ig.add(vuln("CVE-2021-1111"), comment=False)
    assert ig.render() == "vulnerabilities:\n  - id: CVE-2021-1111\n"


def test_plain_format_roundtrip(tmp_path):
    path = tmp_path / ".trivyignore"
    path.write_text("# legacy\nCVE-2021-1111\n")
    ig = IgnoreFile.load(path)
    assert ig.ids["vulnerabilities"] == {"CVE-2021-1111"}
    assert ig.add(vuln("CVE-2021-1111")) is False
    ig.add(vuln("CVE-2022-2222"))
    assert ig.render() == "# legacy\nCVE-2021-1111\nCVE-2022-2222 # HIGH\n"


def test_save_writes_trailing_newline(tmp_path):
    path = tmp_path / ".trivyignore.yaml"
    ig = IgnoreFile.load(path)
    ig.add(vuln("CVE-2021-1111"))
    ig.save()
    assert path.read_text().endswith("\n")
    assert not list(tmp_path.glob("*.tmp"))


def test_file_without_trailing_newline_is_handled(tmp_path):
    path = tmp_path / ".trivyignore.yaml"
    path.write_text("vulnerabilities:\n  - id: CVE-2021-1111")
    ig = IgnoreFile.load(path)
    ig.add(vuln("CVE-2022-2222"))
    assert ig.render() == (
        "vulnerabilities:\n  - id: CVE-2021-1111\n  - id: CVE-2022-2222 # HIGH\n"
    )


def test_reload_after_save_is_stable(tmp_path):
    path = tmp_path / ".trivyignore.yaml"
    ig = IgnoreFile.load(path)
    ig.add(vuln("CVE-2021-1111"))
    ig.add(Finding(id="AVD-1", severity="HIGH", kind="misconfigurations"))
    ig.save()

    again = IgnoreFile.load(path)
    assert again.ids["vulnerabilities"] == {"CVE-2021-1111"}
    assert again.ids["misconfigurations"] == {"AVD-1"}
    assert again.add(vuln("CVE-2021-1111")) is False
