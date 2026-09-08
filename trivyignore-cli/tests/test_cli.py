from pathlib import Path

import pytest

from trivyignore_cli import cli
from trivyignore_cli.models import Finding


@pytest.fixture
def project(tmp_path):
    (tmp_path / "deploy/api").mkdir(parents=True)
    (tmp_path / "deploy/api/Dockerfile").write_text("FROM scratch\n")
    return tmp_path


@pytest.fixture
def fake_tools(monkeypatch):
    """Replace docker/trivy with in-process fakes."""
    state = {"builds": [], "scans": [], "removed": [], "findings": []}

    def fake_build(target, root, **kwargs):
        state["builds"].append(target.name)
        return target.tag_for(root)

    def fake_scan(tag, severities, **kwargs):
        state["scans"].append((tag, tuple(severities)))
        return list(state["findings"])

    monkeypatch.setattr(cli, "build_image", fake_build)
    monkeypatch.setattr(cli, "scan_image", fake_scan)
    monkeypatch.setattr(cli, "image_id", lambda tag, **kw: "sha256:abc")
    monkeypatch.setattr(cli, "remove_image", lambda tag, **kw: state["removed"].append(tag))
    return state


def run(args, root: Path) -> int:
    return cli.main(["--root", str(root), *args])


def test_writes_findings_to_new_ignore_file(project, fake_tools):
    fake_tools["findings"] = [Finding(id="CVE-1", severity="HIGH")]
    assert run([], project) == 0
    content = (project / ".trivyignore.yaml").read_text()
    assert content == "vulnerabilities:\n  - id: CVE-1 # HIGH\n"


def test_second_run_is_idempotent(project, fake_tools):
    fake_tools["findings"] = [Finding(id="CVE-1", severity="HIGH")]
    run([], project)
    first = (project / ".trivyignore.yaml").read_text()
    run([], project)
    assert (project / ".trivyignore.yaml").read_text() == first


def test_dry_run_does_not_write(project, fake_tools):
    fake_tools["findings"] = [Finding(id="CVE-1", severity="HIGH")]
    assert run(["--dry-run"], project) == 0
    assert not (project / ".trivyignore.yaml").exists()


def test_check_exits_2_on_new_findings(project, fake_tools):
    fake_tools["findings"] = [Finding(id="CVE-1", severity="HIGH")]
    assert run(["--check"], project) == cli.EXIT_ADDED
    assert not (project / ".trivyignore.yaml").exists()


def test_check_exits_0_when_all_ignored(project, fake_tools):
    (project / ".trivyignore.yaml").write_text("vulnerabilities:\n  - id: CVE-1\n")
    fake_tools["findings"] = [Finding(id="CVE-1", severity="HIGH")]
    assert run(["--check"], project) == 0


def test_default_severity_is_high(project, fake_tools):
    run([], project)
    assert fake_tools["scans"][0][1] == ("HIGH",)


def test_severity_flag(project, fake_tools):
    run(["--severity", "critical,high"], project)
    assert fake_tools["scans"][0][1] == ("HIGH", "CRITICAL")


def test_invalid_severity_errors(project, fake_tools):
    assert run(["--severity", "nope"], project) == cli.EXIT_ERROR


def test_explicit_files_are_used(project, fake_tools):
    (project / "other").mkdir()
    (project / "other/Dockerfile").write_text("FROM scratch\n")
    run(["-f", "other/Dockerfile"], project)
    assert fake_tools["builds"] == [str(project / "other/Dockerfile")]


def test_list_only_does_not_build(project, fake_tools, capsys):
    assert run(["--list"], project) == 0
    assert fake_tools["builds"] == []
    assert "deploy/api/Dockerfile" in capsys.readouterr().out


def test_no_dockerfiles_is_not_an_error(tmp_path, fake_tools):
    assert run([], tmp_path) == 0


def test_missing_dockerfile_fails(project, fake_tools, monkeypatch):
    def boom(target, root, **kwargs):
        raise cli.ToolError("Dockerfile not found")

    monkeypatch.setattr(cli, "build_image", boom)
    assert run(["-f", "nope/Dockerfile"], project) == cli.EXIT_ERROR


def test_keep_going_continues_after_failure(project, fake_tools, monkeypatch):
    (project / "bad").mkdir()
    (project / "bad/Dockerfile").write_text("FROM scratch\n")
    calls = []

    def flaky(target, root, **kwargs):
        calls.append(target.name)
        if "bad" in target.name:
            raise cli.ToolError("build failed")
        return target.tag_for(root)

    monkeypatch.setattr(cli, "build_image", flaky)
    fake_tools["findings"] = [Finding(id="CVE-1", severity="HIGH")]

    assert run(["--keep-going"], project) == cli.EXIT_ERROR
    assert len(calls) == 2
    assert (project / ".trivyignore.yaml").exists()


def test_custom_ignore_file_path(project, fake_tools):
    fake_tools["findings"] = [Finding(id="CVE-1", severity="HIGH")]
    run(["-o", "security/ignore.yaml"], project)
    assert (project / "security/ignore.yaml").exists()


def test_plain_format_inferred_from_name(project, fake_tools):
    fake_tools["findings"] = [Finding(id="CVE-1", severity="HIGH")]
    run(["-o", ".trivyignore"], project)
    assert (project / ".trivyignore").read_text() == "CVE-1 # HIGH\n"


def test_no_comment_flag(project, fake_tools):
    fake_tools["findings"] = [Finding(id="CVE-1", severity="HIGH")]
    run(["--no-comment"], project)
    assert (project / ".trivyignore.yaml").read_text() == (
        "vulnerabilities:\n  - id: CVE-1\n"
    )


def test_images_are_scanned_without_building(project, fake_tools):
    fake_tools["findings"] = [Finding(id="CVE-1", severity="HIGH")]
    run(["--image", "nginx:latest"], project)
    assert fake_tools["builds"] == []
    assert fake_tools["scans"][0][0] == "nginx:latest"


def test_temp_images_are_cleaned_up(project, fake_tools):
    run([], project)
    assert fake_tools["removed"] == ["trivyscan/deploy-api-dockerfile:latest"]


def test_keep_images_skips_cleanup(project, fake_tools):
    run(["--keep-images"], project)
    assert fake_tools["removed"] == []


def test_config_file_supplies_defaults(project, fake_tools):
    (project / ".trivyignore-cli.toml").write_text(
        'files = ["deploy/api/Dockerfile"]\nseverity = "HIGH,CRITICAL"\n'
    )
    fake_tools["findings"] = [Finding(id="CVE-1", severity="HIGH")]
    run([], project)
    assert fake_tools["scans"][0][1] == ("HIGH", "CRITICAL")


def test_cli_flag_overrides_config(project, fake_tools):
    (project / ".trivyignore-cli.toml").write_text('severity = "LOW"\n')
    run(["--severity", "CRITICAL"], project)
    assert fake_tools["scans"][0][1] == ("CRITICAL",)


def test_no_config_ignores_config_file(project, fake_tools):
    (project / ".trivyignore-cli.toml").write_text('severity = "LOW"\n')
    run(["--no-config"], project)
    assert fake_tools["scans"][0][1] == ("HIGH",)


def test_unknown_config_key_errors(project, fake_tools):
    (project / ".trivyignore-cli.toml").write_text('bogus = 1\n')
    assert run([], project) == cli.EXIT_ERROR


def test_existing_entries_are_preserved(project, fake_tools):
    (project / ".trivyignore.yaml").write_text(
        "# audited\nvulnerabilities:\n  - id: CVE-OLD\n    statement: wontfix\n"
    )
    fake_tools["findings"] = [Finding(id="CVE-NEW", severity="HIGH")]
    run([], project)
    out = (project / ".trivyignore.yaml").read_text()
    assert "# audited" in out
    assert "statement: wontfix" in out
    assert "CVE-NEW" in out
