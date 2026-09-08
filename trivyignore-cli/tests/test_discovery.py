from pathlib import Path

import pytest

from trivyignore_cli.discovery import build_targets, find_dockerfiles, parse_file_spec


def touch(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("FROM scratch\n")
    return path


def test_finds_nested_dockerfiles(tmp_path):
    touch(tmp_path / "deploy/api/Dockerfile")
    touch(tmp_path / "deploy/db/Dockerfile")
    touch(tmp_path / "README.md")

    found = find_dockerfiles(tmp_path, respect_gitignore=False)
    rels = sorted(p.relative_to(tmp_path).as_posix() for p in found)
    assert rels == ["deploy/api/Dockerfile", "deploy/db/Dockerfile"]


def test_matches_dockerfile_variants(tmp_path):
    touch(tmp_path / "Dockerfile")
    touch(tmp_path / "Dockerfile.prod")
    touch(tmp_path / "api.Dockerfile")
    touch(tmp_path / "Containerfile")

    found = find_dockerfiles(tmp_path, respect_gitignore=False)
    names = sorted(p.name for p in found)
    assert names == ["Containerfile", "Dockerfile", "Dockerfile.prod", "api.Dockerfile"]


def test_dockerignore_is_not_a_dockerfile(tmp_path):
    touch(tmp_path / ".dockerignore")
    touch(tmp_path / "Dockerfile")
    found = find_dockerfiles(tmp_path, respect_gitignore=False)
    assert [p.name for p in found] == ["Dockerfile"]


def test_prunes_noise_directories(tmp_path):
    touch(tmp_path / "Dockerfile")
    touch(tmp_path / "node_modules/pkg/Dockerfile")
    touch(tmp_path / ".git/Dockerfile")
    touch(tmp_path / "vendor/x/Dockerfile")

    found = find_dockerfiles(tmp_path, respect_gitignore=False)
    assert [p.relative_to(tmp_path).as_posix() for p in found] == ["Dockerfile"]


def test_default_excludes_testdata(tmp_path):
    touch(tmp_path / "Dockerfile")
    touch(tmp_path / "pkg/testdata/Dockerfile")
    found = find_dockerfiles(tmp_path, respect_gitignore=False)
    assert [p.relative_to(tmp_path).as_posix() for p in found] == ["Dockerfile"]


def test_custom_exclude(tmp_path):
    touch(tmp_path / "keep/Dockerfile")
    touch(tmp_path / "skip/Dockerfile")
    found = find_dockerfiles(
        tmp_path, excludes=["skip/**"], respect_gitignore=False
    )
    assert [p.relative_to(tmp_path).as_posix() for p in found] == ["keep/Dockerfile"]


def test_custom_pattern(tmp_path):
    touch(tmp_path / "Dockerfile")
    touch(tmp_path / "Dockerfile.prod")
    found = find_dockerfiles(
        tmp_path, patterns=["Dockerfile.prod"], respect_gitignore=False
    )
    assert [p.name for p in found] == ["Dockerfile.prod"]


def test_results_are_sorted(tmp_path):
    for name in ["c", "a", "b"]:
        touch(tmp_path / name / "Dockerfile")
    found = find_dockerfiles(tmp_path, respect_gitignore=False)
    assert [p.parent.name for p in found] == ["a", "b", "c"]


def test_parse_spec_defaults_context_to_dirname(tmp_path):
    target = parse_file_spec("deploy/api/Dockerfile", tmp_path)
    assert target.dockerfile == tmp_path / "deploy/api/Dockerfile"
    assert target.context == tmp_path / "deploy/api"


def test_parse_spec_with_explicit_context(tmp_path):
    target = parse_file_spec("deploy/api/Dockerfile:.", tmp_path)
    assert target.dockerfile == tmp_path / "deploy/api/Dockerfile"
    assert target.context == tmp_path / "."


def test_parse_spec_absolute_paths(tmp_path):
    spec = f"{tmp_path / 'Dockerfile'}:{tmp_path}"
    target = parse_file_spec(spec, Path("/nowhere"))
    assert target.dockerfile == tmp_path / "Dockerfile"
    assert target.context == tmp_path


def test_explicit_files_disable_discovery(tmp_path):
    touch(tmp_path / "auto/Dockerfile")
    touch(tmp_path / "explicit/Dockerfile")
    targets = build_targets(tmp_path, file_specs=["explicit/Dockerfile"])
    assert len(targets) == 1
    assert targets[0].dockerfile == tmp_path / "explicit/Dockerfile"


def test_context_override_applies_to_discovery(tmp_path):
    touch(tmp_path / "deploy/api/Dockerfile")
    targets = build_targets(
        tmp_path, context_override=tmp_path, respect_gitignore=False
    )
    assert targets[0].context == tmp_path


def test_images_skip_discovery(tmp_path):
    touch(tmp_path / "Dockerfile")
    targets = build_targets(tmp_path, images=["nginx:latest"])
    assert len(targets) == 1
    assert targets[0].is_prebuilt


def test_tag_is_deterministic_and_valid(tmp_path):
    target = parse_file_spec("deploy/Open-WebUI/Dockerfile", tmp_path)
    tag = target.tag_for(tmp_path)
    assert tag == "trivyscan/deploy-open-webui-dockerfile:latest"
    assert tag == target.tag_for(tmp_path)


def test_tag_for_prebuilt_image_is_the_image(tmp_path):
    targets = build_targets(tmp_path, images=["nginx:1.25"])
    assert targets[0].tag_for(tmp_path) == "nginx:1.25"
