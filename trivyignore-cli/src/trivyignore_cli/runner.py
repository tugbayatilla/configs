"""Thin wrappers around the docker and trivy binaries."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .models import Finding, Target


class ToolError(RuntimeError):
    """A required external tool failed or is missing."""


def require(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        raise ToolError(f"{tool!r} not found on PATH")
    return path


def _run(cmd: list[str], quiet: bool, capture: bool = False) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=capture or quiet,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()
        raise ToolError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}"
            + (f"\n{detail}" if detail else "")
        )
    return proc


def build_image(
    target: Target,
    root: Path,
    quiet: bool = True,
    pull: bool = False,
    no_cache: bool = False,
    docker_bin: str = "docker",
) -> str:
    """Build ``target`` and return the tag Trivy should scan."""
    if target.is_prebuilt:
        return target.image  # type: ignore[return-value]

    require(docker_bin)
    assert target.dockerfile is not None
    if not target.dockerfile.is_file():
        raise ToolError(f"Dockerfile not found: {target.dockerfile}")

    context = target.context or target.dockerfile.parent
    if not context.is_dir():
        raise ToolError(f"build context is not a directory: {context}")

    tag = target.tag_for(root)
    cmd = [docker_bin, "build", "-t", tag, "-f", str(target.dockerfile)]
    if pull:
        cmd.append("--pull")
    if no_cache:
        cmd.append("--no-cache")
    if target.target_stage:
        cmd += ["--target", target.target_stage]
    if target.platform:
        cmd += ["--platform", target.platform]
    for key, value in target.build_args.items():
        cmd += ["--build-arg", f"{key}={value}"]
    cmd.append(str(context))

    _run(cmd, quiet=quiet)
    return tag


def image_id(tag: str, docker_bin: str = "docker") -> str:
    try:
        proc = subprocess.run(
            [docker_bin, "image", "inspect", "-f", "{{.Id}}", tag],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        return ""
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip().removeprefix("sha256:")


def remove_image(tag: str, docker_bin: str = "docker") -> None:
    subprocess.run(
        [docker_bin, "image", "rm", "-f", tag],
        capture_output=True,
        text=True,
    )


def scan_image(
    tag: str,
    severities: list[str],
    scanners: list[str] | None = None,
    ignore_unfixed: bool = False,
    extra_args: list[str] | None = None,
    trivy_bin: str = "trivy",
    timeout: str | None = None,
) -> list[Finding]:
    """Scan ``tag`` with Trivy and return the parsed findings."""
    require(trivy_bin)
    cmd = [
        trivy_bin,
        "image",
        "--format",
        "json",
        "--severity",
        ",".join(severities),
    ]
    if scanners:
        cmd += ["--scanners", ",".join(scanners)]
    if ignore_unfixed:
        cmd.append("--ignore-unfixed")
    if timeout:
        cmd += ["--timeout", timeout]
    if extra_args:
        cmd += extra_args
    cmd.append(tag)

    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip()
        raise ToolError(f"trivy scan failed for {tag}\n{detail}")

    return parse_report(proc.stdout)


def parse_report(payload: str) -> list[Finding]:
    """Turn a Trivy JSON report into a deduplicated, sorted finding list."""
    if not payload.strip():
        return []
    try:
        data = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise ToolError(f"could not parse trivy JSON output: {exc}") from exc

    findings: dict[tuple[str, str], Finding] = {}
    for result in data.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            _collect(
                findings,
                vuln.get("VulnerabilityID"),
                vuln.get("Severity"),
                "vulnerabilities",
                vuln.get("Title") or "",
                vuln.get("PkgName") or "",
            )
        for mis in result.get("Misconfigurations") or []:
            _collect(
                findings,
                mis.get("ID") or mis.get("AVDID"),
                mis.get("Severity"),
                "misconfigurations",
                mis.get("Title") or "",
                "",
            )
        for secret in result.get("Secrets") or []:
            _collect(
                findings,
                secret.get("RuleID"),
                secret.get("Severity"),
                "secrets",
                secret.get("Title") or "",
                "",
            )
        for lic in result.get("Licenses") or []:
            _collect(
                findings,
                lic.get("Name"),
                lic.get("Severity"),
                "licenses",
                lic.get("Category") or "",
                lic.get("PkgName") or "",
            )

    return sorted(findings.values(), key=lambda f: (f.kind, f.id))


def _collect(
    store: dict[tuple[str, str], Finding],
    ident: str | None,
    severity: str | None,
    kind: str,
    title: str,
    pkg: str,
) -> None:
    if not ident:
        return
    key = (kind, ident)
    if key in store:
        return
    store[key] = Finding(
        id=ident,
        severity=(severity or "UNKNOWN").upper(),
        kind=kind,
        title=title,
        pkg_name=pkg,
    )
